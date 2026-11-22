package main

// 1.4.0 (préparation H.264) : lecture d'un flux vidéo H.264 en RTSP, sans réencodage.
//
// Sources Klipper courantes :
//   - camera-streamer : rtsp://<hôte>:8554/stream.h264 (si son serveur RTSP est activé) ;
//   - go2rtc          : rtsp://<hôte>:8554/<nom du flux>.
// Le Link essaie ces adresses à l'ouverture de la caméra (mode automatique) ; si aucune ne répond
// en H.264, il reste sur le MJPEG habituel.
//
// RTSP 1.0 sur TCP (ou TLS pour rtsps://), RTP entrelacé dans la connexion (RFC 2326 §10.12),
// charge utile H.264 selon la RFC 6184 (NAL simples, STAP-A, FU-A). Chaque image complète
// (« unité d'accès ») est rendue en Annex-B ; une image clé est précédée de ses SPS et PPS,
// pour qu'un lecteur puisse démarrer dessus.

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

var debutAnnexB = []byte{0, 0, 0, 1}

// AU : une image H.264 complète (Annex-B), avec son horodatage RTP (90 kHz).
type AU struct {
	Data []byte
	Cle  bool
	TS   uint32
}

// ---------------------------------------------------------------------------------------------
// Client RTSP

type rtspClient struct {
	u       *url.URL
	c       net.Conn
	r       *bufio.Reader
	cseq    int
	session string
	auth    string // en-tête Authorization à renvoyer (Basic ou Digest)
	digest  map[string]string
	sps     []byte
	pps     []byte
	control string
}

// rtspOuvrir : connexion, DESCRIBE, SETUP (RTP entrelacé sur TCP) et PLAY.
func rtspOuvrir(adresse string, delai time.Duration) (*rtspClient, error) {
	u, err := url.Parse(adresse)
	if err != nil {
		return nil, err
	}
	hote := u.Host
	if u.Port() == "" {
		if u.Scheme == "rtsps" {
			hote = net.JoinHostPort(u.Hostname(), "322")
		} else {
			hote = net.JoinHostPort(u.Hostname(), "554")
		}
	}
	d := &net.Dialer{Timeout: delai}
	var c net.Conn
	if u.Scheme == "rtsps" {
		c, err = tls.DialWithDialer(d, "tcp", hote, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	} else {
		c, err = d.Dial("tcp", hote)
	}
	if err != nil {
		return nil, err
	}
	rc := &rtspClient{u: u, c: c, r: bufio.NewReaderSize(c, 256<<10)}
	if err := rc.preparer(delai); err != nil {
		c.Close()
		return nil, err
	}
	return rc, nil
}

func (rc *rtspClient) urlSansIdentifiants() string {
	v := *rc.u
	v.User = nil
	return v.String()
}

func (rc *rtspClient) preparer(delai time.Duration) error {
	base := rc.urlSansIdentifiants()
	code, h, corps, err := rc.requete("DESCRIBE", base, map[string]string{"Accept": "application/sdp"}, delai)
	if err != nil {
		return err
	}
	if code != 200 {
		return fmt.Errorf("DESCRIBE : %d", code)
	}
	if cb := h["content-base"]; cb != "" {
		base = cb
	}
	if err := rc.lireSDP(string(corps)); err != nil {
		return err
	}
	piste := rc.control
	switch {
	case piste == "" || piste == "*":
		piste = base
	case !strings.Contains(piste, "://"):
		piste = strings.TrimRight(base, "/") + "/" + strings.TrimLeft(piste, "/")
	}
	code, h, _, err = rc.requete("SETUP", piste, map[string]string{"Transport": "RTP/AVP/TCP;unicast;interleaved=0-1"}, delai)
	if err != nil {
		return err
	}
	if code != 200 {
		return fmt.Errorf("SETUP : %d", code)
	}
	rc.session = strings.TrimSpace(strings.SplitN(h["session"], ";", 2)[0])
	code, _, _, err = rc.requete("PLAY", base, map[string]string{"Range": "npt=0.000-"}, delai)
	if err != nil {
		return err
	}
	if code != 200 {
		return fmt.Errorf("PLAY : %d", code)
	}
	return nil
}

// lireSDP : première piste vidéo H.264, son contrôle et ses paramètres (sprop-parameter-sets).
func (rc *rtspClient) lireSDP(sdp string) error {
	video, h264 := false, false
	for _, l := range strings.Split(strings.ReplaceAll(sdp, "\r\n", "\n"), "\n") {
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "m="):
			if video && h264 {
				return nil // première piste vidéo H.264 déjà trouvée
			}
			video = strings.HasPrefix(l, "m=video")
			h264 = false
		case video && strings.HasPrefix(l, "a=rtpmap:"):
			if strings.Contains(strings.ToUpper(l), "H264") {
				h264 = true
			}
		case video && strings.HasPrefix(l, "a=control:"):
			rc.control = strings.TrimPrefix(l, "a=control:")
		case video && strings.HasPrefix(l, "a=fmtp:"):
			if i := strings.Index(l, "sprop-parameter-sets="); i >= 0 {
				v := l[i+len("sprop-parameter-sets="):]
				if j := strings.IndexAny(v, "; "); j >= 0 {
					v = v[:j]
				}
				for _, p := range strings.Split(v, ",") {
					b, err := base64.StdEncoding.DecodeString(p)
					if err != nil || len(b) == 0 {
						continue
					}
					switch b[0] & 0x1F {
					case 7:
						rc.sps = b
					case 8:
						rc.pps = b
					}
				}
			}
		}
	}
	if !(video && h264) {
		return errors.New("pas de vidéo H.264 dans ce flux")
	}
	return nil
}

func (rc *rtspClient) requete(methode, cible string, en map[string]string, delai time.Duration) (int, map[string]string, []byte, error) {
	for essai := 0; essai < 2; essai++ {
		rc.cseq++
		var b strings.Builder
		fmt.Fprintf(&b, "%s %s RTSP/1.0\r\nCSeq: %d\r\nUser-Agent: PitBoard-Link\r\n", methode, cible, rc.cseq)
		if rc.session != "" {
			fmt.Fprintf(&b, "Session: %s\r\n", rc.session)
		}
		if a := rc.autorisation(methode, cible); a != "" {
			fmt.Fprintf(&b, "Authorization: %s\r\n", a)
		}
		for k, v := range en {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
		b.WriteString("\r\n")
		rc.c.SetDeadline(time.Now().Add(delai))
		if _, err := io.WriteString(rc.c, b.String()); err != nil {
			return 0, nil, nil, err
		}
		code, h, corps, err := rc.lireReponse()
		rc.c.SetDeadline(time.Time{})
		if err != nil {
			return 0, nil, nil, err
		}
		if code == 401 && essai == 0 && rc.u.User != nil {
			rc.preparerAuth(h["www-authenticate"])
			continue
		}
		return code, h, corps, nil
	}
	return 401, nil, nil, errors.New("authentification RTSP refusée")
}

// lireReponse : réponse RTSP (en sautant d'éventuels paquets RTP entrelacés déjà arrivés).
func (rc *rtspClient) lireReponse() (int, map[string]string, []byte, error) {
	for {
		p, err := rc.r.Peek(1)
		if err != nil {
			return 0, nil, nil, err
		}
		if p[0] != '$' {
			break
		}
		if _, _, err := rc.lirePaquet(); err != nil {
			return 0, nil, nil, err
		}
	}
	ligne, err := rc.r.ReadString('\n')
	if err != nil {
		return 0, nil, nil, err
	}
	parts := strings.Fields(ligne)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "RTSP/") {
		return 0, nil, nil, fmt.Errorf("réponse RTSP invalide : %q", strings.TrimSpace(ligne))
	}
	code, _ := strconv.Atoi(parts[1])
	h := map[string]string{}
	for {
		l, err := rc.r.ReadString('\n')
		if err != nil {
			return 0, nil, nil, err
		}
		l = strings.TrimRight(l, "\r\n")
		if l == "" {
			break
		}
		if i := strings.IndexByte(l, ':'); i > 0 {
			k := strings.ToLower(strings.TrimSpace(l[:i]))
			v := strings.TrimSpace(l[i+1:])
			if k == "www-authenticate" && h[k] != "" && !strings.HasPrefix(strings.ToLower(v), "digest") {
				continue // on garde Digest s'il est proposé
			}
			h[k] = v
		}
	}
	var corps []byte
	if n, _ := strconv.Atoi(h["content-length"]); n > 0 && n < 1<<20 {
		corps = make([]byte, n)
		if _, err := io.ReadFull(rc.r, corps); err != nil {
			return 0, nil, nil, err
		}
	}
	return code, h, corps, nil
}

func (rc *rtspClient) preparerAuth(defi string) {
	user := rc.u.User.Username()
	pass, _ := rc.u.User.Password()
	if strings.HasPrefix(strings.ToLower(defi), "digest") {
		rc.digest = map[string]string{"user": user, "pass": pass}
		for _, p := range strings.Split(defi[6:], ",") {
			if i := strings.IndexByte(p, '='); i > 0 {
				rc.digest[strings.ToLower(strings.TrimSpace(p[:i]))] = strings.Trim(strings.TrimSpace(p[i+1:]), `"`)
			}
		}
		rc.auth = ""
		return
	}
	rc.digest = nil
	rc.auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func (rc *rtspClient) autorisation(methode, cible string) string {
	if rc.digest == nil {
		return rc.auth
	}
	m := func(s string) string { h := md5.Sum([]byte(s)); return hex.EncodeToString(h[:]) }
	d := rc.digest
	ha1 := m(d["user"] + ":" + d["realm"] + ":" + d["pass"])
	ha2 := m(methode + ":" + cible)
	rep := m(ha1 + ":" + d["nonce"] + ":" + ha2)
	return fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"`, d["user"], d["realm"], d["nonce"], cible, rep)
}

// lirePaquet : un paquet entrelacé « $ canal longueur données ».
func (rc *rtspClient) lirePaquet() (byte, []byte, error) {
	var t [4]byte
	if _, err := io.ReadFull(rc.r, t[:]); err != nil {
		return 0, nil, err
	}
	if t[0] != '$' {
		return 0, nil, errors.New("flux RTSP désynchronisé")
	}
	n := int(binary.BigEndian.Uint16(t[2:]))
	b := make([]byte, n)
	if _, err := io.ReadFull(rc.r, b); err != nil {
		return 0, nil, err
	}
	return t[1], b, nil
}

// Lire : appelle img pour chaque image complète, jusqu'à une erreur ou continuer() == false.
func (rc *rtspClient) Lire(continuer func() bool, img func(AU)) error {
	dep := &depaqueteur{sps: rc.sps, pps: rc.pps}
	dernierPing := time.Now()
	for continuer() {
		rc.c.SetReadDeadline(time.Now().Add(15 * time.Second))
		p, err := rc.r.Peek(1)
		if err != nil {
			return err
		}
		if p[0] != '$' { // réponse à un maintien de session
			if _, _, _, err := rc.lireReponse(); err != nil {
				return err
			}
			continue
		}
		canal, b, err := rc.lirePaquet()
		if err != nil {
			return err
		}
		if canal == 0 {
			for _, au := range dep.paquet(b) {
				img(au)
			}
		}
		if time.Since(dernierPing) > 25*time.Second { // maintien de la session
			dernierPing = time.Now()
			rc.cseq++
			msg := fmt.Sprintf("GET_PARAMETER %s RTSP/1.0\r\nCSeq: %d\r\nSession: %s\r\n", rc.urlSansIdentifiants(), rc.cseq, rc.session)
			if a := rc.autorisation("GET_PARAMETER", rc.urlSansIdentifiants()); a != "" {
				msg += "Authorization: " + a + "\r\n"
			}
			rc.c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			io.WriteString(rc.c, msg+"\r\n")
		}
	}
	return nil
}

func (rc *rtspClient) Fermer() {
	rc.c.SetDeadline(time.Now().Add(2 * time.Second))
	if rc.session != "" {
		rc.cseq++
		io.WriteString(rc.c, fmt.Sprintf("TEARDOWN %s RTSP/1.0\r\nCSeq: %d\r\nSession: %s\r\n\r\n", rc.urlSansIdentifiants(), rc.cseq, rc.session))
	}
	rc.c.Close()
}

// ---------------------------------------------------------------------------------------------
// Dépaquetage RTP H.264 (RFC 6184)

type depaqueteur struct {
	sps, pps []byte
	nals     [][]byte
	ts       uint32
	fu       []byte
	vu       bool
}

func (d *depaqueteur) paquet(p []byte) []AU {
	if len(p) < 12 || p[0]>>6 != 2 {
		return nil
	}
	cc := int(p[0] & 0x0F)
	marque := p[1]&0x80 != 0
	ts := binary.BigEndian.Uint32(p[4:8])
	off := 12 + 4*cc
	if p[0]&0x10 != 0 { // extension
		if len(p) < off+4 {
			return nil
		}
		off += 4 + 4*int(binary.BigEndian.Uint16(p[off+2:off+4]))
	}
	fin := len(p)
	if p[0]&0x20 != 0 && fin > 0 { // bourrage
		fin -= int(p[fin-1])
	}
	if off >= fin {
		return nil
	}
	var sortie []AU
	if d.vu && ts != d.ts && len(d.nals) > 0 { // image précédente sans bit de marque
		sortie = append(sortie, d.unite())
	}
	d.ts, d.vu = ts, true
	charge := p[off:fin]
	switch t := charge[0] & 0x1F; {
	case t >= 1 && t <= 23:
		d.ajouter(append([]byte(nil), charge...))
	case t == 24: // STAP-A
		for i := 1; i+2 <= len(charge); {
			n := int(binary.BigEndian.Uint16(charge[i:]))
			i += 2
			if i+n > len(charge) {
				break
			}
			d.ajouter(append([]byte(nil), charge[i:i+n]...))
			i += n
		}
	case t == 28: // FU-A
		if len(charge) < 2 {
			break
		}
		debut, finFU := charge[1]&0x80 != 0, charge[1]&0x40 != 0
		if debut {
			d.fu = append(d.fu[:0], (charge[0]&0xE0)|(charge[1]&0x1F))
		} else if len(d.fu) == 0 {
			break // fragment sans début : perdu
		}
		d.fu = append(d.fu, charge[2:]...)
		if finFU {
			d.ajouter(append([]byte(nil), d.fu...))
			d.fu = d.fu[:0]
		}
	}
	if marque && len(d.nals) > 0 {
		sortie = append(sortie, d.unite())
	}
	return sortie
}

func (d *depaqueteur) ajouter(n []byte) {
	if len(n) == 0 {
		return
	}
	switch n[0] & 0x1F {
	case 7:
		d.sps = n
	case 8:
		d.pps = n
	}
	d.nals = append(d.nals, n)
}

func (d *depaqueteur) unite() AU {
	cle := false
	aSps, aPps := false, false
	for _, n := range d.nals {
		switch n[0] & 0x1F {
		case 5:
			cle = true
		case 7:
			aSps = true
		case 8:
			aPps = true
		}
	}
	var b bytes.Buffer
	if cle {
		if !aSps && d.sps != nil {
			b.Write(debutAnnexB)
			b.Write(d.sps)
		}
		if !aPps && d.pps != nil {
			b.Write(debutAnnexB)
			b.Write(d.pps)
		}
	}
	for _, n := range d.nals {
		b.Write(debutAnnexB)
		b.Write(n)
	}
	d.nals = nil
	return AU{Data: b.Bytes(), Cle: cle, TS: d.ts}
}

// ---------------------------------------------------------------------------------------------
// Adresses H.264 possibles d'une webcam Klipper (mode automatique)

func h264Candidats(service, stream, snap string) []string {
	sv := strings.ToLower(service)
	hote := ""
	for _, s := range []string{stream, snap} {
		if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
			hote = u.Hostname()
			break
		}
	}
	if hote == "" {
		return nil
	}
	var l []string
	switch {
	case strings.Contains(sv, "camerastreamer") || strings.HasSuffix(strings.TrimRight(stream, "/"), "/webrtc"):
		l = append(l, "rtsp://"+net.JoinHostPort(hote, "8554")+"/stream.h264")
	case strings.Contains(sv, "go2rtc") || strings.Contains(stream, "src="):
		src := ""
		if i := strings.Index(stream, "src="); i >= 0 {
			src = stream[i+4:]
			if j := strings.IndexByte(src, '&'); j >= 0 {
				src = src[:j]
			}
		}
		if src != "" {
			l = append(l, "rtsp://"+net.JoinHostPort(hote, "8554")+"/"+src)
		}
	}
	return l
}

// ---------------------------------------------------------------------------------------------
// Hub H.264 : une lecture partagée, chaque spectateur démarre sur la dernière image clé.

type H264Hub struct {
	adresses func() []string

	mu        sync.Mutex
	gop       []AU // dernière image clé et les images qui la suivent
	seq       uint64
	notify    chan struct{}
	wantUntil time.Time
	running   bool
	actif     string // adresse qui a répondu en H.264 ("" : aucune)
	echecAt   time.Time
}

func newH264Hub(adresses func() []string) *H264Hub {
	return &H264Hub{adresses: adresses, notify: make(chan struct{})}
}

// Disponible : vrai si une adresse H.264 a déjà répondu (ou n'a pas encore été essayée récemment).
func (h *H264Hub) Disponible() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.actif != "" || (len(h.adresses()) > 0 && time.Since(h.echecAt) > 5*time.Minute)
}

// Attendre : démarre la lecture et attend une première image clé (faux si aucune adresse ne répond).
func (h *H264Hub) Attendre(d time.Duration) bool {
	h.Want(30 * time.Second)
	fin := time.Now().Add(d)
	for time.Now().Before(fin) {
		h.mu.Lock()
		pret, echec := len(h.gop) > 0, !h.running && h.actif == ""
		h.mu.Unlock()
		if pret {
			return true
		}
		if echec {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func (h *H264Hub) Want(d time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if u := time.Now().Add(d); u.After(h.wantUntil) {
		h.wantUntil = u
	}
	if !h.running {
		h.running = true
		go h.boucle()
	}
}

func (h *H264Hub) voulu() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return time.Now().Before(h.wantUntil)
}

func (h *H264Hub) publier(au AU) {
	h.mu.Lock()
	if au.Cle {
		h.gop = h.gop[:0]
	}
	if len(h.gop) > 0 || au.Cle {
		if len(h.gop) < 600 { // au plus ~20 s à 30 img/s entre deux images clés
			h.gop = append(h.gop, au)
		}
	}
	h.seq++
	old := h.notify
	h.notify = make(chan struct{})
	h.mu.Unlock()
	close(old)
}

func (h *H264Hub) boucle() {
	defer func() {
		h.mu.Lock()
		h.running = false
		h.gop = nil
		h.mu.Unlock()
	}()
	for h.voulu() {
		ok := false
		for _, a := range h.adresses() {
			rc, err := rtspOuvrir(a, 5*time.Second)
			if err != nil {
				continue
			}
			ok = true
			h.mu.Lock()
			h.actif = a
			h.mu.Unlock()
			rc.Lire(h.voulu, h.publier)
			rc.Fermer()
			break
		}
		if !ok {
			h.mu.Lock()
			h.actif = ""
			h.echecAt = time.Now()
			h.mu.Unlock()
			return
		}
		time.Sleep(time.Second)
	}
}

// Suivre : envoie à f chaque image à partir de la dernière image clé, tant que f rend nil.
func (h *H264Hub) Suivre(stop <-chan struct{}, f func(AU) error) error {
	h.Want(30 * time.Second)
	var envoyees uint64
	premier := true
	for {
		h.mu.Lock()
		gop := append([]AU(nil), h.gop...)
		seq, ch := h.seq, h.notify
		h.mu.Unlock()
		if premier && len(gop) > 0 {
			for _, au := range gop {
				if err := f(au); err != nil {
					return err
				}
			}
			premier = false
			envoyees = seq
		} else if !premier && seq > envoyees {
			// Images arrivées depuis le dernier envoi : les dernières du GOP courant.
			n := int(seq - envoyees)
			if n > len(gop) { // retard trop grand : on reprend à l'image clé
				n = len(gop)
			}
			for _, au := range gop[len(gop)-n:] {
				if err := f(au); err != nil {
					return err
				}
			}
			envoyees = seq
		}
		h.Want(30 * time.Second)
		select {
		case <-ch:
		case <-stop:
			return nil
		case <-time.After(10 * time.Second):
			if !h.voulu() {
				return errors.New("plus de vidéo H.264")
			}
		}
	}
}
