package main

// Tunnel sortant vers le relais (TLS, port 7127, comme les PitBoard ESP32-S3).
//
//   relais -> HELLO <nonce_srv>
//   Link   -> LINKAUTH <id> <nonce_cli> <clé publique Ed25519 b64> <signature b64> aes,push,camch
//             signature de « PITBOARD-LINK-1:<id>:<nonce_srv>:<nonce_cli> »
//   relais -> OK <ack> <jeton|-> <capacités>
//             clé de session = SHA-256(« PITBOARD-LINK-SESS-1:<id>:<nonce_srv>:<nonce_cli>:<signature> »)
//             ack = SHA-256(clé de session | « VPS-ACK ») en hexadécimal
//   puis le même flux que les cartes (AES-128-CTR par sens « UP » / « DOWN ») :
//   STATUS, PING, HIST, RESP / REQ, TOKEN, MODE, CAM_SUB, et PAIRCODE (propre à Link).
//
// Les images passent par un canal séparé (CAMAUTH), comme sur les S3, pour ne jamais
// retarder l'état ni les commandes.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Tunnel struct {
	app  *App
	priv ed25519.PrivateKey

	mu        sync.Mutex
	conn      net.Conn
	w         io.Writer
	sessKey   []byte
	up        atomic.Bool
	reconn    chan struct{}
	code      string
	codeExp   int64
	camUntil  [maxImp]time.Time // 1.2.0 : une voie caméra par imprimante
	camRun    [maxImp]bool
	h264Until [maxImp]time.Time // 1.4.1 : vidéo H.264 demandée par le relais
}

func newTunnel(app *App, priv ed25519.PrivateKey) *Tunnel {
	return &Tunnel{app: app, priv: priv, reconn: make(chan struct{}, 1)}
}

func (t *Tunnel) Up() bool { return t.up.Load() }

func (t *Tunnel) Reconnect() {
	t.mu.Lock()
	c := t.conn
	t.mu.Unlock()
	if c != nil {
		c.Close()
	}
}

func shaHex(parts ...[]byte) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func ctrStream(key []byte, dir string) cipher.Stream {
	h := sha256.Sum256(append(append([]byte{}, key...), dir...))
	blk, _ := aes.NewCipher(h[:16])
	return cipher.NewCTR(blk, h[16:32])
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (t *Tunnel) relay() (string, string) {
	r := t.app.store.Config().Relay
	host, _, err := net.SplitHostPort(r)
	if err != nil {
		return r + ":7127", r
	}
	return r, host
}

func dialRelay(addr, host string) (*tls.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return tls.DialWithDialer(d, "tcp", addr, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
}

func (t *Tunnel) writeEtat() {
	var st PState
	if k := t.app.klipper(0); k != nil {
		st = k.Snapshot()
	}
	t.mu.Lock()
	e := EtatFichier{
		ID: t.app.id, Version: linkVersion, Relais: t.up.Load(), Lie: t.app.store.Token() != "",
		Code: t.code, CodeExpire: t.codeExp, Moonraker: st.Connected,
	}
	t.mu.Unlock()
	if e.Lie {
		e.Code, e.CodeExpire = "", 0
	}
	t.app.store.WriteEtat(e)
}

func (t *Tunnel) Run() {
	fails := 0
	for {
		err := t.session()
		t.up.Store(false)
		t.writeEtat()
		if err != nil {
			fails++
			log.Printf("relais : %v", err)
		} else {
			fails = 0
		}
		wait := time.Duration(min(60, 1<<min(fails, 6))) * time.Second
		if fails == 0 {
			wait = 2 * time.Second
		}
		time.Sleep(wait)
	}
}

func (t *Tunnel) send(header string, payload []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.w == nil || t.conn == nil {
		return errors.New("tunnel fermé")
	}
	t.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	buf := make([]byte, 0, len(header)+1+len(payload))
	buf = append(buf, header...)
	buf = append(buf, '\n')
	buf = append(buf, payload...)
	_, err := t.w.Write(buf)
	if err != nil {
		t.conn.Close()
	}
	return err
}

func (t *Tunnel) session() error {
	addr, host := t.relay()
	conn, err := dialRelay(addr, host)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReader(conn)
	hello, err := br.ReadString('\n')
	if err != nil || !strings.HasPrefix(hello, "HELLO ") {
		return fmt.Errorf("salut du relais illisible (%v)", err)
	}
	srvNonce := strings.TrimSpace(hello[6:])
	cliNonce := randHex(16)
	id := t.app.id
	msg := "PITBOARD-LINK-1:" + id + ":" + srvNonce + ":" + cliNonce
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(t.priv, []byte(msg)))
	pub := base64.StdEncoding.EncodeToString(t.priv.Public().(ed25519.PublicKey))
	if _, err := fmt.Fprintf(conn, "LINKAUTH %s %s %s %s aes,push,camch\n", id, cliNonce, pub, sig); err != nil {
		return err
	}
	okLine, err := br.ReadString('\n')
	if err != nil {
		return fmt.Errorf("réponse d'authentification absente (%v)", err)
	}
	parts := strings.Fields(okLine)
	if len(parts) < 3 || parts[0] != "OK" {
		return fmt.Errorf("authentification refusée : %s", strings.TrimSpace(okLine))
	}
	sk := sha256.Sum256([]byte("PITBOARD-LINK-SESS-1:" + id + ":" + srvNonce + ":" + cliNonce + ":" + sig))
	if !strings.EqualFold(parts[1], shaHex(sk[:], []byte("VPS-ACK"))) {
		return errors.New("signature du relais invalide")
	}
	conn.SetDeadline(time.Time{})
	t.app.store.SetToken(parts[2])

	down := &cipher.StreamReader{S: ctrStream(sk[:], "DOWN"), R: br}
	t.mu.Lock()
	t.conn = conn
	t.w = &cipher.StreamWriter{S: ctrStream(sk[:], "UP"), W: conn}
	t.sessKey = sk[:]
	t.mu.Unlock()
	t.up.Store(true)
	defer func() {
		t.mu.Lock()
		t.conn, t.w = nil, nil
		t.mu.Unlock()
	}()
	log.Printf("relais : tunnel ouvert (%s, compte : %v)", id, t.app.store.Token() != "")
	t.writeEtat()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go t.pusher(ctx)

	rd := bufio.NewReaderSize(down, 64<<10)
	for {
		conn.SetReadDeadline(time.Now().Add(50 * time.Second))
		line, err := rd.ReadString('\n')
		if err != nil {
			return fmt.Errorf("tunnel fermé (%v)", err)
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		switch f[0] {
		case "PONG":
		case "MODE":
		case "TOKEN":
			if len(f) >= 2 {
				avant := t.app.store.Token()
				t.app.store.SetToken(f[1])
				if avant != "" && t.app.store.Token() == "" {
					t.app.e2e.Reset() // Link délié du compte : les téléphones appairés sont oubliés
				}
				log.Printf("relais : jeton mis à jour (compte : %v)", t.app.store.Token() != "")
				if t.app.store.Token() != "" {
					t.mu.Lock()
					t.code, t.codeExp = "", 0
					t.mu.Unlock()
				}
				t.writeEtat()
			}
		case "PAIRCODE":
			if len(f) >= 3 {
				exp, _ := strconv.ParseInt(f[2], 10, 64)
				t.mu.Lock()
				t.code, t.codeExp = f[1], exp
				t.mu.Unlock()
				log.Printf("relais : code d'appairage %s (à saisir dans l'app PitBoard)", f[1])
				t.writeEtat()
			}
		case "CAM_SUB":
			if len(f) >= 3 {
				slot, err := strconv.Atoi(f[1])
				if err == nil && slot >= 0 && slot < maxImp {
					ttl, _ := strconv.Atoi(f[2])
					if len(f) >= 4 && f[3] == "h264" {
						t.camSubH264(slot, ttl)
					} else {
						t.camSub(slot, ttl)
					}
				}
			}
		case "REQ":
			if len(f) < 6 {
				return errors.New("REQ invalide")
			}
			n, err := strconv.Atoi(f[5])
			if err != nil || n < 0 || n > 256<<10 {
				return errors.New("REQ : taille invalide")
			}
			body := make([]byte, n)
			if _, err := io.ReadFull(rd, body); err != nil {
				return err
			}
			go t.serveReq(ctx, f[1], f[2], f[3], body)
		default:
			log.Printf("relais : trame inconnue %q", trunc(line, 60))
		}
	}
}

func (t *Tunnel) serveReq(ctx context.Context, id, method, uri string, body []byte) {
	if _, err := url.Parse(uri); err != nil {
		t.send(fmt.Sprintf("RESP %s 400 text/plain 0", id), nil)
		return
	}
	rctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	code, mimeT, data := t.route(rctx, method, uri, body)
	if mimeT == "" {
		mimeT = "text/plain"
	}
	t.send(fmt.Sprintf("RESP %s %d %s %d", id, code, mimeT, len(data)), data)
}

// route : réponse à une requête reçue du relais (1.6.3 : séparée de serveReq pour les tests).
func (t *Tunnel) route(ctx context.Context, method, uri string, body []byte) (int, string, []byte) {
	u, err := url.Parse(uri)
	if err != nil {
		return 400, "text/plain", nil
	}
	switch {
	case method == "POST" && u.Path == "/api/e2e":
		// 1.1.0 : requête chiffrée de bout en bout (le relais ne la lit pas).
		return t.app.e2e.Handle(ctx, t.app, body)
	case u.Path == "/api/e2e/pair":
		// 1.6.3 : appairage à distance retiré ; l'appairage se fait sur le WiFi de l'imprimante.
		return 403, "application/json", []byte(`{"error":"e2e","why":"local"}`)
	case method == "GET" && (u.Path == "/api/status" || u.Path == "/api/config"):
		// Lecture seule : ce que voit un téléphone non appairé.
		code, mimeT, data, _ := t.app.handle(ctx, method, u.Path, u.Query(), body, true)
		return code, mimeT, data
	}
	// Caméra, miniature, historique et commandes : de bout en bout seulement.
	return 403, "application/json", []byte(`{"error":"e2e","why":"appairage"}`)
}

func hash32(b []byte) uint64 {
	h := fnv.New64a()
	h.Write(b)
	return h.Sum64()
}

// pusher : état toutes les 2 s s'il change (10 s sinon), PING toutes les 20 s, historique.
func (t *Tunnel) pusher(ctx context.Context) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var lastHash uint64
	var lastSt, lastPing time.Time
	var lastHist, lastPairReq time.Time
	lastPairReq = time.Now() // le relais remet déjà un code à la connexion
	mrVu := false            // 1.5.1 : etat.json réécrit dès que Moonraker répond (pitboard-link code)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-t.app.changed:
		}
		now := time.Now()
		if k := t.app.klipper(0); k != nil {
			if c := k.Snapshot().Connected; c != mrVu {
				mrVu = c
				t.writeEtat()
			}
		}
		if now.Sub(lastSt) >= 2*time.Second || lastSt.IsZero() {
			st := t.app.statusJSON(true)
			// L'âge et la durée de fonctionnement changent à chaque seconde : on les ignore pour décider.
			h := hash32(stripVolatile(st))
			if h != lastHash || now.Sub(lastSt) >= 10*time.Second {
				if t.send(fmt.Sprintf("STATUS %d", len(st)), st) != nil {
					return
				}
				lastHash, lastSt = h, now
			}
		}
		if now.Sub(lastPing) >= 20*time.Second {
			if t.send("PING 0", nil) != nil {
				return
			}
			lastPing = now
			t.writeEtat()
		}
		// Sans compte et code expiré : on en redemande un (le relais en donne au plus un par minute).
		if t.app.store.Token() == "" {
			t.mu.Lock()
			expired := t.codeExp == 0 || now.Unix() >= t.codeExp
			t.mu.Unlock()
			if expired && now.Sub(lastPairReq) >= 70*time.Second {
				if t.send("PAIRREQ", nil) != nil {
					return
				}
				lastPairReq = now
			}
		}
		// 1.1.0 : l'historique n'est plus poussé en clair au relais (lu de bout en bout par l'app).
		_ = lastHist
	}
}

func stripVolatile(b []byte) []byte {
	out := b
	for _, k := range []string{`"uptime":`, `"ageSec":`, `"heap":`, `"heapMin":`, `"agoSec":`, `"pausedSec":`} {
		for {
			i := bytes.Index(out, []byte(k))
			if i < 0 {
				break
			}
			j := i + len(k)
			for j < len(out) && (out[j] == '-' || (out[j] >= '0' && out[j] <= '9')) {
				j++
			}
			out = append(append([]byte{}, out[:i]...), out[j:]...)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Canal caméra (CAMAUTH) : ouvert tant que le relais est abonné (CAM_SUB).
// Images envoyées aussi vite que la connexion les accepte, 25 par seconde au plus :
// le débit s'adapte de lui-même à la liaison montante de la maison.
// ---------------------------------------------------------------------------

func (t *Tunnel) camSub(slot, ttl int) {
	t.mu.Lock()
	if ttl <= 0 {
		t.camUntil[slot] = time.Time{}
		t.mu.Unlock()
		return
	}
	if ttl > 60 {
		ttl = 60
	}
	if t.app.e2e.Count() == 0 {
		// Aucun téléphone appairé : personne ne pourrait lire les images chiffrées.
		t.mu.Unlock()
		return
	}
	impCfg, ok := t.app.store.Config().Imprimante(slot)
	cam := t.app.camera(slot)
	if !ok || !impCfg.Cam || cam == nil {
		t.mu.Unlock()
		return
	}
	t.camUntil[slot] = time.Now().Add(time.Duration(ttl) * time.Second)
	start := !t.camRun[slot]
	t.camRun[slot] = true
	t.mu.Unlock()
	cam.Want(time.Duration(ttl) * time.Second)
	if start {
		go t.camLoop(slot)
	}
}

// camSubH264 : 1.4.1 : vidéo H.264 par le relais (webcam camera-streamer ou go2rtc), même canal caméra.
func (t *Tunnel) camSubH264(slot, ttl int) {
	t.mu.Lock()
	if ttl <= 0 {
		t.h264Until[slot] = time.Time{}
		t.mu.Unlock()
		return
	}
	if ttl > 60 {
		ttl = 60
	}
	impCfg, ok := t.app.store.Config().Imprimante(slot)
	h := t.app.h264(slot)
	if t.app.e2e.Count() == 0 || !ok || !impCfg.Cam || h == nil {
		t.mu.Unlock()
		return
	}
	t.h264Until[slot] = time.Now().Add(time.Duration(ttl) * time.Second)
	start := !t.camRun[slot]
	t.camRun[slot] = true
	t.mu.Unlock()
	h.Want(time.Duration(ttl) * time.Second)
	if start {
		go t.camLoop(slot)
	}
}

func (t *Tunnel) mjpegWanted(slot int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return time.Now().Before(t.camUntil[slot]) && t.up.Load()
}

func (t *Tunnel) h264Wanted(slot int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return time.Now().Before(t.h264Until[slot]) && t.up.Load()
}

func (t *Tunnel) camWanted(slot int) bool { return t.mjpegWanted(slot) || t.h264Wanted(slot) }

func (t *Tunnel) camLoop(slot int) {
	defer func() {
		t.mu.Lock()
		t.camRun[slot] = false
		t.mu.Unlock()
	}()
	for t.camWanted(slot) {
		if err := t.camSession(slot); err != nil {
			log.Printf("canal caméra %d : %v", slot+1, err)
			time.Sleep(2 * time.Second)
		}
	}
}

// verrouEcriture : écritures entières (en-tête + image) depuis la boucle JPEG et la pompe H.264.
type verrouEcriture struct {
	mu   sync.Mutex
	w    io.Writer
	conn net.Conn
	der  time.Time
	err  error
}

func (v *verrouEcriture) Write(b []byte) (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.err != nil {
		return 0, v.err
	}
	v.conn.SetWriteDeadline(time.Now().Add(20 * time.Second))
	n, err := v.w.Write(b)
	v.der = time.Now()
	if err != nil {
		v.err = err
		v.conn.Close()
	}
	return n, err
}

func (v *verrouEcriture) depuis() time.Duration {
	v.mu.Lock()
	defer v.mu.Unlock()
	return time.Since(v.der)
}

func (v *verrouEcriture) erreur() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.err
}

// pompeH264 : tant que le relais demande la vidéo H.264, envoie chaque image chiffrée :
// « CAMH seq drapeaux longueur » puis l'image (drapeaux : 1 = image clé).
func (t *Tunnel) pompeH264(slot int, w *verrouEcriture, fin <-chan struct{}) {
	var seq uint64
	envoyees, t0 := 0, time.Now()
	for {
		select {
		case <-fin:
			return
		default:
		}
		h := t.app.h264(slot)
		if h == nil || !t.h264Wanted(slot) {
			select {
			case <-fin:
				return
			case <-time.After(500 * time.Millisecond):
			}
			continue
		}
		stop := make(chan struct{})
		go func() {
			for t.h264Wanted(slot) {
				select {
				case <-fin:
					close(stop)
					return
				case <-time.After(time.Second):
				}
			}
			close(stop)
		}()
		err := h.Suivre(stop, func(au AU) error {
			seq++
			b := t.app.e2e.SealH264(au.Cle, au.TS, au.Data)
			fl := 0
			if au.Cle {
				fl = 1
			}
			if _, err := w.Write(append([]byte(fmt.Sprintf("CAMH %d %d %d\n", seq, fl, len(b))), b...)); err != nil {
				return err
			}
			envoyees++
			if time.Since(t0) >= time.Minute {
				log.Printf("canal caméra %d : %.1f images H.264/s envoyées", slot+1, float64(envoyees)/time.Since(t0).Seconds())
				envoyees, t0 = 0, time.Now()
			}
			return nil
		})
		<-stop
		if err != nil && w.erreur() != nil {
			return
		}
	}
}

func (t *Tunnel) camSession(slot int) error {
	cam := t.app.camera(slot)
	if cam == nil {
		return errors.New("imprimante retirée")
	}
	t.mu.Lock()
	sk := t.sessKey
	t.mu.Unlock()
	if sk == nil {
		return errors.New("pas de session")
	}
	addr, host := t.relay()
	conn, err := dialRelay(addr, host)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReader(conn)
	hello, err := br.ReadString('\n')
	if err != nil || !strings.HasPrefix(hello, "HELLO ") {
		return errors.New("salut du relais illisible")
	}
	srvNonce := strings.TrimSpace(hello[6:])
	cliNonce := randHex(16)
	ck := sha256.Sum256(append(append([]byte{}, sk...), []byte(fmt.Sprintf(":CAM:%d:", slot)+srvNonce+":"+cliNonce)...))
	if _, err := fmt.Fprintf(conn, "CAMAUTH %s %d %s %s\n", t.app.id, slot, cliNonce, shaHex(ck[:], []byte("ESP32-CAM"))); err != nil {
		return err
	}
	ok, err := br.ReadString('\n')
	f := strings.Fields(ok)
	if err != nil || len(f) < 2 || f[0] != "OK" || !strings.EqualFold(f[1], shaHex(ck[:], []byte("VPS-CAM-ACK"))) {
		return fmt.Errorf("canal caméra refusé : %s", strings.TrimSpace(ok))
	}
	conn.SetDeadline(time.Time{})
	w := &verrouEcriture{w: &cipher.StreamWriter{S: ctrStream(ck[:], "CAMUP"), W: conn}, conn: conn}
	// 1.4.1 : vidéo H.264, dans l'ordre et sans saut à l'intérieur d'un groupe d'images (le relais
	// saute au groupe suivant si le téléphone ne suit pas). Tâche à part, même connexion.
	finH264 := make(chan struct{})
	defer close(finH264)
	go t.pompeH264(slot, w, finH264)
	var last uint64
	lastSend := time.Now()
	sent := 0
	t0 := time.Now()
	for t.camWanted(slot) {
		if !t.mjpegWanted(slot) { // H.264 seul : la pompe envoie, on garde la liaison
			time.Sleep(500 * time.Millisecond)
			if w.depuis() > 15*time.Second {
				if _, err := w.Write([]byte("PING 0\n")); err != nil {
					return err
				}
			}
			if w.erreur() != nil {
				return w.erreur()
			}
			continue
		}
		cam.Want(10 * time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		f, seq, err := cam.Next(ctx, last, 5*time.Second)
		cancel()
		if err != nil {
			if time.Since(lastSend) > 15*time.Second {
				if _, err := w.Write([]byte("PING 0\n")); err != nil {
					return err
				}
				lastSend = time.Now()
			}
			continue
		}
		// 1.1.2 : 20 images/s au plus par le relais (limite du serveur), chiffrées de bout en bout.
		if d := 50*time.Millisecond - time.Since(lastSend); d > 0 {
			time.Sleep(d)
		}
		f = t.app.e2e.SealFrame(f)
		hdr := fmt.Sprintf("CAM %d %d\n", seq, len(f))
		if _, err := w.Write(append([]byte(hdr), f...)); err != nil {
			return err
		}
		last, lastSend = seq, time.Now()
		sent++
		if time.Since(t0) >= time.Minute {
			if slot == 0 {
				log.Printf("canal caméra : %.1f images/s envoyées", float64(sent)/time.Since(t0).Seconds())
			} else {
				log.Printf("canal caméra %d : %.1f images/s envoyées", slot+1, float64(sent)/time.Since(t0).Seconds())
			}
			sent, t0 = 0, time.Now()
		}
	}
	return nil
}
