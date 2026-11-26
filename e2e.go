package main

// Chiffrement de bout en bout entre l'app PitBoard et Pitboard Link (1.1.0).
//
// Le relais ne doit ni lire ni modifier ce qui passe entre le téléphone et l'imprimante.
// Chaque téléphone reçoit sa clé lors d'un « appairage local » : la première fois qu'il est
// sur le même WiFi que l'imprimante, il envoie une clé aléatoire de 32 octets directement au
// Link, par le serveur local HTTPS (certificat épinglé, jeton local, adresses privées seulement).
// Le relais ne voit jamais cette clé : il n'est pas sur le réseau de la maison.
//
// 1.6.3 : l'appairage se fait uniquement sur le réseau local. L'appairage à distance par le
// compte (1.1.1, ECDH par le relais) est retiré : un relais compromis pouvait y créer ses propres
// « téléphones » et envoyer des commandes. Les téléphones appairés ainsi et jamais vérifiés sont
// oubliés au démarrage, et Handle refuse toute entrée non vérifiée.
//
// Ensuite, à distance :
//   - requêtes : POST /api/e2e, corps opaque (AES-256-GCM), réponse opaque ;
//   - caméra : images chiffrées avec une clé de caméra (AES-256-GCM), remise aux téléphones
//     appairés par une requête de bout en bout (/api/camkey) ;
//   - un téléphone non appairé n'a que l'état (lecture seule) : pas de caméra, pas de commande.
//
// Format d'une requête (corps de POST /api/e2e) :
//   "PBE1" | app (8 octets) | nonce (12) | GCM(kReq, nonce, aad = "PBE1"+app+id du Link, JSON)
//   JSON : {"m":"GET","u":"/api/history?p=0","t":<ms>,"b":"<base64>"}
// Réponse (200, application/octet-stream) :
//   nonce (12) | GCM(kResp, nonce, aad = nonce de la requête, en-tête JSON + "\n" + corps)
//   en-tête : {"c":200,"t":"application/json","h":{"X-Cam-Seq":"12"}}
// Image de caméra (trame CAM vers le relais) :
//   "PBC1" | id de clé (4) | nonce (12) | GCM(clé caméra, nonce, aad = "PBC1"+id, horodatage ms (8) + JPEG)

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const maxApps = 20

type e2eApp struct {
	K string `json:"k"` // clé de 32 octets, base64
	N string `json:"n"` // nom du téléphone
	T int64  `json:"t"` // appairage (unix)
	V bool   `json:"v"` // appairé sur le réseau local (seules ces entrées sont acceptées depuis 1.6.3)
}

type E2E struct {
	store  *Store
	linkID string

	mu    sync.Mutex
	apps  map[string]e2eApp
	vus   map[string]time.Time // nonces déjà reçus (rejeu)
	camID [4]byte
	camK  []byte
	camT  time.Time
}

func newE2E(s *Store, id string) *E2E {
	e := &E2E{store: s, linkID: id, apps: map[string]e2eApp{}, vus: map[string]time.Time{}}
	if b, err := os.ReadFile(s.path("e2e.json")); err == nil {
		var f struct {
			Apps map[string]e2eApp `json:"apps"`
		}
		if json.Unmarshal(b, &f) == nil && f.Apps != nil {
			e.apps = f.Apps
		}
	}
	// 1.6.3 : téléphones appairés à distance et jamais vérifiés sur le réseau local : oubliés.
	n := 0
	for id, a := range e.apps {
		if !a.V {
			delete(e.apps, id)
			n++
		}
	}
	if n > 0 {
		e.saveLocked()
		log.Printf("bout en bout : %d téléphone(s) appairé(s) à distance et non vérifié(s) oublié(s), à appairer sur le WiFi de l'imprimante", n)
	}
	e.rotateCam()
	return e
}

func (e *E2E) saveLocked() {
	b, _ := json.MarshalIndent(map[string]any{"apps": e.apps}, "", "  ")
	if err := writeFileAtomic(e.store.path("e2e.json"), b, 0o600); err != nil {
		log.Printf("bout en bout : enregistrement impossible : %v", err)
	}
}

// Nombre de téléphones appairés.
func (e *E2E) Count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.apps)
}

// Oublie tous les téléphones (Link délié du compte) et change la clé de caméra.
func (e *E2E) Reset() {
	e.mu.Lock()
	n := len(e.apps)
	e.apps = map[string]e2eApp{}
	e.saveLocked()
	e.mu.Unlock()
	e.rotateCam()
	if n > 0 {
		log.Printf("bout en bout : %d téléphone(s) oublié(s)", n)
	}
}

// Enroll : appairage local d'un téléphone (appelé seulement par le serveur local, jeton vérifié).
func (e *E2E) Enroll(body []byte) (int, string) {
	var r struct {
		App  string `json:"app"`
		Key  string `json:"key"`
		Name string `json:"name"`
	}
	if json.Unmarshal(body, &r) != nil {
		return 400, `{"error":"requête illisible"}`
	}
	app := strings.ToLower(strings.TrimSpace(r.App))
	if raw, err := hex.DecodeString(app); err != nil || len(raw) != 8 {
		return 400, `{"error":"identifiant de téléphone invalide"}`
	}
	k, err := base64.StdEncoding.DecodeString(r.Key)
	if err != nil || len(k) != 32 {
		return 400, `{"error":"clé invalide"}`
	}
	name := strings.TrimSpace(r.Name)
	if len(name) > 40 {
		name = name[:40]
	}
	e.mu.Lock()
	_, connu := e.apps[app]
	e.apps[app] = e2eApp{K: r.Key, N: name, T: time.Now().Unix(), V: true}
	e.limiterLocked()
	e.saveLocked()
	e.mu.Unlock()
	if !connu {
		log.Printf("bout en bout : téléphone %s appairé en local (%q)", app, name)
	}
	b, _ := json.Marshal(map[string]any{"ok": true, "link": e.linkID})
	return 200, string(b)
}

// limiterLocked : au plus maxApps téléphones, le plus ancien part.
func (e *E2E) limiterLocked() {
	if len(e.apps) > maxApps {
		type kv struct {
			id string
			t  int64
		}
		var l []kv
		for id, a := range e.apps {
			l = append(l, kv{id, a.T})
		}
		sort.Slice(l, func(i, j int) bool { return l[i].t < l[j].t })
		for _, x := range l[:len(l)-maxApps] {
			delete(e.apps, x.id)
		}
	}
}

// Verify : sur le réseau local, le téléphone prouve qu'il a la même clé que le Link
// (HMAC(K, "PB-E2E-VERIFY-1")). Différente ou inconnue : ok=false, le téléphone refait l'appairage en local.
// Gardé en 1.6.3 pour les apps qui vérifient encore leur clé ; appelé seulement par le serveur local.
func (e *E2E) Verify(body []byte) (int, string) {
	var r struct {
		App   string `json:"app"`
		Proof string `json:"proof"`
	}
	if json.Unmarshal(body, &r) != nil {
		return 400, `{"error":"requête illisible"}`
	}
	app := strings.ToLower(strings.TrimSpace(r.App))
	e.mu.Lock()
	defer e.mu.Unlock()
	rec, ok := e.apps[app]
	k, _ := base64.StdEncoding.DecodeString(rec.K)
	proof, _ := base64.StdEncoding.DecodeString(r.Proof)
	if !ok || len(k) != 32 || !hmac.Equal(proof, derive(k, "PB-E2E-VERIFY-1")) {
		if ok {
			// Clé différente : ce téléphone est oublié.
			delete(e.apps, app)
			e.saveLocked()
			log.Printf("bout en bout : ALERTE clé différente pour le téléphone %s, appairage annulé", app)
		}
		return 200, `{"ok":false}`
	}
	return 200, `{"ok":true}`
}

func derive(k []byte, label string) []byte {
	m := hmac.New(sha256.New, k)
	m.Write([]byte(label))
	return m.Sum(nil)
}

func gcm(k []byte) cipher.AEAD {
	b, err := aes.NewCipher(k)
	if err != nil {
		panic(err)
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		panic(err)
	}
	return g
}

var errE2EInconnu = errors.New("téléphone non appairé")

// Handle : requête de bout en bout reçue par le relais. Les erreurs de déchiffrement donnent 403
// (« e2e ») : l'app redevient alors « lecture seule » jusqu'au prochain appairage local.
func (e *E2E) Handle(ctx context.Context, a *App, body []byte) (int, string, []byte) {
	deny := func(why string) (int, string, []byte) {
		return 403, "application/json", []byte(`{"error":"e2e","why":"` + why + `"}`)
	}
	if len(body) < 4+8+12+16 || string(body[:4]) != "PBE1" {
		return deny("format")
	}
	appRaw, nonce, ct := body[4:12], body[12:24], body[24:]
	app := hex.EncodeToString(appRaw)
	e.mu.Lock()
	rec, ok := e.apps[app]
	e.mu.Unlock()
	if !ok || !rec.V {
		// 1.6.3 : seuls les téléphones appairés sur le réseau local sont acceptés.
		return deny("inconnu")
	}
	k, err := base64.StdEncoding.DecodeString(rec.K)
	if err != nil || len(k) != 32 {
		return deny("inconnu")
	}
	aad := append(append([]byte("PBE1"), appRaw...), e.linkID...)
	pt, err := gcm(derive(k, "PB-E2E-REQ-1")).Open(nil, nonce, ct, aad)
	if err != nil {
		return deny("cle")
	}
	var r struct {
		M string `json:"m"`
		U string `json:"u"`
		T int64  `json:"t"`
		B string `json:"b"`
	}
	if json.Unmarshal(pt, &r) != nil {
		return deny("format")
	}
	// Rejeu : horodatage à ± 10 min et nonce jamais vu.
	now := time.Now()
	if d := now.UnixMilli() - r.T; d > 600_000 || d < -600_000 {
		return deny("horloge")
	}
	nk := string(nonce)
	e.mu.Lock()
	if _, vu := e.vus[nk]; vu {
		e.mu.Unlock()
		return deny("rejeu")
	}
	e.vus[nk] = now
	if len(e.vus) > 4096 {
		for n, t := range e.vus {
			if now.Sub(t) > 21*time.Minute {
				delete(e.vus, n)
			}
		}
	}
	e.mu.Unlock()

	var code int
	var mimeT string
	var data []byte
	var hdr map[string]string
	u, err := url.Parse(r.U)
	if err != nil || !strings.HasPrefix(u.Path, "/api/") {
		code, mimeT, data = 400, "application/json", []byte(`{"error":"chemin invalide"}`)
	} else if u.Path == "/api/camkey" {
		code, mimeT, data = 200, "application/json", e.camKeyJSON()
	} else if u.Path == "/api/e2e" || strings.HasPrefix(u.Path, "/api/e2e/") {
		code, mimeT, data = 404, "application/json", []byte(`{"error":"inconnu"}`)
	} else {
		var in []byte
		if r.B != "" {
			in, _ = base64.StdEncoding.DecodeString(r.B)
		}
		code, mimeT, data, hdr = a.handle(ctx, strings.ToUpper(r.M), u.Path, u.Query(), in, true)
	}
	h, _ := json.Marshal(map[string]any{"c": code, "t": mimeT, "h": hdr})
	plain := make([]byte, 0, len(h)+1+len(data))
	plain = append(append(append(plain, h...), '\n'), data...)
	rn := make([]byte, 12)
	rand.Read(rn)
	out := gcm(derive(k, "PB-E2E-RESP-1")).Seal(append([]byte{}, rn...), rn, plain, nonce)
	return 200, "application/octet-stream", out
}

// ---------------------------------------------------------------------------
// Clé de caméra : aléatoire, changée toutes les 12 h et quand les téléphones sont oubliés.
// ---------------------------------------------------------------------------

func (e *E2E) rotateCam() {
	k := make([]byte, 32)
	rand.Read(k)
	var id [4]byte
	rand.Read(id[:])
	e.mu.Lock()
	e.camK, e.camID, e.camT = k, id, time.Now()
	e.mu.Unlock()
}

func (e *E2E) camKeyJSON() []byte {
	e.mu.Lock()
	if time.Since(e.camT) > 12*time.Hour {
		e.mu.Unlock()
		e.rotateCam()
		e.mu.Lock()
	}
	b, _ := json.Marshal(map[string]any{
		"id": hex.EncodeToString(e.camID[:]),
		"k":  base64.StdEncoding.EncodeToString(e.camK),
	})
	e.mu.Unlock()
	return b
}

// SealFrame : image chiffrée pour le relais (que seuls les téléphones appairés peuvent lire).
// SealH264 : image H.264 chiffrée pour le relais (1.4.1), même clé caméra que les JPEG.
// « PBH1 » | idClé(4) | nonce(12) | GCM(drapeaux(1) | horodatage RTP(4) | Annex-B), aad = « PBH1 » | idClé.
func (e *E2E) SealH264(cle bool, ts uint32, data []byte) []byte {
	e.mu.Lock()
	if time.Since(e.camT) > 12*time.Hour {
		e.mu.Unlock()
		e.rotateCam()
		e.mu.Lock()
	}
	k, id := e.camK, e.camID
	e.mu.Unlock()
	nonce := make([]byte, 12)
	rand.Read(nonce)
	pt := make([]byte, 5+len(data))
	if cle {
		pt[0] = 1
	}
	binary.BigEndian.PutUint32(pt[1:5], ts)
	copy(pt[5:], data)
	var buf bytes.Buffer
	buf.Grow(4 + 4 + 12 + len(pt) + 16)
	buf.WriteString("PBH1")
	buf.Write(id[:])
	buf.Write(nonce)
	aad := append([]byte("PBH1"), id[:]...)
	return gcm(k).Seal(buf.Bytes(), nonce, pt, aad)
}

func (e *E2E) SealFrame(jpeg []byte) []byte {
	e.mu.Lock()
	if time.Since(e.camT) > 12*time.Hour {
		e.mu.Unlock()
		e.rotateCam()
		e.mu.Lock()
	}
	k, id := e.camK, e.camID
	e.mu.Unlock()
	nonce := make([]byte, 12)
	rand.Read(nonce)
	pt := make([]byte, 8+len(jpeg))
	binary.BigEndian.PutUint64(pt, uint64(time.Now().UnixMilli()))
	copy(pt[8:], jpeg)
	var buf bytes.Buffer
	buf.Grow(4 + 4 + 12 + len(pt) + 16)
	buf.WriteString("PBC1")
	buf.Write(id[:])
	buf.Write(nonce)
	aad := append([]byte("PBC1"), id[:]...)
	return gcm(k).Seal(buf.Bytes(), nonce, pt, aad)
}
