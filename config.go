package main

// Configuration et identité de Pitboard Link.
// Tout est rangé dans un seul dossier (par défaut /opt/pitboard-link/data) :
//   config.json  réglages (imprimante, port local, relais)
//   link.key     clé privée Ed25519 (identité auprès du relais), 600
//   token        jeton du compte (remis par le relais après l'appairage), 600
//   tls.crt/key  certificat auto-signé du serveur local (empreinte épinglée par l'app)
//   etat.json    état lisible par « pitboard-link code » (code d'appairage, liaison)

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Name       string `json:"name"`
	Model      string `json:"model"`
	Moonraker  string `json:"moonraker"`
	APIKey     string `json:"apiKey"`
	Port       int    `json:"port"`
	Relay      string `json:"relay"`
	Cam        bool   `json:"cam"`
	CamURL     string `json:"camUrl"` // vide : webcam déclarée dans Moonraker
	AutoUpdate bool   `json:"autoUpdate"`
	// 1.2.0 : autres imprimantes Klipper suivies par ce Link (emplacements 1 à 3, Moonraker sur le réseau).
	Printers []PrinterCfg `json:"printers,omitempty"`
}

// PrinterCfg : imprimante supplémentaire (l'emplacement 0 est l'imprimante de la machine, réglée plus haut).
type PrinterCfg struct {
	Slot    int    `json:"slot"`
	Type    string `json:"type,omitempty"` // "klipper" ; 1.3.1 : les Bambu Lab passent par un PitBoard S3, plus par le Link
	Name    string `json:"name"`
	Model   string `json:"model"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	APIKey  string `json:"apiKey"`
	Cam     bool   `json:"cam"`
	CamURL  string `json:"camUrl"`
	Enabled bool   `json:"enabled"`
}

const maxImp = 4

// Imp : réglages effectifs d'une imprimante (emplacement 0 ou supplémentaire).
type Imp struct {
	Slot              int
	Name, Model       string
	Moonraker, APIKey string
	Cam               bool
	CamURL            string
	Enabled           bool
	Host              string
	Port              int
	Type              string
}

func (c Config) Imprimante(slot int) (Imp, bool) {
	if slot == 0 {
		return Imp{Slot: 0, Name: c.Name, Model: c.Model, Moonraker: c.Moonraker, APIKey: c.APIKey, Cam: c.Cam,
			CamURL: c.CamURL, Enabled: true, Host: "127.0.0.1", Port: 7125, Type: "klipper"}, true
	}
	for _, p := range c.Printers {
		if p.Slot == slot {
			port := p.Port
			if port <= 0 {
				port = 7125
			}
			if p.Type != "" && p.Type != "klipper" {
				return Imp{}, false // ancienne entrée Bambu (1.3.0) : ignorée
			}
			return Imp{Slot: slot, Name: p.Name, Model: p.Model, Moonraker: fmt.Sprintf("http://%s:%d", p.Host, port),
				APIKey: p.APIKey, Cam: p.Cam, CamURL: p.CamURL, Enabled: p.Enabled, Host: p.Host, Port: port,
				Type: "klipper"}, true
		}
	}
	return Imp{}, false
}

// Emplacements en service (0 d'abord).
func (c Config) Emplacements() []int {
	out := []int{0}
	for s := 1; s < maxImp; s++ {
		if p, ok := c.Imprimante(s); ok && p.Host != "" {
			out = append(out, s)
		}
	}
	return out
}

func defaultConfig() Config {
	return Config{
		Moonraker:  "http://127.0.0.1:7125",
		Port:       7130,
		Relay:      "pitboard.greg-lft.fr:7127",
		Cam:        true,
		AutoUpdate: true,
	}
}

type Store struct {
	dir string
	mu  sync.Mutex
	cfg Config
}

func openStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, cfg: defaultConfig()}
	b, err := os.ReadFile(s.path("config.json"))
	if err == nil {
		if err := json.Unmarshal(b, &s.cfg); err != nil {
			return nil, errors.New("config.json illisible : " + err.Error())
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if s.cfg.Port == 0 {
		s.cfg.Port = 7130
	}
	if s.cfg.Moonraker == "" {
		s.cfg.Moonraker = "http://127.0.0.1:7125"
	}
	if s.cfg.Relay == "" {
		s.cfg.Relay = "pitboard.greg-lft.fr:7127"
	}
	return s, nil
}

func (s *Store) path(n string) string { return filepath.Join(s.dir, n) }

func (s *Store) Config() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

func (s *Store) SaveConfig(c Config) error {
	s.mu.Lock()
	s.cfg = c
	s.mu.Unlock()
	b, _ := json.MarshalIndent(c, "", "  ")
	return writeFileAtomic(s.path("config.json"), b, 0o600)
}

func writeFileAtomic(p string, b []byte, mode os.FileMode) error {
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// ---------------------------------------------------------------------------
// Identité Ed25519. L'identifiant est dérivé de la clé publique : « L » + 11
// caractères hexadécimaux. Personne ne peut se présenter sous cet identifiant
// sans la clé privée, et il ne peut pas se confondre avec une puce ESP32
// (12 caractères hexadécimaux).
// ---------------------------------------------------------------------------

func (s *Store) Identity() (ed25519.PrivateKey, string, error) {
	p := s.path("link.key")
	b, err := os.ReadFile(p)
	var priv ed25519.PrivateKey
	if err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil || len(blk.Bytes) != ed25519.SeedSize {
			return nil, "", errors.New("link.key illisible")
		}
		priv = ed25519.NewKeyFromSeed(blk.Bytes)
	} else if os.IsNotExist(err) {
		_, k, gerr := ed25519.GenerateKey(rand.Reader)
		if gerr != nil {
			return nil, "", gerr
		}
		priv = k
		out := pem.EncodeToMemory(&pem.Block{Type: "PITBOARD LINK KEY", Bytes: priv.Seed()})
		if err := writeFileAtomic(p, out, 0o600); err != nil {
			return nil, "", err
		}
	} else {
		return nil, "", err
	}
	return priv, linkID(priv.Public().(ed25519.PublicKey)), nil
}

func linkID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return "L" + strings.ToUpper(hex.EncodeToString(h[:])[:11])
}

func (s *Store) Token() string {
	b, err := os.ReadFile(s.path("token"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (s *Store) SetToken(t string) {
	t = strings.TrimSpace(t)
	if t == "" || t == "-" {
		os.Remove(s.path("token"))
		return
	}
	writeFileAtomic(s.path("token"), []byte(t+"\n"), 0o600)
}

// ---------------------------------------------------------------------------
// Certificat auto-signé du serveur local (ECDSA P-256, 20 ans). L'app épingle
// l'empreinte SHA-256 de ce certificat, reçue par le relais.
// ---------------------------------------------------------------------------

func (s *Store) TLSCert(id string) (tls.Certificate, string, error) {
	cp, kp := s.path("tls.crt"), s.path("tls.key")
	if _, err := os.Stat(cp); os.IsNotExist(err) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return tls.Certificate{}, "", err
		}
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
		tpl := &x509.Certificate{
			SerialNumber:          serial,
			Subject:               pkix.Name{CommonName: "Pitboard Link " + id},
			NotBefore:             time.Now().Add(-24 * time.Hour),
			NotAfter:              time.Now().AddDate(20, 0, 0),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			DNSNames:              []string{"pitboard-link"},
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
		if err != nil {
			return tls.Certificate{}, "", err
		}
		kder, _ := x509.MarshalECPrivateKey(key)
		if err := writeFileAtomic(kp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
			return tls.Certificate{}, "", err
		}
		if err := writeFileAtomic(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
			return tls.Certificate{}, "", err
		}
	}
	c, err := tls.LoadX509KeyPair(cp, kp)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	fp := sha256.Sum256(c.Certificate[0])
	return c, hex.EncodeToString(fp[:]), nil
}

// État lisible par la commande « pitboard-link code ».
type EtatFichier struct {
	ID         string `json:"id"`
	Version    string `json:"version"`
	Relais     bool   `json:"relais"`
	Lie        bool   `json:"lie"`
	Code       string `json:"code,omitempty"`
	CodeExpire int64  `json:"codeExpire,omitempty"`
	Moonraker  bool   `json:"moonraker"`
	Maj        int64  `json:"maj"`
}

func (s *Store) WriteEtat(e EtatFichier) {
	e.Maj = time.Now().Unix()
	b, _ := json.MarshalIndent(e, "", "  ")
	writeFileAtomic(s.path("etat.json"), b, 0o644)
}

func (s *Store) ReadEtat() (EtatFichier, error) {
	var e EtatFichier
	b, err := os.ReadFile(s.path("etat.json"))
	if err != nil {
		return e, err
	}
	err = json.Unmarshal(b, &e)
	return e, err
}
