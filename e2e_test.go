package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestE2E(t *testing.T) {
	dir, _ := os.MkdirTemp("", "e2e")
	defer os.RemoveAll(dir)
	st, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	e := newE2E(st, "L48AE35AAE8F")
	k := make([]byte, 32)
	rand.Read(k)
	appRaw := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	app := hex.EncodeToString(appRaw)
	code, s := e.Enroll([]byte(`{"app":"` + app + `","key":"` + base64.StdEncoding.EncodeToString(k) + `","name":"Pixel"}`))
	if code != 200 {
		t.Fatal(s)
	}
	req := func(u string) (int, []byte) {
		pt, _ := json.Marshal(map[string]any{"m": "GET", "u": u, "t": time.Now().UnixMilli()})
		nonce := make([]byte, 12)
		rand.Read(nonce)
		aad := append(append([]byte("PBE1"), appRaw...), "L48AE35AAE8F"...)
		body := append(append(append([]byte("PBE1"), appRaw...), nonce...), gcm(derive(k, "PB-E2E-REQ-1")).Seal(nil, nonce, pt, aad)...)
		c, _, out := e.Handle(context.Background(), nil, body)
		if c != 200 {
			return c, out
		}
		plain, err := gcm(derive(k, "PB-E2E-RESP-1")).Open(nil, out[:12], out[12:], nonce)
		if err != nil {
			t.Fatal(err)
		}
		return 200, plain
	}
	c, out := req("/api/camkey")
	if c != 200 || !strings.Contains(string(out), `"c":200`) {
		t.Fatalf("%d %s", c, out)
	}
	i := strings.IndexByte(string(out), '\n')
	var ck struct{ ID, K string }
	json.Unmarshal(out[i+1:], &ck)
	key, _ := base64.StdEncoding.DecodeString(ck.K)
	fr := e.SealFrame([]byte("JPEGDATA"))
	id, _ := hex.DecodeString(ck.ID)
	if string(fr[:4]) != "PBC1" || string(fr[4:8]) != string(id) {
		t.Fatal("entête image")
	}
	pt, err := gcm(key).Open(nil, fr[8:20], fr[20:], append([]byte("PBC1"), id...))
	if err != nil || string(pt[8:]) != "JPEGDATA" || time.Now().UnixMilli()-int64(binary.BigEndian.Uint64(pt)) > 1000 {
		t.Fatal("image", err)
	}
	// Téléphone inconnu
	e.Reset()
	if c, _ := req("/api/camkey"); c != 403 {
		t.Fatal("après reset", c)
	}
}

// 1.6.3 : appairage uniquement sur le réseau local.
func TestAppairageLocalSeulement(t *testing.T) {
	dir, _ := os.MkdirTemp("", "e2e")
	defer os.RemoveAll(dir)
	st, _ := openStore(dir)
	k := make([]byte, 32)
	rand.Read(k)
	kb := base64.StdEncoding.EncodeToString(k)
	// Un téléphone appairé en local et un téléphone appairé à distance jamais vérifié (avant 1.6.3).
	f, _ := json.Marshal(map[string]any{"apps": map[string]e2eApp{
		"0102030405060708": {K: kb, N: "local", T: 1, V: true},
		"1112131415161718": {K: kb, N: "distance", T: 2, V: false},
	}})
	os.WriteFile(st.path("e2e.json"), f, 0o600)
	e := newE2E(st, "L48AE35AAE8F")
	if e.Count() != 1 {
		t.Fatal("téléphone non vérifié gardé", e.Count())
	}
	b, _ := os.ReadFile(st.path("e2e.json"))
	if strings.Contains(string(b), "1112131415161718") {
		t.Fatal("téléphone non vérifié encore enregistré")
	}
	req := func(appRaw []byte, u string) int {
		pt, _ := json.Marshal(map[string]any{"m": "POST", "u": u, "t": time.Now().UnixMilli()})
		nonce := make([]byte, 12)
		rand.Read(nonce)
		aad := append(append([]byte("PBE1"), appRaw...), "L48AE35AAE8F"...)
		body := append(append(append([]byte("PBE1"), appRaw...), nonce...), gcm(derive(k, "PB-E2E-REQ-1")).Seal(nil, nonce, pt, aad)...)
		c, _, _ := e.Handle(context.Background(), nil, body)
		return c
	}
	// Entrée non vérifiée (ajoutée sans passer par Enroll) : toute requête refusée, commandes comprises.
	e.mu.Lock()
	e.apps["2122232425262728"] = e2eApp{K: kb, N: "intrus", T: 3, V: false}
	e.mu.Unlock()
	if c := req([]byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28}, "/api/cancel?p=0"); c != 403 {
		t.Fatal("annulation acceptée pour un téléphone non vérifié", c)
	}
	if c := req([]byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28}, "/api/camkey"); c != 403 {
		t.Fatal("clé caméra remise à un téléphone non vérifié", c)
	}
	// Téléphone appairé en local : accepté ; sa clé se vérifie toujours.
	if c := req([]byte{1, 2, 3, 4, 5, 6, 7, 8}, "/api/camkey"); c != 200 {
		t.Fatal("téléphone local refusé", c)
	}
	_, v := e.Verify([]byte(`{"app":"0102030405060708","proof":"` + base64.StdEncoding.EncodeToString(derive(k, "PB-E2E-VERIFY-1")) + `"}`))
	if v != `{"ok":true}` {
		t.Fatal(v)
	}
}

func TestPasDAppairageParLeRelais(t *testing.T) {
	dir, _ := os.MkdirTemp("", "e2e")
	defer os.RemoveAll(dir)
	st, _ := openStore(dir)
	a := &App{store: st, e2e: newE2E(st, "L48AE35AAE8F")}
	tu := &Tunnel{app: a}
	code, _, data := tu.route(context.Background(), "POST", "/api/e2e/pair", []byte(`{"app":"0102030405060708","pub":"AAAA","name":"P"}`))
	if code != 403 || !strings.Contains(string(data), `"why":"local"`) || a.e2e.Count() != 0 {
		t.Fatal("appairage à distance accepté", code, string(data))
	}
}
