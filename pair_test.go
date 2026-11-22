package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// 1.6.2 : /api/pair dit seulement qui est là ; jamais le code d'appairage.
func TestPairLocal(t *testing.T) {
	st := &Store{dir: t.TempDir()}
	app := &App{store: st, id: "L000000000AC", changed: make(chan struct{}, 1)}
	lire := func(ip string) (int, map[string]any) {
		r := httptest.NewRequest("GET", "/api/pair", nil)
		r.RemoteAddr = ip + ":40000"
		w := httptest.NewRecorder()
		app.localHandler(w, r)
		var d map[string]any
		json.Unmarshal(w.Body.Bytes(), &d)
		return w.Code, d
	}
	if c, _ := lire("8.8.8.8"); c != 403 {
		t.Fatalf("adresse publique acceptée (%d)", c)
	}
	c, d := lire("192.168.0.10")
	if c != 200 || d["id"] != "L000000000AC" || d["lie"] != false {
		t.Fatalf("réponse inattendue %d %v", c, d)
	}
	if _, ok := d["code"]; ok {
		t.Fatal("code d'appairage donné sur le réseau")
	}

	st.SetToken("jeton-du-compte-0123")
	if _, d := lire("192.168.0.10"); d["lie"] != true {
		t.Fatalf("lié non signalé : %v", d)
	}
}
