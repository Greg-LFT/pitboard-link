package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"
)

// Faux Moonraker : une imprimante en cours d'impression à 42 %.
func fauxMoonraker() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/printer/objects/list":
			w.Write([]byte(`{"result":{"objects":["extruder","heater_bed","fan","print_stats","exclude_object"]}}`))
		case "/printer/info":
			w.Write([]byte(`{"result":{"state":"ready","software_version":"v0.12"}}`))
		case "/printer/objects/query":
			w.Write([]byte(`{"result":{"status":{"print_stats":{"state":"printing","filename":"cube.gcode","print_duration":600,"total_duration":620,"info":{"current_layer":10,"total_layer":50}},"display_status":{"progress":0.42},"extruder":{"temperature":210.2,"target":210},"heater_bed":{"temperature":60,"target":60},"webhooks":{"state":"ready"}}}}`))
		case "/server/webcams/list":
			w.Write([]byte(`{"result":{"webcams":[]}}`))
		default:
			w.WriteHeader(404)
			w.Write([]byte(`{}`))
		}
	}))
}

func TestMultiImprimantes(t *testing.T) {
	srv := fauxMoonraker()
	defer srv.Close()
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	dir, _ := os.MkdirTemp("", "multi")
	defer os.RemoveAll(dir)
	st, _ := openStore(dir)
	cfg := st.Config()
	cfg.Moonraker = "http://127.0.0.1:1" // imprimante de la machine injoignable
	st.SaveConfig(cfg)
	app := &App{store: st, id: "L000000000AA", started: time.Now(), changed: make(chan struct{}, 1)}
	app.e2e = newE2E(st, app.id)
	app.syncImprimantes()
	pn, _ := strconv.Atoi(port)
	c, s := app.postConfig([]byte(`{"printers":[{"slot":0,"type":"klipper","name":"Q2"},{"slot":-1,"type":"klipper","name":"Voron","host":"` + host + `","port":` + strconv.Itoa(pn) + `}]}`))
	if c != 200 {
		t.Fatal(s)
	}
	time.Sleep(2500 * time.Millisecond)
	var d struct {
		Printers []map[string]any `json:"printers"`
		Display  map[string]any   `json:"display"`
	}
	json.Unmarshal(app.statusJSON(true), &d)
	if len(d.Printers) != 2 {
		t.Fatalf("imprimantes : %d", len(d.Printers))
	}
	v := d.Printers[1]
	if v["slot"].(float64) != 1 || v["name"] != "Voron" || v["phase"] != "impression" || v["progress"].(float64) != 42 {
		t.Fatalf("imprimante 2 : %v", v)
	}
	if d.Display["src"].(float64) != 1 {
		t.Fatalf("tuile : %v", d.Display)
	}
	var cj struct{ Printers []map[string]any }
	json.Unmarshal(app.configJSON(), &cj)
	if len(cj.Printers) != 2 || cj.Printers[1]["host"] != host {
		t.Fatalf("config : %v", cj.Printers)
	}
	// Commande sur l'emplacement 2 : objet inconnu (pas d'objets listés) → 400, mais l'imprimante est bien trouvée.
	code, _, _, _ := app.handle(nil, "POST", "/api/cancel", map[string][]string{"p": {"1"}}, nil, true)
	if code == 404 {
		t.Fatal("emplacement 1 introuvable")
	}
	// Retrait : liste avec seulement l'emplacement 0.
	app.postConfig([]byte(`{"printers":[{"slot":0,"type":"klipper"}]}`))
	if app.klipper(1) != nil {
		t.Fatal("emplacement 1 toujours suivi")
	}
}
