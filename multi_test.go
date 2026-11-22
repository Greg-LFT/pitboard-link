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

// 1.5.0 : un Link ne suit que sa machine : une autre imprimante est refusée.
func TestUneSeuleImprimante(t *testing.T) {
	srv := fauxMoonraker()
	defer srv.Close()
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	dir, _ := os.MkdirTemp("", "une")
	defer os.RemoveAll(dir)
	st, _ := openStore(dir)
	cfg := st.Config()
	cfg.Moonraker = "http://" + srv.Listener.Addr().String()
	cfg.Printers = []PrinterCfg{{Slot: 1, Type: "klipper", Host: "192.168.0.50", Port: 7125, Enabled: true}} // ancienne 1.4.x
	st.SaveConfig(cfg)
	app := &App{store: st, id: "L000000000AA", started: time.Now(), changed: make(chan struct{}, 1)}
	app.e2e = newE2E(st, app.id)
	app.syncImprimantes()
	pn, _ := strconv.Atoi(port)
	c, _ := app.postConfig([]byte(`{"printers":[{"slot":0,"type":"klipper","name":"Q2"},{"slot":-1,"type":"klipper","name":"Voron","host":"` + host + `","port":` + strconv.Itoa(pn) + `}]}`))
	if c != 409 {
		t.Fatalf("ajout d'une autre imprimante : %d au lieu de 409", c)
	}
	if c, s := app.postConfig([]byte(`{"printers":[{"slot":0,"type":"klipper","name":"Q2"}]}`)); c != 200 {
		t.Fatal(s)
	}
	time.Sleep(2500 * time.Millisecond)
	var d struct {
		Printers []map[string]any `json:"printers"`
	}
	json.Unmarshal(app.statusJSON(true), &d)
	if len(d.Printers) != 1 || d.Printers[0]["name"] != "Q2" || d.Printers[0]["progress"].(float64) != 42 {
		t.Fatalf("imprimantes : %v", d.Printers)
	}
	if app.klipper(1) != nil || len(app.store.Config().Printers) != 0 {
		t.Fatal("ancienne imprimante supplémentaire encore suivie")
	}
}
