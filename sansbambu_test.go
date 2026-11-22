package main

import "testing"

func TestSansBambu(t *testing.T) {
	c := Config{Printers: []PrinterCfg{
		{Slot: 1, Type: "bambu", Host: "192.168.0.50", Enabled: true},
		{Slot: 2, Host: "192.168.0.51", Port: 7125, Enabled: true},
	}}
	if _, ok := c.Imprimante(1); ok {
		t.Fatal("une entrée Bambu ne doit plus être suivie")
	}
	got := c.Emplacements()
	if len(got) != 2 || got[0] != 0 || got[1] != 2 {
		t.Fatalf("emplacements = %v", got)
	}
}

func TestAjoutBambuRefuse(t *testing.T) {
	dir := t.TempDir()
	st, _ := openStore(dir)
	app := &App{store: st, id: "L000000000AB", changed: make(chan struct{}, 1)}
	app.e2e = newE2E(st, app.id)
	c, s := app.postConfig([]byte(`{"printers":[{"slot":0},{"slot":-1,"type":"bambu","host":"192.168.0.50","serial":"X","code":"1"}]}`))
	if c != 400 {
		t.Fatalf("ajout Bambu : %d %s", c, s)
	}
	if code, _, _, _ := app.handle(nil, "GET", "/api/discover", nil, nil, true); code == 200 {
		t.Fatalf("discover ne doit plus exister : %d", code)
	}
}
