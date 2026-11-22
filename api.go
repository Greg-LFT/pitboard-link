package main

// API de Pitboard Link : mêmes chemins et mêmes champs JSON que le firmware 0.9.15,
// pour que l'app réutilise ses écrans d'imprimante. Servie à la fois sur le réseau
// local (HTTPS, jeton du compte exigé) et à travers le tunnel du relais.

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const holdMinutes = 2 // maintien de « terminé » à 100 % (comme le réglage par défaut des PitBoard)

type App struct {
	store *Store
	kl    *Klipper // emplacement 0 (imprimante de la machine)
	cam   *CamHub
	id    string
	// 1.2.0 : plusieurs imprimantes (emplacements 0 à 3).
	impMu   sync.Mutex
	kls     [maxImp]Source
	types   [maxImp]string
	cams    [maxImp]*CamHub
	h264s   [maxImp]*H264Hub // 1.4.0
	stops   [maxImp]chan struct{}
	changed chan struct{}
	decouv  Decouverte // 1.3.0 : recherche d'imprimantes sur le réseau
	fp      string
	started time.Time
	tun     *Tunnel
	e2e     *E2E
}

func lanIP() string {
	c, err := net.Dial("udp", "192.0.2.1:9") // aucune donnée envoyée : sert à trouver l'interface de sortie
	if err != nil {
		return ""
	}
	defer c.Close()
	if a, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return a.IP.String()
	}
	return ""
}

func hexColor(c uint32) string { return fmt.Sprintf("#%06X", c&0xFFFFFF) }

func (a *App) printerName() string { return a.nomImp(0) }

// nomImp : nom de l'imprimante d'un emplacement (machine : son nom d'hôte par défaut).
func (a *App) nomImp(slot int) string {
	p, _ := a.store.Config().Imprimante(slot)
	n := strings.TrimSpace(p.Name)
	if n != "" {
		return n
	}
	if slot > 0 {
		return p.Host
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "Imprimante"
}

// klipper / camera : lecteur et caméra d'un emplacement (nil s'il n'est pas en service).
func (a *App) klipper(slot int) Source {
	if slot < 0 || slot >= maxImp {
		return nil
	}
	a.impMu.Lock()
	defer a.impMu.Unlock()
	return a.kls[slot]
}

// h264 : lecteur H.264 de l'imprimante [slot] (nil si aucun).
func (a *App) h264(slot int) *H264Hub {
	a.impMu.Lock()
	defer a.impMu.Unlock()
	if slot < 0 || slot >= maxImp {
		return nil
	}
	return a.h264s[slot]
}

func (a *App) camera(slot int) *CamHub {
	if slot < 0 || slot >= maxImp {
		return nil
	}
	a.impMu.Lock()
	defer a.impMu.Unlock()
	return a.cams[slot]
}

// syncImprimantes : démarre ou arrête la lecture de chaque emplacement selon la configuration.
func (a *App) syncImprimantes() {
	cfg := a.store.Config()
	voulus := map[int]bool{}
	for _, s := range cfg.Emplacements() {
		voulus[s] = true
	}
	a.impMu.Lock()
	defer a.impMu.Unlock()
	for s := 0; s < maxImp; s++ {
		p, _ := cfg.Imprimante(s)
		// Imprimante retirée : on arrête son lecteur.
		if a.kls[s] != nil && (!voulus[s] || a.types[s] != p.Type) {
			close(a.stops[s])
			a.kls[s], a.cams[s], a.stops[s], a.types[s], a.h264s[s] = nil, nil, nil, "", nil
			if !voulus[s] {
				log.Printf("imprimante %d retirée", s+1)
			}
		}
		if voulus[s] && a.kls[s] == nil {
			stop := make(chan struct{})
			k := newKlipper(a.store, s, a.changed)
			a.kls[s], a.cams[s], a.h264s[s] = k, newCamHub(k.CamURLs), newH264Hub(k.H264URLs)
			if s > 0 {
				log.Printf("imprimante %d suivie : %s", s+1, p.Moonraker)
			}
			a.stops[s], a.types[s] = stop, p.Type
			go a.kls[s].run(stop)
		}
	}
	a.kl, _ = a.kls[0].(*Klipper)
	a.cam = a.cams[0]
}

// printerJSON : reprise de printerJson() du firmware.
func (a *App) printerJSON(p PState, slot int) M {
	cfg, _ := a.store.Config().Imprimante(slot)
	o := M{"slot": slot, "type": "klipper", "name": a.nomImp(slot)}
	if slot == 0 {
		if ip := lanIP(); ip != "" {
			o["ui"] = "http://" + ip
		}
	} else if cfg.Host != "" {
		o["ui"] = "http://" + cfg.Host
	}
	hold := time.Duration(holdMinutes) * time.Minute
	recent := !p.EndedAt.IsZero() && time.Since(p.EndedAt) < hold
	ph := p.Phase
	if (ph == PhFinished || ph == PhFailed) && !recent {
		ph = PhIdle
	} else if ph == PhIdle && recent {
		ph = p.EndPhase
	}
	repos := ph == PhIdle && p.Phase != PhIdle
	active := isActivePh(p.Phase)
	o["camOk"] = p.CamOK
	o["enabled"] = p.Enabled
	o["connected"] = p.Connected
	o["phase"] = ph.Name()
	o["raw"] = p.Raw
	o["active"] = active
	switch {
	case ph == PhFinished:
		o["progress"] = 100.0
	case repos:
		o["progress"] = 0.0
	default:
		o["progress"] = math.Round(p.Progress*100) / 100
	}
	if repos {
		o["layer"], o["totalLayer"], o["remainingMin"], o["job"] = -1, -1, -1, ""
	} else {
		o["layer"], o["totalLayer"], o["remainingMin"], o["job"] = p.Layer, p.TotalLayer, p.RemainingMin, p.Job
	}
	o["error"] = p.Error
	if p.LastUpdate.IsZero() {
		o["ageSec"] = -1
	} else {
		o["ageSec"] = int(time.Since(p.LastUpdate).Seconds())
	}
	if p.Alert != "" {
		o["alert"] = M{"text": p.Alert}
	}
	if p.Phase == PhPaused && !p.PausedAt.IsZero() {
		o["pausedSec"] = int(time.Since(p.PausedAt).Seconds())
		if p.PauseWhy != "" {
			o["pauseWhy"] = p.PauseWhy
		}
	}
	if p.History {
		o["history"] = true
	}
	o["finished"] = p.FinishedCount
	o["failed"] = p.FailedCount
	if !p.EndedAt.IsZero() {
		o["last"] = M{
			"job":    p.LastJob,
			"ok":     p.EndPhase == PhFinished,
			"agoSec": int(time.Since(p.EndedAt).Seconds()),
			"durSec": p.LastDurSec,
		}
	}
	// Modèle : celui saisi, sinon celui annoncé par l'imprimante (Bambu).
	if cfg.Model != "" {
		o["model"] = cfg.Model
	} else if p.Model != "" {
		o["model"] = p.Model
	}
	if !p.Connected {
		return o
	}
	temp := func(k string, cur, tgt float64) {
		if cur <= -100 {
			return
		}
		t := -1
		if tgt >= 0 {
			t = int(math.Round(tgt))
		}
		o[k] = []any{round1(cur), t}
	}
	temp("nozzle", p.TNoz, p.TNozT)
	temp("bed", p.TBed, p.TBedT)
	temp("chamber", p.TCh, p.TChT)
	temp("nozzle2", p.TNoz2, p.TNoz2T)
	if p.NozActive >= 0 {
		o["nozActive"] = p.NozActive
	}
	if p.FanAux >= 0 {
		o["fanAux"] = p.FanAux
	}
	if p.FanCham >= 0 {
		o["fanCham"] = p.FanCham
	}
	if p.FwCur != "" {
		o["fw"] = p.FwCur
	}
	if len(p.ExNames) >= 2 && active {
		ob := []M{}
		for i, n := range p.ExNames {
			e := M{"n": n}
			if p.ExDone[i] {
				e["x"] = true
			}
			if p.ExCur == i {
				e["c"] = true
			}
			ob = append(ob, e)
		}
		o["objects"] = ob
		if p.ExTotal > len(p.ExNames) {
			o["objMore"] = p.ExTotal - len(p.ExNames)
		}
	}
	if p.SpeedPct >= 0 {
		o["speedPct"] = p.SpeedPct
	}
	if p.Velocity >= 0 {
		o["velocity"] = int(math.Round(p.Velocity))
	}
	if p.Flow >= 0 {
		o["flow"] = round1(p.Flow)
	}
	if p.FanPct >= 0 {
		o["fan"] = p.FanPct
	}
	if p.ElapsedSec >= 0 && !repos {
		o["elapsedSec"] = p.ElapsedSec
	}
	if p.FilType != "" {
		o["filType"] = p.FilType
	}
	if p.FilUsedMm >= 0 && !repos {
		o["filUsedM"] = math.Round(p.FilUsedMm/100) / 10
	}
	if p.FilTotalMm > 0 && !repos {
		o["filTotalM"] = math.Round(p.FilTotalMm/100) / 10
	}
	if p.FilWeightG > 0 && !repos {
		o["filWeightG"] = int(math.Round(p.FilWeightG))
	}
	if p.Thumb != "" {
		o["thumb"] = p.ThumbID
	}
	if p.FilSensor >= 0 {
		o["filSensor"] = p.FilSensor
	}
	if p.AmsUnits > 0 {
		units := []M{}
		for u := 0; u < p.AmsUnits && u < 4; u++ {
			uo := M{}
			if p.AmsHum[u] >= 0 {
				uo["hum"] = p.AmsHum[u]
			}
			trays := []M{}
			for t := 0; t < 4; t++ {
				k := u*4 + t
				to := M{"id": k}
				if p.AmsMask&(1<<k) != 0 && p.AmsType[k] != "" {
					to["type"] = p.AmsType[k]
					if p.AmsCol[k] != 0 {
						to["color"] = hexColor(p.AmsCol[k])
					}
					if p.AmsRemain[k] >= 0 {
						to["remain"] = p.AmsRemain[k]
					}
				}
				trays = append(trays, to)
			}
			uo["trays"] = trays
			units = append(units, uo)
		}
		o["ams"] = M{"now": p.TrayNow, "units": units}
	}
	if p.Spool != "" {
		sp := M{"name": p.Spool}
		if p.SpoolCol != 0 {
			sp["color"] = hexColor(p.SpoolCol)
		}
		if p.SpoolRemainG >= 0 {
			sp["remainG"] = int(math.Round(p.SpoolRemainG))
		}
		o["spool"] = sp
	}
	// Caméra : flux continu (every > 0 = images/s pour l'app), disponible même au repos.
	if p.CamOK {
		c := M{"every": 10, "rot": p.CamRot, "flipH": p.CamFlipH, "flipV": p.CamFlipV}
		if h := a.h264(slot); h != nil && h.Disponible() {
			c["h264"] = true // 1.4.0 : vidéo H.264 possible en local (/api/cam?stream=1&h264=1)
		}
		o["cam"] = c
	}
	if p.Enabled && active {
		o["canCancel"] = true
		if p.Connected {
			o["canPause"] = true
		}
	}
	if !p.CancelAt.IsZero() && time.Since(p.CancelAt) < time.Minute && p.CancelMsg != "" {
		o["cancelMsg"] = p.CancelMsg
	}
	return o
}

func (a *App) statusJSON(full bool) []byte {
	d := M{
		"version": linkVersion,
		"mcu":     "link",
		"kind":    "link",
		"licence": M{"ok": true, "chip": a.id},
		"admin":   M{"locked": false, "session": false},
	}
	ip := lanIP()
	if !full {
		d["locked"] = true
		d["wifi"] = M{"state": "connected", "ip": ip}
		b, _ := json.Marshal(d)
		return b
	}
	var mst runtime.MemStats
	runtime.ReadMemStats(&mst)
	d["motors"] = false
	d["uptime"] = int(time.Since(a.started).Seconds())
	d["heap"] = mst.HeapAlloc
	d["heapMin"] = mst.HeapAlloc
	d["reset"] = ""
	d["compte"] = a.store.Token() != ""
	d["wifi"] = M{
		"saved": "", "state": "connected", "sta": true, "ip": ip, "rssi": 0, "mdns": "",
		"ipMode": "dhcp", "error": "", "ap": false, "apSsid": "", "apClients": 0,
	}
	cfg := a.store.Config()
	// e2e : version du chiffrement de bout en bout (1.1.0) ; apps : téléphones appairés.
	d["link"] = M{"lan": ip, "port": cfg.Port, "fp": a.fp, "relais": a.tun != nil && a.tun.Up(), "e2e": 1, "apps": a.e2e.Count()}
	// 1.2.0 : toutes les imprimantes suivies ; la tuile suit la première en cours d'impression.
	src, pct, label := -1, 0.0, "aucune impression en cours"
	pjs := []M{}
	for _, s := range a.store.Config().Emplacements() {
		k := a.klipper(s)
		if k == nil {
			continue
		}
		p := k.Snapshot()
		pjs = append(pjs, a.printerJSON(p, s))
		switch {
		case src < 0 && p.Enabled && isActivePh(p.Phase):
			src, pct, label = s, p.Progress, a.nomImp(s)
		case src < 0 && !p.EndedAt.IsZero() && time.Since(p.EndedAt) < holdMinutes*time.Minute && p.EndPhase == PhFinished:
			src, pct, label = s, 100, a.nomImp(s)
		}
	}
	d["display"] = M{"percent": math.Round(pct), "label": label, "src": src, "mode": 0}
	d["printers"] = pjs
	b, _ := json.Marshal(d)
	return b
}

func (a *App) configJSON() []byte {
	cfg := a.store.Config()
	b01 := func(v bool) int {
		if v {
			return 1
		}
		return 0
	}
	// 1.2.0 : emplacement 0 = imprimante de la machine, 1 à 3 = autres imprimantes Klipper du réseau.
	prs := []M{}
	for _, s := range cfg.Emplacements() {
		p, _ := cfg.Imprimante(s)
		if s == 0 {
			// 1.2.1 : adresse de la machine sur le réseau (et non 127.0.0.1) : un PitBoard S3 qui reprend
			// cette imprimante doit pouvoir la joindre, et l'app la reconnaît comme la même imprimante.
			if ip := lanIP(); ip != "" {
				p.Host = ip
			}
		}
		prs = append(prs, M{
			"slot": s, "type": "klipper", "enabled": p.Enabled, "name": a.nomImp(s),
			"host": p.Host, "port": p.Port, "keySet": p.APIKey != "", "model": p.Model,
			"cam": b01(p.Cam), "camF": 10,
		})
	}
	d := M{
		"wifiSsid": "", "wifiPassSet": false,
		"printers":    prs,
		"maxPrinters": maxImp, "mode": 0, "holdMinutes": holdMinutes,
		"bootSweep": false, "alertCount": 0, "alertLo": 0, "alertHi": 0, "pinNeedle": -1,
		"motors": false, "needleUs0": 0, "needleUs100": 0, "needleUs50": 0, "needleSpeed": 0,
		"link": true,
	}
	b, _ := json.Marshal(d)
	return b
}

// postConfig : réglages depuis l'app. « printers » est la liste complète (comme pour un PitBoard S3) :
// emplacement 0 = imprimante de la machine (toujours gardée : nom, modèle, caméra, clé API) ;
// emplacement -1 = nouvelle imprimante (premier emplacement libre) ; un emplacement absent est retiré.
func (a *App) postConfig(body []byte) (int, string) {
	var d M
	if err := json.Unmarshal(body, &d); err != nil {
		return 400, `{"error":"JSON invalide"}`
	}
	cfg := a.store.Config()
	changed := false
	if lst, ok := d["printers"].([]any); ok {
		old := map[int]PrinterCfg{}
		for _, p := range cfg.Printers {
			old[p.Slot] = p
		}
		var nouv []PrinterCfg
		pris := map[int]bool{0: true}
		var ajouts []M
		for _, pv := range lst {
			p, _ := pv.(map[string]any)
			if p == nil {
				continue
			}
			if t, _ := p["type"].(string); t != "" && t != "klipper" {
				return 400, `{"error":"Pitboard Link ne suit que des imprimantes Klipper ; une Bambu Lab se suit avec un PitBoard S3"}`
			}
			slot := jInt(p["slot"], -1)
			if slot == 0 {
				if v, ok := p["name"].(string); ok {
					cfg.Name = trunc(strings.TrimSpace(v), 40)
				}
				if v, ok := p["model"].(string); ok {
					cfg.Model = trunc(strings.TrimSpace(v), 23)
				}
				if v, ok := p["cam"]; ok {
					cfg.Cam = jInt(v, 1) != 0
				}
				if v, ok := p["apiKey"].(string); ok && v != "" {
					cfg.APIKey = strings.TrimSpace(v)
				}
				continue
			}
			if slot > 0 && slot < maxImp && !pris[slot] {
				pris[slot] = true
				pc := old[slot]
				pc.Slot = slot
				appliquerImp(&pc, p)
				nouv = append(nouv, pc)
			} else {
				ajouts = append(ajouts, p)
			}
		}
		for _, p := range ajouts {
			libre := -1
			for s := 1; s < maxImp; s++ {
				if !pris[s] {
					libre = s
					break
				}
			}
			if libre < 0 {
				return 409, fmt.Sprintf(`{"error":"Pitboard Link suit au plus %d imprimantes"}`, maxImp)
			}
			pris[libre] = true
			pc := PrinterCfg{Slot: libre, Cam: true, Enabled: true}
			appliquerImp(&pc, p)
			if pc.Host == "" {
				return 400, `{"error":"adresse de l'imprimante manquante"}`
			}
			nouv = append(nouv, pc)
		}
		cfg.Printers = nouv
		changed = true
	}
	if v, ok := d["autoUpdate"].(bool); ok {
		cfg.AutoUpdate, changed = v, true
	}
	if changed {
		if err := a.store.SaveConfig(cfg); err != nil {
			return 500, `{"error":"enregistrement impossible"}`
		}
		a.syncImprimantes()
		for s := 0; s < maxImp; s++ {
			if k := a.klipper(s); k != nil {
				k.reload()
			}
		}
		a.notify()
	}
	return 200, `{"ok":true,"reboot":false,"wifi":false}`
}

func appliquerImp(pc *PrinterCfg, p map[string]any) {
	pc.Type = "klipper"
	if v, ok := p["name"].(string); ok {
		pc.Name = trunc(strings.TrimSpace(v), 40)
	}
	if v, ok := p["model"].(string); ok {
		pc.Model = trunc(strings.TrimSpace(v), 23)
	}
	if v, ok := p["host"].(string); ok {
		h := strings.TrimSpace(v)
		h = strings.TrimPrefix(strings.TrimPrefix(h, "http://"), "https://")
		h = strings.TrimRight(h, "/")
		if hh, pp, err := net.SplitHostPort(h); err == nil {
			h = hh
			if n, err := strconv.Atoi(pp); err == nil {
				pc.Port = n
			}
		}
		if h != pc.Host {
			pc.Host = h
		}
	}
	if v, ok := p["port"]; ok {
		if n := jInt(v, 0); n > 0 && n < 65536 {
			pc.Port = n
		}
	}
	if v, ok := p["apiKey"].(string); ok && v != "" {
		pc.APIKey = strings.TrimSpace(v)
	}
	if v, ok := p["cam"]; ok {
		pc.Cam = jInt(v, 1) != 0
	}
	if v, ok := p["enabled"].(bool); ok {
		pc.Enabled = v
	}
	if pc.Port <= 0 {
		pc.Port = 7125
	}
}

func (a *App) notify() {
	select {
	case a.changed <- struct{}{}:
	default:
	}
}

// handle : une requête de l'app, locale ou relayée. Renvoie code, type, corps.
func (a *App) handle(ctx context.Context, method, path string, q url.Values, body []byte, full bool) (int, string, []byte, map[string]string) {
	js := func(code int, s string) (int, string, []byte, map[string]string) {
		return code, "application/json", []byte(s), nil
	}
	if path == "/api/status" && method == "GET" {
		return 200, "application/json", a.statusJSON(full), nil
	}
	if !full {
		return 401, "text/plain", nil, nil
	}
	// 1.2.0 : imprimante visée (?p=emplacement, 0 par défaut).
	slot := 0
	if v := q.Get("p"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return js(404, `{"error":"imprimante inconnue"}`)
		}
		slot = n
	}
	if method == "GET" && path == "/api/klscan" {
		return 200, "application/json", a.decouv.KlScan(q.Has("start")), nil
	}
	kl, cam := a.klipper(slot), a.camera(slot)
	if kl == nil && path != "/api/config" && path != "/api/reset" && path != "/api/reboot" {
		return js(404, `{"error":"imprimante inconnue"}`)
	}
	impCfg, _ := a.store.Config().Imprimante(slot)
	switch {
	case method == "GET" && path == "/api/config":
		return 200, "application/json", a.configJSON(), nil
	case method == "POST" && path == "/api/config":
		c, s := a.postConfig(body)
		return js(c, s)
	case method == "GET" && path == "/api/history":
		c, b := kl.History()
		return c, "application/json", b, nil
	case method == "GET" && path == "/api/thumb":
		if b := kl.Thumb(); b != nil {
			return 200, "image/png", b, nil
		}
		return 503, "text/plain", nil, nil
	case method == "GET" && path == "/api/cam":
		if !impCfg.Cam || cam == nil {
			return 404, "text/plain", nil, nil
		}
		after, _ := strconv.ParseUint(q.Get("after"), 10, 64)
		if after > cam.Seq() {
			after = 0 // Link redémarré : numérotation repartie de zéro
		}
		wait := 6 * time.Second
		if q.Has("after") {
			wait = 15 * time.Second
		}
		f, seq, err := cam.Next(ctx, after, wait)
		if err != nil {
			if q.Has("after") {
				return 204, "text/plain", nil, nil
			}
			return 503, "application/json", []byte(`{"error":"caméra indisponible"}`), nil
		}
		return 200, "image/jpeg", f, map[string]string{"X-Cam-Seq": strconv.FormatUint(seq, 10)}
	case method == "POST" && path == "/api/cancel":
		c, s := kl.Cancel()
		return js(c, s)
	case method == "POST" && path == "/api/pause":
		c, s := kl.Pause(q.Get("action"))
		return js(c, s)
	case method == "POST" && path == "/api/exclude":
		c, s := kl.Exclude(q.Get("name"))
		return js(c, s)
	case method == "POST" && path == "/api/reset":
		// « Supprimer le PitBoard » dans l'app : Link oublie le compte et redemande un code.
		a.store.SetToken("")
		a.e2e.Reset()
		if a.tun != nil {
			go func() { time.Sleep(500 * time.Millisecond); a.tun.Reconnect() }()
		}
		return js(200, `{"ok":true,"full":false}`)
	case method == "POST" && path == "/api/reboot":
		go func() { time.Sleep(500 * time.Millisecond); log.Print("redémarrage demandé"); os.Exit(0) }()
		return js(200, `{"ok":true}`)
	}
	return js(404, `{"error":"inconnu"}`)
}

// ---------------------------------------------------------------------------
// Serveur local HTTPS (réseau de la maison seulement)
// ---------------------------------------------------------------------------

func privateAddr(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

func (a *App) localHandler(w http.ResponseWriter, r *http.Request) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip := net.ParseIP(host); ip == nil || !privateAddr(ip) {
		http.Error(w, "", http.StatusForbidden)
		return
	}
	tok := a.store.Token()
	got := r.Header.Get("X-Pit-Token")
	full := tok != "" && got != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(got)) == 1
	if full && r.Method == "GET" && r.URL.Path == "/api/cam" && r.URL.Query().Get("stream") == "1" && r.URL.Query().Get("h264") == "1" {
		a.streamH264(w, r)
		return
	}
	if full && r.Method == "GET" && r.URL.Path == "/api/cam" && r.URL.Query().Get("stream") == "1" {
		a.streamCam(w, r)
		return
	}
	// 1.1.0 : appairage local d'un téléphone pour le chiffrement de bout en bout.
	if r.URL.Path == "/api/e2e/enroll" || r.URL.Path == "/api/e2e/verify" {
		if !full || r.Method != "POST" {
			http.Error(w, "", http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4<<10))
		var code int
		var s string
		if r.URL.Path == "/api/e2e/verify" {
			code, s = a.e2e.Verify(body)
		} else {
			code, s = a.e2e.Enroll(body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(code)
		w.Write([]byte(s))
		return
	}
	var body []byte
	if r.Method == "POST" {
		body, _ = io.ReadAll(io.LimitReader(r.Body, 64<<10))
	}
	code, mimeT, data, hdr := a.handle(r.Context(), r.Method, r.URL.Path, r.URL.Query(), body, full)
	for k, v := range hdr {
		w.Header().Set(k, v)
	}
	w.Header().Set("Cache-Control", "no-store")
	if mimeT != "" {
		w.Header().Set("Content-Type", mimeT)
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(code)
	w.Write(data)
}

// streamCam : flux MJPEG continu (multipart/x-mixed-replace) pour l'app sur le WiFi.
// Toujours la dernière image : si le téléphone lit moins vite, les images intermédiaires sont sautées.
func (a *App) streamCam(w http.ResponseWriter, r *http.Request) {
	slot, _ := strconv.Atoi(r.URL.Query().Get("p"))
	impCfg, ok := a.store.Config().Imprimante(slot)
	cam := a.camera(slot)
	if !ok || !impCfg.Cam || cam == nil {
		http.Error(w, "", http.StatusNotFound)
		return
	}
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "multipart/x-mixed-replace; boundary=pbframe")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(200)
	rc.Flush()
	var last uint64
	for {
		f, seq, err := cam.Next(r.Context(), last, 10*time.Second)
		if err != nil {
			if r.Context().Err() != nil {
				return
			}
			continue
		}
		rc.SetWriteDeadline(time.Now().Add(15 * time.Second))
		hdr := fmt.Sprintf("--pbframe\r\nContent-Type: image/jpeg\r\nContent-Length: %d\r\nX-Cam-Seq: %d\r\n\r\n", len(f), seq)
		if _, err := w.Write([]byte(hdr)); err != nil {
			return
		}
		if _, err := w.Write(f); err != nil {
			return
		}
		if _, err := w.Write([]byte("\r\n")); err != nil {
			return
		}
		if rc.Flush() != nil {
			return
		}
		last = seq
	}
}

// streamH264 : vidéo H.264 de la webcam pour l'app sur le WiFi, sans réencodage. Chaque image :
// longueur (4 octets), drapeaux (1 octet, bit 0 = image clé), horodatage RTP (4 octets), Annex-B.
// Le flux commence sur une image clé. 404 si la webcam n'a pas de H.264 : l'app reste en MJPEG.
func (a *App) streamH264(w http.ResponseWriter, r *http.Request) {
	slot, _ := strconv.Atoi(r.URL.Query().Get("p"))
	impCfg, ok := a.store.Config().Imprimante(slot)
	h := a.h264(slot)
	if !ok || !impCfg.Cam || h == nil || !h.Attendre(8*time.Second) {
		http.Error(w, "", http.StatusNotFound)
		return
	}
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "video/x-pitboard-h264")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(200)
	rc.Flush()
	var tete [9]byte
	h.Suivre(r.Context().Done(), func(au AU) error {
		binary.BigEndian.PutUint32(tete[0:4], uint32(len(au.Data)))
		tete[4] = 0
		if au.Cle {
			tete[4] = 1
		}
		binary.BigEndian.PutUint32(tete[5:9], au.TS)
		rc.SetWriteDeadline(time.Now().Add(15 * time.Second))
		if _, err := w.Write(tete[:]); err != nil {
			return err
		}
		if _, err := w.Write(au.Data); err != nil {
			return err
		}
		return rc.Flush()
	})
}

func (a *App) serveLocal(cert tls.Certificate) {
	port := a.store.Config().Port
	srv := &http.Server{
		Addr:              ":" + strconv.Itoa(port),
		Handler:           http.HandlerFunc(a.localHandler),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      40 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	for {
		log.Printf("serveur local HTTPS sur le port %d", port)
		err := srv.ListenAndServeTLS("", "")
		log.Printf("serveur local arrêté : %v (nouvel essai dans 10 s)", err)
		time.Sleep(10 * time.Second)
	}
}
