package main

// Lecture de l'imprimante Klipper par Moonraker (en local sur l'hôte).
// Reprise fidèle de sources.h (firmware 0.9.15) : mêmes états, mêmes champs,
// mêmes règles (fin d'impression des Qidi lue dans l'historique, miniatures des
// .3mf à plusieurs plateaux, Qidi Box, Spoolman, objets ignorables, alertes).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
)

type Phase int

const (
	PhUnknown Phase = iota
	PhOffline
	PhIdle
	PhPrinting
	PhPaused
	PhFinished
	PhFailed
)

func (p Phase) Name() string {
	switch p {
	case PhOffline:
		return "hors ligne"
	case PhIdle:
		return "au repos"
	case PhPrinting:
		return "impression"
	case PhPaused:
		return "pause"
	case PhFinished:
		return "terminé"
	case PhFailed:
		return "échec / annulé"
	}
	return "inconnu"
}

func isActivePh(p Phase) bool { return p == PhPrinting || p == PhPaused }

type PState struct {
	Enabled, Connected bool
	Phase              Phase
	WasActive          bool
	Progress           float64
	Layer, TotalLayer  int
	RemainingMin       int
	Job, Raw, Error    string
	TNoz, TNozT        float64
	TBed, TBedT        float64
	TCh, TChT          float64
	SpeedPct           int
	FanPct             int
	Velocity, Flow     float64
	ElapsedSec         int
	FilUsedMm          float64
	FilTotalMm         float64
	FilWeightG         float64
	FilType            string
	Thumb              string
	ThumbID            int
	LastUpdate         time.Time
	StartedAt          time.Time
	FinishedCount      int
	FailedCount        int
	EndedAt            time.Time
	EndPhase           Phase
	LastJob            string
	RunSec             int
	LastDurSec         int
	Alert              string
	PausedAt           time.Time
	PauseWhy           string
	FilSensor          int
	TNoz2, TNoz2T      float64
	NozActive          int
	FanAux, FanCham    int
	Model, FwCur       string
	ExNames            []string
	ExTotal            int
	ExDone             map[int]bool
	ExCur              int
	AmsUnits           int
	AmsMask            uint16
	AmsType            [16]string
	AmsCol             [16]uint32
	AmsRemain          [16]int
	AmsHum             [4]int
	TrayNow            int
	Spool              string
	SpoolCol           uint32
	SpoolRemainG       float64
	History            bool
	CancelMsg          string
	CancelAt           time.Time
	CamOK              bool
	CamRot             int
	CamFlipH, CamFlipV bool
}

func newPState() PState {
	p := PState{
		Enabled: true, Phase: PhUnknown, Layer: -1, TotalLayer: -1, RemainingMin: -1,
		TNoz: -1000, TNozT: -1, TBed: -1000, TBedT: -1, TCh: -1000, TChT: -1,
		SpeedPct: -1, FanPct: -1, Velocity: -1, Flow: -1, ElapsedSec: -1,
		FilUsedMm: -1, FilTotalMm: -1, FilWeightG: -1, LastDurSec: -1, FilSensor: -1,
		TNoz2: -1000, TNoz2T: -1, NozActive: -1, FanAux: -1, FanCham: -1, ExCur: -1,
		TrayNow: -1, SpoolRemainG: -1, EndPhase: PhUnknown,
	}
	for i := range p.AmsRemain {
		p.AmsRemain[i] = -1
	}
	for i := range p.AmsHum {
		p.AmsHum[i] = -1
	}
	return p
}

// applyPhase : transitions (début / fin d'impression). À appeler sous verrou.
func (s *PState) applyPhase(nw Phase) {
	now := time.Now()
	if nw != PhOffline && nw != PhUnknown {
		active := isActivePh(nw)
		if (active || s.WasActive) && s.Job != "" {
			s.LastJob = s.Job
		}
		if active && s.WasActive && s.ElapsedSec > 0 {
			s.RunSec = s.ElapsedSec
		}
		if s.WasActive && (nw == PhFinished || nw == PhFailed) {
			if s.RunSec > 0 {
				s.LastDurSec = s.RunSec
			} else {
				s.LastDurSec = int(now.Sub(s.StartedAt).Seconds())
			}
		}
		if active && !s.WasActive {
			s.RunSec = 0
		}
		if s.WasActive && nw == PhFinished {
			s.FinishedCount++
		}
		if s.WasActive && nw == PhFailed {
			s.FailedCount++
		}
		if s.WasActive && (nw == PhFinished || nw == PhFailed) {
			s.EndedAt = now
			s.EndPhase = nw
		}
		if active && !s.WasActive {
			s.StartedAt = now
		}
		s.WasActive = active
	}
	if nw == PhPaused && s.Phase != PhPaused {
		s.PausedAt = now
	}
	if nw != PhPaused {
		s.PausedAt = time.Time{}
		s.PauseWhy = ""
	}
	s.Phase = nw
}

type Klipper struct {
	store  *Store
	slot   int
	client *http.Client

	mu sync.Mutex
	s  PState

	// cache (propre à la tâche de lecture)
	objDone                 bool
	chamberObj, fanObj      string
	filObj, query, metaFile string
	camSnap, camStream      string
	camH264                 []string // 1.4.0 : adresses RTSP H.264 possibles (camera-streamer, go2rtc)
	hasBox, hasExt1         bool
	hasExclude              bool
	auxFanObj, chamFanObj   string
	fwStr                   string
	noSpoolman              bool
	estSec                  float64
	endTries                int
	fails                   int
	metaNext, spoolNext     time.Time
	boxNext, exNext         time.Time
	camNext, thumbNext      time.Time
	histNext                time.Time
	histWas                 bool

	hist     []byte
	histAt   time.Time
	relire   atomic.Bool // 1.2.0 : réglages changés (adresse, caméra) : tout relire
	thumbBuf []byte
	thumbFor int
	changed  chan struct{}
}

func newKlipper(st *Store, slot int, changed chan struct{}) *Klipper {
	return &Klipper{
		store:   st,
		slot:    slot,
		client:  &http.Client{Timeout: 6 * time.Second},
		s:       newPState(),
		estSec:  -1,
		changed: changed,
	}
}

// pc : réglages de cette imprimante (1.2.0 : un Link peut en suivre plusieurs).
func (k *Klipper) pc() Imp {
	p, _ := k.store.Config().Imprimante(k.slot)
	return p
}

func (k *Klipper) logf(f string, a ...any) {
	if k.slot == 0 {
		log.Printf("klipper : "+f, a...)
	} else {
		log.Printf(fmt.Sprintf("klipper %d : ", k.slot+1)+f, a...)
	}
}

func (k *Klipper) base() string { return strings.TrimRight(k.pc().Moonraker, "/") }

func (k *Klipper) do(method, path string, body []byte) (int, []byte) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, k.base()+path, rd)
	if err != nil {
		return -1, nil
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if key := k.pc().APIKey; key != "" {
		req.Header.Set("X-Api-Key", key)
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return -1, nil
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return -1, nil
	}
	return resp.StatusCode, b
}

func (k *Klipper) get(path string) (int, []byte) { return k.do("GET", path, nil) }

func (k *Klipper) post(path string, js any) (int, []byte) {
	b, _ := json.Marshal(js)
	return k.do("POST", path, b)
}

// --- petits accès JSON ---------------------------------------------------------

type M = map[string]any

func mget(m M, keys ...string) any {
	var v any = m
	for _, k := range keys {
		mm, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = mm[k]
	}
	return v
}

func mmap(m M, keys ...string) M {
	if v, ok := mget(m, keys...).(map[string]any); ok {
		return v
	}
	return nil
}

func mf(m M, def float64, keys ...string) float64 {
	switch v := mget(m, keys...).(type) {
	case float64:
		return v
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	case bool:
		if v {
			return 1
		}
		return 0
	}
	return def
}

func ms(m M, keys ...string) string {
	if v, ok := mget(m, keys...).(string); ok {
		return v
	}
	return ""
}

func mb(m M, def bool, keys ...string) bool {
	switch v := mget(m, keys...).(type) {
	case bool:
		return v
	case float64:
		return v != 0
	}
	return def
}

func marr(m M, keys ...string) []any {
	if v, ok := mget(m, keys...).([]any); ok {
		return v
	}
	return nil
}

func parseJSON(b []byte) M {
	var m M
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	return m
}

func urlEnc(s string, keepSlash bool) string {
	e := url.PathEscape(s)
	if !keepSlash {
		e = strings.ReplaceAll(e, "/", "%2F")
	}
	return strings.ReplaceAll(e, "+", "%2B")
}

func qEnc(s string) string { return url.QueryEscape(s) }

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return s[:i]
	}
	return s
}

func hexCol(h string) uint32 {
	h = strings.TrimPrefix(h, "#")
	if len(h) < 6 {
		return 0
	}
	v, err := strconv.ParseUint(h[:6], 16, 32)
	if err != nil {
		return 0
	}
	return 0x1000000 | uint32(v)
}

// --- webcam ------------------------------------------------------------------

func (k *Klipper) webcam() {
	cfg := k.pc()
	if cfg.CamURL != "" {
		k.camStream = cfg.CamURL
		k.camSnap = strings.Replace(cfg.CamURL, "action=stream", "action=snapshot", 1)
		return
	}
	code, body := k.get("/server/webcams/list")
	if code != 200 {
		return
	}
	d := parseJSON(body)
	if d == nil {
		return
	}
	host := "http://127.0.0.1"
	if u, err := url.Parse(k.base()); err == nil && u.Hostname() != "" {
		host = u.Scheme + "://" + u.Hostname()
	}
	k.camSnap, k.camStream, k.camH264 = "", "", nil
	abs := func(u string) string {
		if u == "" || strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
			return u
		}
		if !strings.HasPrefix(u, "/") {
			u = "/" + u
		}
		return host + u
	}
	for _, wv := range marr(d, "result", "webcams") {
		w, _ := wv.(map[string]any)
		if w == nil || !mb(w, true, "enabled") {
			continue
		}
		snap, stream := webcamURLs(ms(w, "service"), ms(w, "stream_url"), ms(w, "snapshot_url"))
		if snap == "" && stream == "" {
			continue
		}
		k.camSnap, k.camStream = abs(snap), abs(stream)
		k.camH264 = h264Candidats(ms(w, "service"), abs(ms(w, "stream_url")), abs(ms(w, "snapshot_url")))
		k.mu.Lock()
		k.s.CamRot = int(mf(w, 0, "rotation"))
		k.s.CamFlipH = mb(w, false, "flip_horizontal")
		k.s.CamFlipV = mb(w, false, "flip_vertical")
		k.mu.Unlock()
		return
	}
}

// Une fois par connexion : capteurs, ventilateurs, webcam, version.
func (k *Klipper) objects() int {
	code, body := k.get("/printer/objects/list")
	if code != 200 {
		return code
	}
	d := parseJSON(body)
	if d == nil {
		return 0
	}
	var heat, sens, fanGen string
	fanScore, auxScore, chamScore := 0, 0, 0
	k.hasExt1, k.hasExclude = false, false
	k.auxFanObj, k.chamFanObj = "", ""
	plainFan := false
	for _, v := range marr(d, "result", "objects") {
		s, _ := v.(string)
		lo := strings.ToLower(s)
		if strings.Contains(lo, "chamber") {
			if strings.HasPrefix(lo, "heater_generic ") && heat == "" {
				heat = s
			} else if strings.HasPrefix(lo, "temperature_sensor ") && sens == "" {
				sens = s
			}
		}
		if (strings.HasPrefix(lo, "filament_switch_sensor ") || strings.HasPrefix(lo, "filament_motion_sensor ")) && k.filObj == "" {
			k.filObj = s
		}
		if s == "box_extras" {
			k.hasBox = true
		}
		if s == "extruder1" {
			k.hasExt1 = true
		}
		if s == "exclude_object" {
			k.hasExclude = true
		}
		fanLike := strings.HasPrefix(lo, "fan_generic ") || strings.HasPrefix(lo, "controller_fan ") ||
			strings.HasPrefix(lo, "heater_fan ") || strings.HasPrefix(lo, "temperature_fan ")
		if fanLike && !strings.HasPrefix(lo, "heater_fan ") && !strings.Contains(lo, "box") {
			gen := 1
			if strings.HasPrefix(lo, "fan_generic ") {
				gen = 2
			}
			if strings.Contains(lo, "aux") && gen > auxScore {
				auxScore, k.auxFanObj = gen, s
			} else if (strings.Contains(lo, "chamber") || strings.Contains(lo, "exhaust")) && gen > chamScore {
				chamScore, k.chamFanObj = gen, s
			}
		}
		if s == "fan" {
			plainFan = true
		} else if strings.HasPrefix(lo, "fan_generic ") {
			sc := 0
			if lo == "fan_generic cooling_fan" || lo == "fan_generic part_fan" {
				sc = 3
			} else if strings.Contains(lo, "part") {
				sc = 2
			} else if strings.Contains(lo, "cooling") && !strings.Contains(lo, "aux") && !strings.Contains(lo, "chamber") && !strings.Contains(lo, "board") {
				sc = 1
			}
			if sc > fanScore {
				fanScore, fanGen = sc, s
			}
		}
	}
	if heat != "" {
		k.chamberObj = heat
	} else {
		k.chamberObj = sens
	}
	if plainFan {
		k.fanObj = "fan"
	} else {
		k.fanObj = fanGen
	}
	q := "/printer/objects/query?print_stats=state,filename,print_duration,total_duration,filament_used,info,message" +
		"&display_status=progress,message&virtual_sdcard=progress&extruder=temperature,target&webhooks=state,state_message" +
		"&heater_bed=temperature,target&gcode_move=speed_factor" +
		"&motion_report=live_velocity,live_extruder_velocity"
	if k.fanObj != "" {
		q += "&" + qEnc(k.fanObj) + "=speed"
	}
	if k.chamberObj != "" {
		q += "&" + qEnc(k.chamberObj) + "=temperature,target"
	}
	if k.filObj != "" {
		q += "&" + qEnc(k.filObj) + "=filament_detected,enabled"
	}
	if k.hasExt1 {
		q += "&extruder1=temperature,target&toolhead=extruder"
	}
	if k.auxFanObj != "" {
		q += "&" + qEnc(k.auxFanObj) + "=speed"
	}
	if k.chamFanObj != "" {
		q += "&" + qEnc(k.chamFanObj) + "=speed"
	}
	k.query = q
	k.objDone = true
	// Version : Klipper, sinon firmware de la carte mère (Qidi masque la version de Klipper).
	k.fwStr = ""
	if c, b := k.get("/printer/info"); c == 200 {
		v := strings.TrimSpace(ms(parseJSON(b), "result", "software_version"))
		if len(v) > 1 && v != "?" {
			k.fwStr = "Klipper " + v
		}
	}
	if k.fwStr == "" {
		if c, b := k.get("/printer/objects/query?mcu=mcu_version"); c == 200 {
			v := strings.TrimSpace(ms(parseJSON(b), "result", "status", "mcu", "mcu_version"))
			if len(v) > 1 && v != "?" {
				k.fwStr = v
			}
		}
	}
	k.fwStr = trunc(k.fwStr, 23)
	k.webcam()
	k.logf("version %q, enceinte %q, ventilateur %q, filament %q, caméra %q", k.fwStr, k.chamberObj, k.fanObj, k.filObj, k.camStream)
	return 200
}

// Quand le fichier change : estimation du trancheur, filament, miniature.
func (k *Klipper) meta(file string) {
	if time.Now().Before(k.metaNext) {
		return
	}
	k.metaNext = time.Now().Add(30 * time.Second)
	metaF := file
	code, body := k.get("/server/files/metadata?filename=" + qEnc(metaF))
	if code == 404 && strings.HasPrefix(file, ".cache/") {
		metaF = file[7:]
		code, body = k.get("/server/files/metadata?filename=" + qEnc(metaF))
	}
	if code != 200 && code != 404 {
		return
	}
	k.metaFile = file
	k.metaNext = time.Time{}
	est, total, weight := -1.0, -1.0, -1.0
	typ, thumb := "", ""
	if code == 200 {
		if d := parseJSON(body); d != nil {
			r := mmap(d, "result")
			est = mf(r, -1, "estimated_time")
			total = mf(r, -1, "filament_total")
			weight = mf(r, -1, "filament_weight_total")
			typ = ms(r, "filament_type")
			best := -1
			for _, tv := range marr(r, "thumbnails") {
				t, _ := tv.(map[string]any)
				w := int(mf(t, 0, "width"))
				rp := ms(t, "relative_path")
				if rp == "" {
					continue
				}
				better := best < 0 || (w <= 400 && (best > 400 || w > best)) || (best > 400 && w < best)
				if better {
					best, thumb = w, rp
				}
			}
			if thumb != "" {
				if sl := strings.LastIndexByte(metaF, '/'); sl >= 0 {
					thumb = metaF[:sl+1] + thumb
				}
			}
		}
	}
	k.estSec = est
	k.mu.Lock()
	k.s.FilTotalMm, k.s.FilWeightG, k.s.FilType, k.s.Thumb = total, weight, typ, thumb
	k.s.ThumbID++
	k.mu.Unlock()
}

func (k *Klipper) lastJob() Phase {
	code, body := k.get("/server/history/list?limit=1&order=desc")
	if code != 200 {
		return PhIdle
	}
	jobs := marr(parseJSON(body), "result", "jobs")
	st := ""
	if len(jobs) > 0 {
		if j, ok := jobs[0].(map[string]any); ok {
			st = ms(j, "status")
		}
	}
	k.logf("fin d'impression sans état « complete », historique : %s", st)
	switch st {
	case "completed":
		return PhFinished
	case "in_progress":
		return PhUnknown
	case "":
		return PhIdle
	}
	return PhFailed
}

func (k *Klipper) spool() {
	if k.noSpoolman || time.Now().Before(k.spoolNext) {
		return
	}
	k.spoolNext = time.Now().Add(60 * time.Second)
	code, body := k.get("/server/spoolman/status")
	if code == 404 {
		k.noSpoolman = true
		return
	}
	if code != 200 {
		return
	}
	id := int(mf(parseJSON(body), -1, "result", "spool_id"))
	if id < 0 {
		k.mu.Lock()
		k.s.Spool, k.s.SpoolCol, k.s.SpoolRemainG = "", 0, -1
		k.mu.Unlock()
		return
	}
	code, body = k.post("/server/spoolman/proxy", M{"request_method": "GET", "path": fmt.Sprintf("/v1/spool/%d", id)})
	if code != 200 {
		return
	}
	d := parseJSON(body)
	r := mmap(d, "result")
	if r == nil {
		r = d
	}
	nom := ms(r, "filament", "material")
	if fn := ms(r, "filament", "name"); fn != "" {
		if nom != "" {
			nom += " "
		}
		nom += fn
	}
	if vn := ms(r, "filament", "vendor", "name"); vn != "" {
		nom += " (" + vn + ")"
	}
	k.mu.Lock()
	k.s.Spool = trunc(nom, 47)
	k.s.SpoolCol = hexCol(ms(r, "filament", "color_hex"))
	k.s.SpoolRemainG = mf(r, -1, "remaining_weight")
	k.mu.Unlock()
}

func jInt(v any, def int) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(x)); err == nil {
			return n
		}
	case bool:
		if x {
			return 1
		}
		return 0
	}
	return def
}

// Qidi Box : 4 emplacements par Box, jusqu'à 4 Box, toutes les 30 s.
func (k *Klipper) box() {
	if !k.hasBox || time.Now().Before(k.boxNext) {
		return
	}
	k.boxNext = time.Now().Add(30 * time.Second)
	code, body := k.get("/printer/objects/query?box_extras=boxes,loaded_slot&save_variables=variables")
	if code != 200 {
		return
	}
	d := parseJSON(body)
	bx := mmap(d, "result", "status", "box_extras")
	vars := mmap(d, "result", "status", "save_variables", "variables")
	units := 0
	var mask uint16
	var typ [16]string
	var col [16]uint32
	var remain [16]int
	hum := [4]int{-1, -1, -1, -1}
	for i := range remain {
		remain[i] = -1
	}
	u := 0
	for _, bv := range marr(bx, "boxes") {
		if u >= 4 {
			break
		}
		b, _ := bv.(map[string]any)
		if jInt(mget(b, "is_online"), 0) == 0 {
			u++
			continue
		}
		units = u + 1
		if h := jInt(mget(b, "aht20_humidity"), -1); h > 0 {
			hum[u] = min(max(h, 0), 100)
		}
		t := 0
		for _, fv := range marr(b, "filament_info") {
			if t >= 4 {
				break
			}
			f, _ := fv.(map[string]any)
			kk := u*4 + t
			t++
			etat := 1
			if vars != nil {
				if v, ok := vars[fmt.Sprintf("slot%d", kk)]; ok && v != nil {
					etat = jInt(v, 0)
				}
			}
			if etat <= 0 {
				continue
			}
			mask |= 1 << kk
			typ[kk] = trunc(ms(f, "filament_type"), 7)
			if cs := marr(f, "color_rgb_str"); len(cs) > 0 {
				if hx, ok := cs[0].(string); ok {
					col[kk] = hexCol(hx)
				}
			}
			if jInt(mget(f, "info_from_rfid"), 0) != 0 && mget(f, "filament_per") != nil {
				remain[kk] = min(max(jInt(mget(f, "filament_per"), -1), -1), 100)
			}
		}
		u++
	}
	ld := ms(bx, "loaded_slot")
	now := -1
	if strings.HasPrefix(ld, "slot") {
		now, _ = strconv.Atoi(ld[4:])
		if now >= 16 {
			now = 254
		}
	}
	k.mu.Lock()
	k.s.AmsUnits, k.s.AmsMask, k.s.AmsType, k.s.AmsCol, k.s.AmsRemain, k.s.AmsHum, k.s.TrayNow = units, mask, typ, col, remain, hum, now
	k.mu.Unlock()
}

// Noms d'objets sûrs : lettres, chiffres, « _ », « - », « . » (pas d'injection de G-code).
func klNameOk(n string) bool {
	if n == "" || len(n) >= 32 {
		return false
	}
	for _, r := range n {
		if r > 127 || !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

func (k *Klipper) exclude(active bool) {
	if !k.hasExclude {
		return
	}
	if !active {
		k.mu.Lock()
		k.s.ExNames, k.s.ExTotal, k.s.ExDone, k.s.ExCur = nil, 0, nil, -1
		k.mu.Unlock()
		return
	}
	if time.Now().Before(k.exNext) {
		return
	}
	k.exNext = time.Now().Add(10 * time.Second)
	code, body := k.get("/printer/objects/query?exclude_object=objects,excluded_objects,current_object")
	if code != 200 {
		return
	}
	eo := mmap(parseJSON(body), "result", "status", "exclude_object")
	cur := ms(eo, "current_object")
	excl := map[string]bool{}
	for _, x := range marr(eo, "excluded_objects") {
		if s, ok := x.(string); ok {
			excl[s] = true
		}
	}
	var names []string
	done := map[int]bool{}
	total, ci := 0, -1
	for _, ov := range marr(eo, "objects") {
		o, _ := ov.(map[string]any)
		nm := ms(o, "name")
		if !klNameOk(nm) {
			continue
		}
		total++
		if len(names) >= 12 {
			continue
		}
		if excl[nm] {
			done[len(names)] = true
		}
		if nm == cur {
			ci = len(names)
		}
		names = append(names, nm)
	}
	k.mu.Lock()
	k.s.ExNames, k.s.ExTotal, k.s.ExDone, k.s.ExCur = names, total, done, ci
	k.mu.Unlock()
}

func (k *Klipper) notReady() bool {
	code, body := k.get("/printer/info")
	if code != 200 {
		return false
	}
	r := mmap(parseJSON(body), "result")
	st := ms(r, "state")
	if st == "ready" || r == nil {
		return false
	}
	msg := firstLine(ms(r, "state_message"))
	k.mu.Lock()
	defer k.mu.Unlock()
	k.s.Connected = true
	verbe, err := "arrêté", "Klipper arrêté"
	if st == "startup" {
		verbe, err = "démarre", "Klipper démarre"
	}
	k.s.Alert = trunc("Klipper "+verbe+" : "+msg, 95)
	k.s.Error = err
	k.s.LastUpdate = time.Now()
	if st != "startup" && k.s.WasActive {
		k.s.applyPhase(PhFailed)
	}
	return true
}

func (k *Klipper) thumb() {
	k.mu.Lock()
	path, id := k.s.Thumb, k.s.ThumbID
	k.mu.Unlock()
	if path == "" || k.thumbFor == id || time.Now().Before(k.thumbNext) {
		return
	}
	k.thumbNext = time.Now().Add(30 * time.Second)
	code, body := k.get("/server/files/gcodes/" + urlEnc(path, true))
	if code == 200 && len(body) > 0 && len(body) <= 1<<20 {
		k.mu.Lock()
		k.thumbBuf, k.thumbFor = body, id
		k.mu.Unlock()
		k.logf("miniature enregistrée (%d o)", len(body))
		return
	}
	if code != 404 {
		return
	}
	// .3mf à plusieurs plateaux : l'image annoncée n'existe pas, on prend celle du dossier.
	sl := strings.LastIndexByte(path, '/')
	if sl < 0 {
		return
	}
	dir := path[:sl]
	c, b := k.get("/server/files/directory?path=gcodes/" + urlEnc(dir, true) + "&extended=false")
	if c != 200 {
		return
	}
	best := ""
	for _, fv := range marr(parseJSON(b), "result", "files") {
		f, _ := fv.(map[string]any)
		fn := ms(f, "filename")
		lo := strings.ToLower(fn)
		if !strings.HasSuffix(lo, ".png") || strings.Contains(lo, "small") {
			continue
		}
		if best == "" || (strings.HasPrefix(lo, "plate_") && !strings.HasPrefix(strings.ToLower(best), "plate_")) {
			best = fn
		}
	}
	if best == "" {
		return
	}
	np := dir + "/" + best
	if np == path {
		return
	}
	k.logf("miniature annoncée absente, trouvée : %s", best)
	k.mu.Lock()
	if k.s.ThumbID == id {
		k.s.Thumb = np
	}
	k.mu.Unlock()
	k.thumbNext = time.Now().Add(time.Second)
}

func round1(f float64) float64 { return math.Round(f*10) / 10 }

func (k *Klipper) history() {
	k.histNext = time.Now().Add(10 * time.Minute)
	code, body := k.get("/server/history/totals")
	if code != 200 {
		k.histNext = time.Now().Add(time.Minute)
		return
	}
	t := mmap(parseJSON(body), "result", "job_totals")
	if t == nil {
		k.histNext = time.Now().Add(time.Minute)
		return
	}
	out := M{"totals": M{
		"jobs":       int(mf(t, 0, "total_jobs")),
		"timeSec":    int64(mf(t, 0, "total_time")),
		"printSec":   int64(mf(t, 0, "total_print_time")),
		"filamentM":  round1(mf(t, 0, "total_filament_used") / 1000),
		"longestSec": int64(mf(t, 0, "longest_job")),
	}}
	code, body = k.get("/server/history/list?limit=5&order=desc")
	if code != 200 {
		k.logf("historique, liste illisible (%d), nouvel essai dans 1 min", code)
		k.histNext = time.Now().Add(time.Minute)
		return
	}
	jobs := []M{}
	for _, jv := range marr(parseJSON(body), "result", "jobs") {
		j, _ := jv.(map[string]any)
		jobs = append(jobs, M{
			"file":      ms(j, "filename"),
			"status":    ms(j, "status"),
			"durSec":    int64(mf(j, 0, "print_duration")),
			"end":       int64(mf(j, 0, "end_time")),
			"filamentM": round1(mf(j, 0, "filament_used") / 1000),
		})
	}
	out["jobs"] = jobs
	b, _ := json.Marshal(out)
	k.mu.Lock()
	k.hist, k.histAt = b, time.Now()
	k.mu.Unlock()
}

// Boucle de lecture : toutes les 2 s (3 s sur l'ESP32).
func (k *Klipper) run(stop <-chan struct{}) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	k.poll()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			k.poll()
		}
	}
}

func (k *Klipper) notify() {
	select {
	case k.changed <- struct{}{}:
	default:
	}
}

func (k *Klipper) setError(msg string) {
	k.mu.Lock()
	k.s.Error = msg
	k.mu.Unlock()
}

// reload : demandé après un changement de réglages ; pris en compte à la lecture suivante.
func (k *Klipper) reload() { k.relire.Store(true) }

func (k *Klipper) poll() {
	defer k.notify()
	if k.relire.Swap(false) {
		k.objDone, k.camStream, k.camSnap, k.metaFile, k.camH264 = false, "", "", "", nil
	}
	code := 200
	var body []byte
	if !k.objDone {
		code = k.objects()
	}
	if k.objDone {
		code, body = k.get(k.query)
	} else if code != 401 && code != 403 && code >= 0 {
		code, body = k.get("/printer/objects/query?print_stats=state,filename,print_duration,info&display_status=progress&virtual_sdcard=progress")
	}
	ok := false
	file := ""
	switch {
	case code == 200:
		d := parseJSON(body)
		if d == nil {
			k.setError("réponse JSON invalide")
			break
		}
		ok = true
		k.apply(mmap(d, "result", "status"), &file)
	case code == 401 || code == 403:
		if k.pc().APIKey == "" {
			if k.slot == 0 {
				k.setError("accès refusé : ajoute 127.0.0.1 dans trusted_clients ou saisis une clé API")
			} else {
				k.setError("accès refusé : saisis la clé API de cette imprimante")
			}
		} else {
			k.setError("clé API refusée")
		}
	case code < 0:
		k.setError("Moonraker injoignable")
	default:
		if k.notReady() {
			k.fails = 0
			return
		}
		k.setError(fmt.Sprintf("HTTP %d", code))
	}
	if !ok {
		k.fails++
		if k.fails >= 5 {
			k.mu.Lock()
			if k.s.Connected || k.s.Phase != PhOffline {
				k.s.Connected = false
				k.s.applyPhase(PhOffline)
			}
			k.mu.Unlock()
			k.objDone = false // relu à la reconnexion (Klipper redémarré)
		}
		return
	}
	k.fails = 0
	now := time.Now()
	if k.camStream == "" && k.camSnap == "" && now.After(k.camNext) {
		k.camNext = now.Add(time.Minute)
		k.webcam()
	}
	if file == "" {
		k.metaFile, k.estSec = "", -1
	} else if file != k.metaFile && !now.Before(k.metaNext) {
		k.meta(file)
	}
	k.spool()
	k.box()
	k.mu.Lock()
	actNow := k.s.WasActive
	exAct := isActivePh(k.s.Phase)
	needThumb := k.s.Thumb != "" && k.thumbFor != k.s.ThumbID
	k.mu.Unlock()
	if k.hasExclude {
		k.exclude(exAct)
	}
	if k.histWas && !actNow {
		k.histNext = now.Add(5 * time.Second)
	}
	k.histWas = actNow
	if !now.Before(k.histNext) {
		k.history()
	}
	if needThumb {
		k.thumb()
	}
}

func (k *Klipper) apply(r M, fileOut *string) {
	ps := mmap(r, "print_stats")
	state := ms(ps, "state")
	dp := mf(r, 0, "display_status", "progress")
	vp := mf(r, 0, "virtual_sdcard", "progress")
	p := vp
	if dp > 0 {
		p = dp
	}
	dur := mf(ps, 0, "print_duration")
	tot := mf(ps, -1, "total_duration")
	layer := int(mf(ps, -1, "info", "current_layer"))
	total := int(mf(ps, -1, "info", "total_layer"))
	file := ms(ps, "filename")
	*fileOut = file

	ph := PhIdle
	switch state {
	case "printing":
		ph = PhPrinting
	case "paused":
		ph = PhPaused
	case "complete":
		ph = PhFinished
	case "cancelled", "error":
		ph = PhFailed
	}
	k.mu.Lock()
	was, prevP := k.s.WasActive, k.s.Progress/100
	k.mu.Unlock()
	if was && ph == PhIdle {
		r := k.lastJob()
		k.endTries++
		if r == PhUnknown && k.endTries < 4 {
			ph, p = PhPrinting, prevP
		} else if r == PhUnknown {
			ph = PhIdle
		} else {
			ph = r
		}
		if ph == PhFinished {
			p = 1
		}
	} else {
		k.endTries = 0
	}
	active := isActivePh(ph)

	rem := -1
	if ph == PhPrinting {
		byFile := -1.0
		if p > 0.02 && dur > 60 {
			byFile = dur * (1 - p) / p
		}
		bySlicer := -1.0
		if k.estSec > 0 {
			bySlicer = math.Max(0, k.estSec-dur)
		}
		rr := -1.0
		if byFile >= 0 && bySlicer >= 0 {
			rr = byFile*p + bySlicer*(1-p)
		} else if bySlicer >= 0 {
			rr = bySlicer
		} else {
			rr = byFile
		}
		if rr >= 0 {
			rem = int(rr/60 + 0.5)
		}
	}
	ex, bed := mmap(r, "extruder"), mmap(r, "heater_bed")
	var ch M
	if k.chamberObj != "" {
		ch = mmap(r, k.chamberObj)
	}
	sf := mf(r, -1, "gcode_move", "speed_factor")
	lv := mf(r, -1, "motion_report", "live_velocity")
	le := mf(r, -1, "motion_report", "live_extruder_velocity")
	fan, fanA, fanC := -1.0, -1.0, -1.0
	if k.fanObj != "" {
		fan = mf(r, -1, k.fanObj, "speed")
	}
	if k.auxFanObj != "" {
		fanA = mf(r, -1, k.auxFanObj, "speed")
	}
	if k.chamFanObj != "" {
		fanC = mf(r, -1, k.chamFanObj, "speed")
	}
	var ex1 M
	if k.hasExt1 {
		ex1 = mmap(r, "extruder1")
	}
	nz := -1
	if k.hasExt1 {
		switch ms(r, "toolhead", "extruder") {
		case "extruder1":
			nz = 1
		case "extruder":
			nz = 0
		}
	}
	fil := -1
	if k.filObj != "" {
		if fo := mmap(r, k.filObj); fo != nil && mb(fo, true, "enabled") {
			if mb(fo, true, "filament_detected") {
				fil = 1
			} else {
				fil = 0
			}
		}
	}
	wst := ms(r, "webhooks", "state")
	if wst == "" {
		wst = "ready"
	}
	wmsg := firstLine(ms(r, "webhooks", "state_message"))
	pmsg := ms(ps, "message")
	dmsg := ms(r, "display_status", "message")
	alert := ""
	switch {
	case wst != "ready":
		alert = "Klipper arrêté : " + wmsg
	case state == "error" && pmsg != "":
		alert = "Erreur d'impression : " + pmsg
	case fil == 0 && active:
		alert = "Plus de filament détecté par le capteur"
	}
	why := ""
	if ph == PhPaused {
		switch {
		case fil == 0:
			why = "plus de filament"
		case dmsg != "":
			why = dmsg
		case pmsg != "":
			why = pmsg
		}
	}
	pct := func(v float64) int {
		if v < 0 {
			return -1
		}
		return int(math.Round(v * 100))
	}
	cfg := k.pc()

	k.mu.Lock()
	defer k.mu.Unlock()
	s := &k.s
	s.Connected = true
	s.Progress = p * 100
	s.Layer, s.TotalLayer, s.RemainingMin = layer, total, rem
	s.Job = trunc(file, 63)
	s.Raw = trunc(state, 15)
	s.TNoz, s.TNozT = mf(ex, -1000, "temperature"), mf(ex, -1, "target")
	s.TBed, s.TBedT = mf(bed, -1000, "temperature"), mf(bed, -1, "target")
	if ch == nil {
		s.TCh, s.TChT = -1000, -1
	} else {
		s.TCh, s.TChT = mf(ch, -1000, "temperature"), mf(ch, -1, "target")
	}
	if sf >= 0 {
		s.SpeedPct = int(math.Round(sf * 100))
	} else {
		s.SpeedPct = -1
	}
	s.Velocity, s.Flow = -1, -1
	if active {
		s.Velocity = lv
		if le >= 0 {
			s.Flow = le * 2.4053 // π × 0,875² mm²
		}
	}
	s.FanPct, s.FanAux, s.FanCham = pct(fan), pct(fanA), pct(fanC)
	if ex1 == nil {
		s.TNoz2, s.TNoz2T = -1000, -1
	} else {
		s.TNoz2, s.TNoz2T = mf(ex1, -1000, "temperature"), mf(ex1, -1, "target")
	}
	s.NozActive = nz
	s.Model = trunc(cfg.Model, 23)
	s.FwCur = k.fwStr
	s.ElapsedSec = -1
	if (active || ph == PhFinished) && tot >= 0 {
		s.ElapsedSec = int(tot)
	}
	s.FilUsedMm = mf(ps, -1, "filament_used")
	s.CamOK = cfg.Cam && (k.camStream != "" || k.camSnap != "")
	if file == "" {
		s.Thumb, s.FilType, s.FilTotalMm, s.FilWeightG = "", "", -1, -1
	}
	s.Error = ""
	s.FilSensor = fil
	s.Alert = trunc(alert, 95)
	s.History = true
	s.LastUpdate = time.Now()
	s.applyPhase(ph)
	if ph == PhPaused {
		s.PauseWhy = trunc(why, 63)
	}
}

// --- commandes ------------------------------------------------------------------

func (k *Klipper) active() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return isActivePh(k.s.Phase)
}

func (k *Klipper) Cancel() (int, string) {
	if !k.active() {
		return 409, `{"error":"aucune impression en cours"}`
	}
	log.Printf("annulation demandée")
	if c, _ := k.post("/printer/print/cancel", M{}); c == 200 {
		return 200, `{"ok":true}`
	}
	return 502, `{"error":"annulation refusée par Moonraker"}`
}

func (k *Klipper) Pause(action string) (int, string) {
	resume := action == "resume"
	if !resume && action != "pause" {
		return 400, `{"error":"action inconnue"}`
	}
	k.mu.Lock()
	ph := k.s.Phase
	k.mu.Unlock()
	if resume && ph != PhPaused {
		return 409, `{"error":"l'impression n'est pas en pause"}`
	}
	if !resume && ph != PhPrinting {
		return 409, `{"error":"aucune impression en cours"}`
	}
	path := "/printer/print/pause"
	if resume {
		path = "/printer/print/resume"
	}
	if c, _ := k.post(path, M{}); c == 200 {
		return 200, `{"ok":true}`
	}
	return 502, `{"error":"refusé par Moonraker"}`
}

func (k *Klipper) Exclude(name string) (int, string) {
	k.mu.Lock()
	known := false
	for _, n := range k.s.ExNames {
		if n == name {
			known = true
		}
	}
	act := isActivePh(k.s.Phase)
	k.mu.Unlock()
	if !act {
		return 409, `{"error":"aucune impression en cours"}`
	}
	if !known || !klNameOk(name) {
		return 400, `{"error":"objet inconnu"}`
	}
	if c, _ := k.post("/printer/gcode/script", M{"script": "EXCLUDE_OBJECT NAME=" + name}); c == 200 {
		log.Printf("objet ignoré : %s", name)
		return 200, `{"ok":true}`
	}
	return 502, `{"error":"refusé par Klipper"}`
}

func (k *Klipper) History() (int, []byte) {
	k.mu.Lock()
	h, at := k.hist, k.histAt
	k.mu.Unlock()
	if at.IsZero() || time.Since(at) > time.Minute {
		k.histNext = time.Time{} // relu au prochain passage
	}
	if len(h) == 0 {
		return 503, []byte(`{"error":"historique en cours de lecture"}`)
	}
	return 200, h
}

func (k *Klipper) Thumb() []byte {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.s.Thumb == "" || k.thumbFor != k.s.ThumbID {
		return nil
	}
	return k.thumbBuf
}

func (k *Klipper) CamURLs() (stream, snap string) { return k.camStream, k.camSnap }

// H264URLs : adresses RTSP H.264 à essayer pour la webcam (vide : MJPEG seulement).
func (k *Klipper) H264URLs() []string { return k.camH264 }

func (k *Klipper) Snapshot() PState {
	k.mu.Lock()
	defer k.mu.Unlock()
	s := k.s
	s.ExNames = append([]string(nil), k.s.ExNames...)
	return s
}

func (k *Klipper) HistAt() time.Time {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.histAt
}

// webcamURLs : flux MJPEG et instantané d'une webcam déclarée dans Moonraker, quel que soit son
// service (1.3.0) : mjpg-streamer / ustreamer / crowsnest, camera-streamer (WebRTC + MJPEG),
// go2rtc, uv4l, ou une simple adresse d'image. Les flux sans MJPEG (HLS, WebRTC seul, iframe)
// passent par les instantanés.
func webcamURLs(service, stream, snap string) (string, string) {
	sv := strings.ToLower(service)
	switch {
	case strings.Contains(sv, "camerastreamer") || strings.HasSuffix(strings.TrimRight(stream, "/"), "/webrtc"):
		// camera-streamer : /webrtc → /stream (MJPEG) et /snapshot
		b := strings.TrimSuffix(strings.TrimRight(stream, "/"), "/webrtc")
		if b == "" {
			b = strings.TrimSuffix(snap, "/snapshot")
		}
		if snap == "" {
			snap = b + "/snapshot"
		}
		stream = b + "/stream"
	case strings.Contains(sv, "go2rtc") || strings.Contains(stream, "stream.html?src="):
		// go2rtc : …/stream.html?src=X → …/api/stream.mjpeg?src=X et …/api/frame.jpeg?src=X
		if i := strings.Index(stream, "stream.html?src="); i >= 0 {
			base, src := stream[:i], stream[i+len("stream.html?src="):]
			stream = base + "api/stream.mjpeg?src=" + src
			if snap == "" {
				snap = base + "api/frame.jpeg?src=" + src
			}
		}
	case strings.Contains(sv, "hls") || strings.Contains(sv, "mediamtx") || strings.Contains(sv, "iframe") ||
		strings.HasSuffix(stream, ".m3u8"):
		stream = "" // pas de MJPEG : instantanés seulement
	}
	if snap == "" && strings.Contains(stream, "action=stream") {
		snap = strings.Replace(stream, "action=stream", "action=snapshot", 1)
	}
	if stream == "" && strings.Contains(snap, "action=snapshot") {
		stream = strings.Replace(snap, "action=snapshot", "action=stream", 1)
	}
	return snap, stream
}

// Source : lecteur d'une imprimante suivie (Klipper).
type Source interface {
	run(stop <-chan struct{})
	reload()
	Snapshot() PState
	Cancel() (int, string)
	Pause(action string) (int, string)
	Exclude(name string) (int, string)
	History() (int, []byte)
	Thumb() []byte
	CamURLs() (string, string)
	H264URLs() []string
}

func logPrintf(f string, a ...any) { log.Printf(f, a...) }
