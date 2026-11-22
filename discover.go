package main

// 1.3.0 : recherche des imprimantes sur le réseau, pour l'écran « Imprimantes » de l'app
// (mêmes réponses qu'un PitBoard S3) : /api/klscan, balayage du réseau local sur le port 7125 (Moonraker).
// 1.3.1 : plus d'écoute des Bambu Lab ; elles se suivent avec un PitBoard S3.

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"time"
)

type trouvee struct {
	IP     string `json:"ip"`
	Name   string `json:"name"`
	Locked bool   `json:"locked,omitempty"`
}

type Decouverte struct {
	mu     sync.Mutex
	kl     []trouvee
	klRun  bool
	klProg int
}

// KlScan : démarre (start) puis rend l'avancement du balayage Klipper.
func (d *Decouverte) KlScan(start bool) []byte {
	d.mu.Lock()
	if start && !d.klRun {
		d.klRun, d.klProg, d.kl = true, 0, nil
		go d.balayer()
	}
	j, _ := json.Marshal(map[string]any{"running": d.klRun, "progress": d.klProg, "found": append([]trouvee{}, d.kl...)})
	d.mu.Unlock()
	return j
}

func (d *Decouverte) balayer() {
	defer func() {
		d.mu.Lock()
		d.klRun, d.klProg = false, 100
		d.mu.Unlock()
	}()
	ip := net.ParseIP(lanIP()).To4()
	if ip == nil {
		return
	}
	cli := &http.Client{Timeout: 1500 * time.Millisecond}
	sem := make(chan struct{}, 32)
	var wg sync.WaitGroup
	var fait int
	for h := 1; h < 255; h++ {
		cible := net.IPv4(ip[0], ip[1], ip[2], byte(h)).String()
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+cible+":7125/printer/info", nil)
			r, err := cli.Do(req)
			if err == nil {
				var j map[string]any
				json.NewDecoder(http.MaxBytesReader(nil, r.Body, 64<<10)).Decode(&j)
				r.Body.Close()
				res, _ := j["result"].(map[string]any)
				if r.StatusCode == 200 && res != nil || r.StatusCode == 401 || r.StatusCode == 403 {
					nom, _ := res["hostname"].(string)
					if nom == "" {
						nom = "Klipper"
					}
					d.mu.Lock()
					d.kl = append(d.kl, trouvee{IP: cible, Name: nom, Locked: r.StatusCode != 200})
					d.mu.Unlock()
				}
			}
			d.mu.Lock()
			fait++
			d.klProg = fait * 100 / 254
			d.mu.Unlock()
		}()
	}
	wg.Wait()
}
