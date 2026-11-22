package main

// Caméra : un seul abonnement au flux MJPEG de la webcam (ustreamer, mjpg-streamer…),
// ouvert seulement tant que quelqu'un regarde, et partagé entre tous les clients.
// On garde toujours la dernière image : une image en retard n'est jamais mise en file.
// Aucun réencodage : les JPEG sont recopiés tels que la webcam les produit.

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type CamHub struct {
	urls func() (stream, snap string)

	mu        sync.Mutex
	frame     []byte
	seq       uint64
	at        time.Time
	wantUntil time.Time
	running   bool
	notify    chan struct{} // fermé à chaque nouvelle image
	lastErr   string
}

func newCamHub(urls func() (string, string)) *CamHub {
	return &CamHub{urls: urls, notify: make(chan struct{})}
}

// Want : quelqu'un regarde pendant au moins d. Démarre la lecture si besoin.
func (c *CamHub) Want(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if u := time.Now().Add(d); u.After(c.wantUntil) {
		c.wantUntil = u
	}
	if !c.running {
		c.running = true
		go c.loop()
	}
}

func (c *CamHub) wanted() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Before(c.wantUntil)
}

func (c *CamHub) publish(jpg []byte) {
	c.mu.Lock()
	c.frame = jpg
	c.seq++
	c.at = time.Now()
	old := c.notify
	c.notify = make(chan struct{})
	c.mu.Unlock()
	close(old)
}

// Latest : dernière image connue (nil si aucune), son numéro et son âge.
func (c *CamHub) Latest() ([]byte, uint64, time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.frame == nil {
		return nil, 0, 0
	}
	return c.frame, c.seq, time.Since(c.at)
}

// Next : première image de numéro > after, en attendant au plus timeout.
// Une image de plus de 10 s n'est pas servie comme « nouvelle » à after=0.
func (c *CamHub) Next(ctx context.Context, after uint64, timeout time.Duration) ([]byte, uint64, error) {
	c.Want(timeout + 10*time.Second)
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		c.mu.Lock()
		f, s, at, ch := c.frame, c.seq, c.at, c.notify
		c.mu.Unlock()
		if f != nil && s > after && (after > 0 || time.Since(at) < 10*time.Second) {
			return f, s, nil
		}
		select {
		case <-ch:
		case <-deadline.C:
			return nil, 0, errors.New("aucune image")
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		}
	}
}

func (c *CamHub) Seq() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.seq
}

func (c *CamHub) loop() {
	defer func() {
		c.mu.Lock()
		c.running = false
		c.mu.Unlock()
	}()
	fails := 0
	for c.wanted() {
		stream, snap := c.urls()
		var err error
		switch {
		case stream != "":
			err = c.readStream(stream)
			if err != nil && snap != "" && fails >= 2 {
				err = c.pollSnapshots(snap)
			}
		case snap != "":
			err = c.pollSnapshots(snap)
		default:
			err = errors.New("aucune webcam déclarée")
		}
		if err != nil {
			fails++
			c.mu.Lock()
			// 1.5.1 : pas de message au premier essai (au démarrage, la webcam n'est pas encore lue
			// dans Moonraker) ; seulement si l'échec dure.
			if c.lastErr != err.Error() && fails >= 3 {
				log.Printf("caméra : %v", err)
				c.lastErr = err.Error()
			}
			c.mu.Unlock()
			time.Sleep(time.Duration(min(fails, 5)) * time.Second)
		} else {
			fails = 0
		}
	}
}

var camClient = &http.Client{Timeout: 0} // flux continu : délai géré à la main

func (c *CamHub) readStream(u string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return err
	}
	resp, err := camClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New("flux webcam : HTTP " + strconv.Itoa(resp.StatusCode))
	}
	// Coupure si plus aucune image n'arrive pendant 8 s, ou si plus personne ne regarde.
	alive := make(chan struct{}, 1)
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		last := time.Now()
		for {
			select {
			case <-ctx.Done():
				return
			case <-alive:
				last = time.Now()
			case <-t.C:
				if time.Since(last) > 8*time.Second || !c.wanted() {
					cancel()
					return
				}
			}
		}
	}()
	_, params, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	boundary := strings.TrimPrefix(params["boundary"], "--")
	// 1.0.2 : lecture rapide quand chaque image annonce sa longueur (ustreamer, mjpg-streamer) :
	// une seule allocation par image, sans recherche de la frontière dans les données.
	br := bufio.NewReaderSize(resp.Body, 64<<10)
	if boundary != "" {
		for c.wanted() {
			n := -1
			for {
				line, err := br.ReadSlice('\n')
				if err != nil {
					if ctx.Err() != nil && !c.wanted() {
						return nil
					}
					return err
				}
				l := strings.TrimSpace(string(line))
				if l == "" {
					if n >= 0 {
						break
					}
					continue
				}
				if k, v, ok := strings.Cut(l, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "Content-Length") {
					n, _ = strconv.Atoi(strings.TrimSpace(v))
				}
			}
			if n <= 0 || n > 4<<20 {
				return errors.New("flux webcam : longueur d'image invalide")
			}
			b := make([]byte, n)
			if _, err := io.ReadFull(br, b); err != nil {
				return err
			}
			if len(b) > 2 && b[0] == 0xFF && b[1] == 0xD8 {
				c.publish(b)
				select {
				case alive <- struct{}{}:
				default:
				}
			}
		}
		return nil
	}
	// Sans frontière annoncée : découpe sur les marqueurs JPEG (SOI … EOI).
	var buf bytes.Buffer
	in := false
	var prev byte
	for c.wanted() {
		b, err := br.ReadByte()
		if err != nil {
			return err
		}
		if !in {
			if prev == 0xFF && b == 0xD8 {
				in = true
				buf.Reset()
				buf.WriteByte(0xFF)
				buf.WriteByte(0xD8)
			}
		} else {
			buf.WriteByte(b)
			if prev == 0xFF && b == 0xD9 {
				c.publish(append([]byte(nil), buf.Bytes()...))
				in = false
				select {
				case alive <- struct{}{}:
				default:
				}
			} else if buf.Len() > 4<<20 {
				in = false
			}
		}
		prev = b
	}
	return nil
}

var snapClient = &http.Client{Timeout: 6 * time.Second}

func (c *CamHub) pollSnapshots(u string) error {
	for c.wanted() {
		t0 := time.Now()
		resp, err := snapClient.Get(u)
		if err != nil {
			return err
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if err != nil {
			return err
		}
		if resp.StatusCode != 200 || len(b) < 3 || b[0] != 0xFF || b[1] != 0xD8 {
			return errors.New("instantané webcam : HTTP " + strconv.Itoa(resp.StatusCode))
		}
		c.publish(b)
		if d := 200*time.Millisecond - time.Since(t0); d > 0 {
			time.Sleep(d)
		}
	}
	return nil
}
