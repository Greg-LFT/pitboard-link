package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func rtp(seq uint16, ts uint32, marque bool, charge []byte) []byte {
	p := make([]byte, 12, 12+len(charge))
	p[0] = 0x80
	p[1] = 96
	if marque {
		p[1] |= 0x80
	}
	binary.BigEndian.PutUint16(p[2:], seq)
	binary.BigEndian.PutUint32(p[4:], ts)
	return append(p, charge...)
}

func entrelace(canal byte, b []byte) []byte {
	h := []byte{'$', canal, 0, 0}
	binary.BigEndian.PutUint16(h[2:], uint16(len(b)))
	return append(h, b...)
}

// fauxServeurRTSP : DESCRIBE avec Digest, SETUP, PLAY, puis une image clé (STAP-A SPS/PPS + IDR en
// FU-A sur 3 paquets) et une image P, avec un paquet RTCP au milieu.
func fauxServeurRTSP(t *testing.T, sps, pps, idr, pimg []byte) (string, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		nonce := "abc123"
		for {
			var req []string
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				l = strings.TrimRight(l, "\r\n")
				if l == "" {
					break
				}
				req = append(req, l)
			}
			if len(req) == 0 {
				continue
			}
			methode := strings.Fields(req[0])[0]
			uri := strings.Fields(req[0])[1]
			cseq, auth := "", ""
			for _, h := range req[1:] {
				if strings.HasPrefix(h, "CSeq:") {
					cseq = strings.TrimSpace(h[5:])
				}
				if strings.HasPrefix(h, "Authorization:") {
					auth = strings.TrimSpace(h[14:])
				}
			}
			m := func(s string) string { h := md5.Sum([]byte(s)); return hex.EncodeToString(h[:]) }
			attendu := m(m("bblp:LIVE:code1234") + ":" + nonce + ":" + m(methode+":"+uri))
			if !strings.Contains(auth, `response="`+attendu+`"`) {
				fmt.Fprintf(c, "RTSP/1.0 401 Unauthorized\r\nCSeq: %s\r\nWWW-Authenticate: Basic realm=\"LIVE\"\r\nWWW-Authenticate: Digest realm=\"LIVE\", nonce=\"%s\"\r\n\r\n", cseq, nonce)
				continue
			}
			switch methode {
			case "DESCRIBE":
				sdp := "v=0\r\nm=audio 0 RTP/AVP 0\r\na=control:trackID=9\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n" +
					"a=fmtp:96 packetization-mode=1;sprop-parameter-sets=" + base64.StdEncoding.EncodeToString(sps) + "," + base64.StdEncoding.EncodeToString(pps) + "\r\n" +
					"a=control:trackID=0\r\n"
				fmt.Fprintf(c, "RTSP/1.0 200 OK\r\nCSeq: %s\r\nContent-Base: %s/\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", cseq, uri, len(sdp), sdp)
			case "SETUP":
				if !strings.HasSuffix(uri, "/trackID=0") {
					fmt.Fprintf(c, "RTSP/1.0 404 Not Found\r\nCSeq: %s\r\n\r\n", cseq)
					return
				}
				fmt.Fprintf(c, "RTSP/1.0 200 OK\r\nCSeq: %s\r\nSession: 42;timeout=60\r\nTransport: RTP/AVP/TCP;interleaved=0-1\r\n\r\n", cseq)
			case "PLAY":
				fmt.Fprintf(c, "RTSP/1.0 200 OK\r\nCSeq: %s\r\nSession: 42\r\n\r\n", cseq)
				var w bytes.Buffer
				stap := []byte{24}
				for _, n := range [][]byte{sps, pps} {
					stap = binary.BigEndian.AppendUint16(stap, uint16(len(n)))
					stap = append(stap, n...)
				}
				w.Write(entrelace(0, rtp(1, 1000, false, stap)))
				// IDR en FU-A, 3 fragments
				corps := idr[1:]
				tiers := len(corps) / 3
				for i := 0; i < 3; i++ {
					deb, fin := i*tiers, (i+1)*tiers
					if i == 2 {
						fin = len(corps)
					}
					fh := idr[0]&0x1F | 0
					if i == 0 {
						fh |= 0x80
					}
					if i == 2 {
						fh |= 0x40
					}
					w.Write(entrelace(0, rtp(uint16(2+i), 1000, i == 2, append([]byte{(idr[0] & 0xE0) | 28, fh}, corps[deb:fin]...))))
					if i == 0 {
						w.Write(entrelace(1, []byte{0x80, 200, 0, 6, 1, 2, 3, 4})) // RTCP ignoré
					}
				}
				w.Write(entrelace(0, rtp(5, 4000, true, pimg)))
				c.Write(w.Bytes())
				io.Copy(io.Discard, r)
				return
			}
		}
	}()
	return "rtsp://bblp:code1234@" + ln.Addr().String() + "/streaming/live/1", func() { ln.Close() }
}

func TestRTSPH264(t *testing.T) {
	sps := []byte{0x67, 0x42, 0x00, 0x1f, 0xaa}
	pps := []byte{0x68, 0xce, 0x3c, 0x80}
	idr := append([]byte{0x65}, bytes.Repeat([]byte{0x11, 0x22, 0x33}, 700)...)
	pimg := []byte{0x41, 0x9a, 0x01, 0x02}
	adr, fin := fauxServeurRTSP(t, sps, pps, idr, pimg)
	defer fin()
	rc, err := rtspOuvrir(adr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Fermer()
	var aus []AU
	rc.Lire(func() bool { return len(aus) < 2 }, func(a AU) { aus = append(aus, a) })
	if len(aus) != 2 {
		t.Fatalf("%d images", len(aus))
	}
	if !aus[0].Cle || aus[1].Cle {
		t.Fatalf("images clés : %v %v", aus[0].Cle, aus[1].Cle)
	}
	attendu := bytes.Join([][]byte{nil, sps, pps, idr}, debutAnnexB)
	if !bytes.Equal(aus[0].Data, attendu) {
		t.Fatalf("image clé : %d octets au lieu de %d", len(aus[0].Data), len(attendu))
	}
	if !bytes.Equal(aus[1].Data, append(append([]byte{}, debutAnnexB...), pimg...)) {
		t.Fatalf("image P incorrecte")
	}
}

func TestH264Candidats(t *testing.T) {
	l := h264Candidats("webrtc-camerastreamer", "http://192.168.0.50/webcam/webrtc", "")
	if len(l) != 1 || l[0] != "rtsp://192.168.0.50:8554/stream.h264" {
		t.Fatalf("camera-streamer : %v", l)
	}
	l = h264Candidats("go2rtc", "http://192.168.0.51:1984/stream.html?src=cam1", "")
	if len(l) != 1 || l[0] != "rtsp://192.168.0.51:8554/cam1" {
		t.Fatalf("go2rtc : %v", l)
	}
	if l := h264Candidats("mjpegstreamer", "http://192.168.0.33/webcam/?action=stream", ""); len(l) != 0 {
		t.Fatalf("mjpeg : %v", l)
	}
}

func TestH264HubGOP(t *testing.T) {
	h := newH264Hub(func() []string { return nil })
	h.publier(AU{Data: []byte{1}, Cle: false}) // avant la première image clé : ignorée
	h.publier(AU{Data: []byte{2}, Cle: true})
	h.publier(AU{Data: []byte{3}})
	if len(h.gop) != 2 || h.gop[0].Data[0] != 2 {
		t.Fatalf("gop : %v", h.gop)
	}
	h.publier(AU{Data: []byte{4}, Cle: true})
	if len(h.gop) != 1 || h.gop[0].Data[0] != 4 {
		t.Fatalf("gop après image clé : %v", h.gop)
	}
}

func TestH264HubRTSP(t *testing.T) {
	sps := []byte{0x67, 0x42, 0x00, 0x1f}
	pps := []byte{0x68, 0xce}
	idr := append([]byte{0x65}, bytes.Repeat([]byte{7}, 3000)...)
	adr, fin := fauxServeurRTSP(t, sps, pps, idr, []byte{0x41, 1, 2})
	defer fin()
	h := newH264Hub(func() []string { return []string{"rtsp://127.0.0.1:1/rien", adr} })
	if !h.Attendre(5 * time.Second) {
		t.Fatal("pas d'image clé")
	}
	stop := make(chan struct{})
	var recu []AU
	go func() { time.Sleep(500 * time.Millisecond); close(stop) }()
	h.Suivre(stop, func(a AU) error { recu = append(recu, a); return nil })
	if len(recu) < 1 || !recu[0].Cle {
		t.Fatalf("reçu %d images, première clé : %v", len(recu), len(recu) > 0 && recu[0].Cle)
	}
}
