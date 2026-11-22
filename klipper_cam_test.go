package main

import "testing"

func TestWebcamURLs(t *testing.T) {
	cas := []struct{ sv, st, sn, wSn, wSt string }{
		{"mjpegstreamer-adaptive", "/webcam/?action=stream", "", "/webcam/?action=snapshot", "/webcam/?action=stream"},
		{"webrtc-camerastreamer", "/webcam/webrtc", "", "/webcam/snapshot", "/webcam/stream"},
		{"webrtc-go2rtc", "http://h:1984/stream.html?src=cam", "", "http://h:1984/api/frame.jpeg?src=cam", "http://h:1984/api/stream.mjpeg?src=cam"},
		{"hlsstream", "/cam/index.m3u8", "/cam/snap.jpg", "/cam/snap.jpg", ""},
		{"", "", "/webcam/?action=snapshot", "/webcam/?action=snapshot", "/webcam/?action=stream"},
	}
	for _, c := range cas {
		sn, st := webcamURLs(c.sv, c.st, c.sn)
		if sn != c.wSn || st != c.wSt {
			t.Errorf("%s : %q %q", c.sv, sn, st)
		}
	}
}
