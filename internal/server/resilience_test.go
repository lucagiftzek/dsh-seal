package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// A hard reload bypasses the service worker: the shell request carries
// no-cache. A browser that already has the seal client then gets the bootstrap
// page (so no DSH asset loads plain), except on the reload boot.js asked for
// (cookie sealhr), which gets the real shell even with no-cache.
func TestHardReloadGetsBootstrap(t *testing.T) {
	e := newEnv(t, ModeOffer)
	shell := func(mut func(h http.Header)) string {
		h := hdr(alice)
		mut(h)
		resp := e.get("/", h)
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	isBoot := func(s string) bool {
		return strings.Contains(s, "dsh-seal-bootstrap") && !strings.Contains(s, "mock dsh")
	}
	// normal load and normal reload (max-age=0): the real shell
	if s := shell(func(h http.Header) {}); isBoot(s) {
		t.Fatal("normal load got the bootstrap page")
	}
	if s := shell(func(h http.Header) { h.Set("Cache-Control", "max-age=0") }); isBoot(s) {
		t.Fatal("normal reload got the bootstrap page")
	}
	// hard reloads of Chrome/Firefox (Pragma + Cache-Control) and Safari
	if s := shell(func(h http.Header) { h.Set("Pragma", "no-cache"); h.Set("Cache-Control", "no-cache") }); !isBoot(s) {
		t.Fatalf("hard reload got the shell: %.120s", s)
	}
	if s := shell(func(h http.Header) { h.Set("Cache-Control", "no-cache") }); !isBoot(s) {
		t.Fatal("hard reload (Cache-Control only) got the shell")
	}
	// the reload boot.js asked for: real shell, even with no-cache (DevTools "Disable cache")
	if s := shell(func(h http.Header) {
		h.Set("Pragma", "no-cache")
		h.Set("Cookie", "dsh-auth-x=secretcookie; sealboot=1; sealhr=1")
	}); isBoot(s) {
		t.Fatal("the guarded reload got the bootstrap page again (loop)")
	}
	if e.seal.M.HardReload.Load() != 2 {
		t.Fatalf("hard_reload_bootstrap %d", e.seal.M.HardReload.Load())
	}
	// identities that are not sealed are untouched by a hard reload
	h := hdr(bob)
	h.Set("Pragma", "no-cache")
	resp := e.get("/", h)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if bytes.Contains(b, []byte("/_s/")) {
		t.Fatal("non-eligible identity injected on a hard reload")
	}
	// the marker cookies never reach DSH
	h = hdr(alice)
	h.Set("Cookie", "dsh-auth-x=secretcookie; sealboot=1; sealhr=1")
	resp = e.get("/api/echo", h)
	j := readJSON(t, resp.Body)
	resp.Body.Close()
	if c, _ := j["headers"].(map[string]any)["Cookie"].(string); strings.Contains(c, "seal") || !strings.Contains(c, "dsh-auth-x") {
		t.Fatalf("cookie upstream: %q", c)
	}
}

// The network probe answers 204 in every mode, for anyone, with nothing in it.
func TestProbe(t *testing.T) {
	for _, mode := range []string{ModeOffer, ModePassthrough} {
		e := newEnv(t, mode)
		resp := e.get("/_s/p?t=1", http.Header{})
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent || len(b) != 0 || resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: probe %d %q", mode, resp.StatusCode, b)
		}
		if e.seal.M.Probes.Load() != 1 {
			t.Fatalf("%s: probes %d", mode, e.seal.M.Probes.Load())
		}
	}
}

// The server pings an idle mux (Cloudflare closes proxied sockets idle for
// about 100 s) and accepts the client's pong; the session survives a dropped
// mux, so a reconnect needs no handshake.
func TestMuxServerPingAndReconnect(t *testing.T) {
	old := muxPingEvery.Load()
	muxPingEvery.Store(int64(150 * time.Millisecond))
	defer muxPingEvery.Store(old)
	e := newEnv(t, ModeOffer)
	s := e.session(alice)
	m, err := s.DialMux(context.Background(), e.addr)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan byte, 4)
	go func() {
		for {
			f, err := m.Recv()
			if err != nil {
				close(got)
				return
			}
			if f.Chan == 0 {
				got <- f.Type
				if f.Type == MPing {
					m.Send(MPong, 0, f.Payload)
				}
			}
		}
	}()
	for i := 0; i < 2; i++ {
		select {
		case typ := <-got:
			if typ != MPing {
				t.Fatalf("frame %x on channel 0", typ)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("no server ping")
		}
	}
	// the outer socket drops (laptop sleep): the same session dials a new mux
	m.Close()
	m2, err := s.DialMux(context.Background(), e.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer m2.Close()
	m2.Send(MPing, 0, binary.BigEndian.AppendUint64(nil, 7))
	for {
		f, err := m2.Recv()
		if err != nil {
			t.Fatalf("reconnect with the same session failed: %v", err)
		}
		if f.Type == MPong {
			break
		}
	}
	if e.seal.M.Handshakes.Load() != 1 || e.seal.M.MuxConns.Load() != 2 || e.seal.M.MuxPings.Load() < 2 {
		t.Fatalf("handshakes %d mux %d pings %d", e.seal.M.Handshakes.Load(), e.seal.M.MuxConns.Load(), e.seal.M.MuxPings.Load())
	}
}
