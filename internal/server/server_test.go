package server

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dsh-seal/internal/keystore"
	"dsh-seal/internal/mock"
	"dsh-seal/internal/sealclient"
	sc "dsh-seal/internal/sealcrypto"
	"dsh-seal/internal/wsproto"
)

const alice = "alice@example.com"
const bob = "bob@example.org"

type env struct {
	t     *testing.T
	seal  *Server
	base  string
	addr  string
	upURL string
	c     *http.Client
}

func newEnv(t *testing.T, mode string, mutate ...func(*Config)) *env {
	t.Helper()
	up := httptest.NewServer(mock.Handler())
	t.Cleanup(up.Close)
	cfg := Defaults()
	cfg.Identities = []string{alice}
	cfg.Mode = mode
	cfg.Upstream = strings.TrimPrefix(up.URL, "http://")
	cfg.StateDir = t.TempDir()
	for _, m := range mutate {
		m(&cfg)
	}
	keys, err := keystore.Open(cfg.StateDir, cfg.KXRotate)
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg, keys, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)
	tr := &http.Transport{DisableCompression: true}
	t.Cleanup(tr.CloseIdleConnections)
	return &env{t: t, seal: s, base: ts.URL, addr: strings.TrimPrefix(ts.URL, "http://"), upURL: up.URL, c: &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func hdr(email string) http.Header {
	h := http.Header{}
	if email != "" {
		h.Set("X-Auth-Email", email)
	}
	h.Set("Cookie", "dsh-auth-x=secretcookie; sealboot=1")
	h.Set("Origin", "https://dsh.example.com")
	return h
}

func (e *env) get(path string, h http.Header) *http.Response {
	req, _ := http.NewRequest("GET", e.base+path, nil)
	if h != nil {
		req.Header = h.Clone()
	}
	resp, err := e.c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	return resp
}

func (e *env) session(email string) *sealclient.Session {
	e.t.Helper()
	ctx := context.Background()
	b, err := sealclient.Bundle(ctx, e.c, e.base, hdr(email))
	if err != nil {
		e.t.Fatal(err)
	}
	s, _, err := sealclient.Handshake(ctx, e.c, e.base, hdr(email), b, "")
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

func readJSON(t *testing.T, r io.Reader) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.NewDecoder(r).Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

// Injection ---------------------------------------------------------------------------

func TestInjectBoot(t *testing.T) {
	tag := []byte("<script src=\"/_s/boot.js\"></script>")
	cases := []struct{ in, want string }{
		{"<!doctype html><html><head><title>x</title></head></html>", "<!doctype html><html><head><script src=\"/_s/boot.js\"></script><title>x</title></head></html>"},
		{"<HTML><HEAD lang=en><TITLE>x</TITLE></HEAD></HTML>", "<HTML><HEAD lang=en><script src=\"/_s/boot.js\"></script><TITLE>x</TITLE></HEAD></HTML>"},
		{"\xEF\xBB\xBF<html><head></head></html>", "\xEF\xBB\xBF<html><head><script src=\"/_s/boot.js\"></script></head></html>"},
		{"<html><body><header>h</header></body></html>", "<html><head><script src=\"/_s/boot.js\"></script></head><body><header>h</header></body></html>"},
		{"<!doctype html><p>no html</p>", "<!doctype html><script src=\"/_s/boot.js\"></script><p>no html</p>"},
		{"<p>bare</p>", "<script src=\"/_s/boot.js\"></script><p>bare</p>"},
		{"<html><!-- <head> in a comment --><head><b></b></head></html>", "<html><!-- <head> in a comment --><head><script src=\"/_s/boot.js\"></script><b></b></head></html>"},
		{"<html><head\n data-x=1><title>t</title></head></html>", "<html><head\n data-x=1><script src=\"/_s/boot.js\"></script><title>t</title></head></html>"},
	}
	for i, c := range cases {
		if got := string(InjectBoot([]byte(c.in), tag)); got != c.want {
			t.Errorf("case %d:\n got %q\nwant %q", i, got, c.want)
		}
	}
}

func TestShellInjection(t *testing.T) {
	e := newEnv(t, ModeOffer)
	// gzip client: injected, recompressed, ETag dropped, no-store.
	h := hdr(alice)
	h.Set("Accept-Encoding", "gzip, br")
	resp := e.get("/", h)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("expected gzip, got %q", resp.Header.Get("Content-Encoding"))
	}
	zr, _ := gzip.NewReader(bytes.NewReader(body))
	html, _ := io.ReadAll(zr)
	if !bytes.Contains(html, []byte("<head><meta http-equiv=\"x-dns-prefetch-control\" content=\"off\"><script src=\"/_s/boot.js?v=")) {
		t.Fatalf("boot tag not first in head: %.200s", html)
	}
	if resp.Header.Get("ETag") != "" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("cache headers: etag=%q cc=%q", resp.Header.Get("ETag"), resp.Header.Get("Cache-Control"))
	}
	// identity client
	resp = e.get("/", hdr(alice))
	html, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.Header.Get("Content-Encoding") != "" || !bytes.Contains(html, []byte("/_s/boot.js")) || resp.ContentLength != int64(len(html)) {
		t.Fatalf("identity injection failed: ce=%q cl=%d len=%d", resp.Header.Get("Content-Encoding"), resp.ContentLength, len(html))
	}
	// first visit (no seal cookie): the bootstrap page, no DSH code in plain
	bh := hdr(alice)
	bh.Set("Cookie", "dsh-auth-x=secretcookie")
	resp = e.get("/", bh)
	html, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Contains(html, []byte("dsh-seal-bootstrap")) || bytes.Contains(html, []byte("mock dsh")) || !bytes.Contains(html, []byte("/_s/boot.js")) {
		t.Fatalf("bootstrap page: %s", html)
	}
	// not eligible (bob): untouched, ETag kept
	resp = e.get("/", hdr(bob))
	html, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if bytes.Contains(html, []byte("/_s/")) || resp.Header.Get("ETag") != `"shell-1"` {
		t.Fatal("non-eligible identity must pass through untouched")
	}
	// reports are never injected
	resp = e.get("/report/x.html", hdr(alice))
	html, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if bytes.Contains(html, []byte("/_s/")) {
		t.Fatal("report page was injected")
	}
	if e.seal.M.Injected.Load() != 3 || e.seal.M.Bootstrapped.Load() != 1 {
		t.Fatalf("injected counter %d", e.seal.M.Injected.Load())
	}
}

// Pass-through fidelity -----------------------------------------------------------------

func TestPassthroughFidelity(t *testing.T) {
	e := newEnv(t, ModePassthrough)
	h := hdr(bob)
	h.Set("X-Forwarded-For", "203.0.113.9")
	h.Set("X-Forwarded-Proto", "https")
	h.Set("X-Auth-User", "bob")
	resp := e.get("/api/echo?a=1&b=%20x", h)
	m := readJSON(t, resp.Body)
	resp.Body.Close()
	hs := m["headers"].(map[string]any)
	if hs["X-Auth-Email"] != bob || hs["X-Auth-User"] != "bob" || hs["X-Forwarded-For"] != "203.0.113.9" || hs["X-Forwarded-Proto"] != "https" || hs["Cookie"] != "dsh-auth-x=secretcookie" {
		t.Fatalf("headers changed: %v", hs)
	}
	if m["query"] != "a=1&b=%20x" || resp.Header.Get("X-Mock") != "echo" {
		t.Fatalf("query or response header changed: %v", m["query"])
	}
	// X-Forwarded-For added only when absent
	resp = e.get("/api/echo", hdr(alice))
	m = readJSON(t, resp.Body)
	resp.Body.Close()
	if m["headers"].(map[string]any)["X-Forwarded-For"] != "127.0.0.1" {
		t.Fatalf("xff: %v", m["headers"])
	}
	// shell untouched in passthrough
	resp = e.get("/", hdr(alice))
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != mock.Shell {
		t.Fatal("passthrough changed the shell")
	}
	// gzip passes through compressed
	gh := hdr(alice)
	gh.Set("Accept-Encoding", "gzip")
	resp = e.get("/api/gzip", gh)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatal("gzip encoding lost")
	}
}

func TestPassthroughSSEStreams(t *testing.T) {
	e := newEnv(t, ModePassthrough)
	start := time.Now()
	resp := e.get("/api/sse?n=3&ms=300", hdr(alice))
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(line, "data: tick 0") {
			break
		}
	}
	if d := time.Since(start); d > 250*time.Millisecond {
		t.Fatalf("first event took %v: the proxy buffers", d)
	}
}

func TestPassthroughLargeUploads(t *testing.T) {
	e := newEnv(t, ModePassthrough)
	data := make([]byte, 50<<20)
	rand.Read(data)
	sum := sha256.Sum256(data)
	req, _ := http.NewRequest("POST", e.base+"/api/echo", bytes.NewReader(data))
	req.Header = hdr(alice)
	resp, err := e.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	m := readJSON(t, resp.Body)
	resp.Body.Close()
	if m["sha256"] != hex.EncodeToString(sum[:]) || m["contentLength"].(float64) != float64(len(data)) {
		t.Fatalf("50 MB upload mismatch: %v %v", m["len"], m["contentLength"])
	}
	// chunked upload (no Content-Length) streams through as chunked
	req, _ = http.NewRequest("POST", e.base+"/api/echo", io.MultiReader(bytes.NewReader(data[:1<<20])))
	req.Header = hdr(alice)
	req.ContentLength = -1
	resp, err = e.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	m = readJSON(t, resp.Body)
	resp.Body.Close()
	if m["len"].(float64) != 1<<20 || m["chunked"] != true {
		t.Fatalf("chunked upload: %v", m)
	}
	// big download streams back intact
	resp = e.get("/api/big?n=20000000", hdr(alice))
	n, _ := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if n != 20000000 {
		t.Fatalf("download length %d", n)
	}
}

func TestPassthroughWebSocketTunnel(t *testing.T) {
	e := newEnv(t, ModePassthrough)
	h := hdr(alice)
	h.Set("Host", e.addr)
	h.Set("Sec-WebSocket-Protocol", "proto-a, proto-b")
	ws, res, err := wsproto.Dial(context.Background(), e.addr, "/ws/echo?hello=1", h)
	if err != nil || ws == nil {
		t.Fatalf("dial: %v %+v", err, res)
	}
	defer ws.Close()
	if res.Protocol != "proto-a" {
		t.Fatalf("subprotocol %q", res.Protocol)
	}
	_, hello, _ := ws.ReadMessage()
	if !bytes.Contains(hello, []byte(alice)) {
		t.Fatalf("identity lost in tunnel: %s", hello)
	}
	big := bytes.Repeat([]byte("x"), 300000)
	ws.WriteMessage(wsproto.OpBinary, big)
	op, got, err := ws.ReadMessage()
	if err != nil || op != wsproto.OpBinary || !bytes.Equal(got, big) {
		t.Fatalf("echo through tunnel failed: %v", err)
	}
	if e.seal.M.WSTunnels.Load() != 1 {
		t.Fatal("tunnel not counted")
	}
}

// Sealed fetch -----------------------------------------------------------------------------

func TestSealedFetch(t *testing.T) {
	e := newEnv(t, ModeOffer)
	s := e.session(alice)
	ctx := context.Background()

	// GET with a query: path and query travel inside; identity from outside.
	r, err := s.Do(ctx, &sealclient.Request{Method: "GET", Path: "/api/echo?u=https%3A%2F%2Fsecret.example%2Fimg&q=private", Header: [][2]string{{"X-Test", "1"}, {"X-Auth-Email", "evil@example.com"}, {"Cookie", "forged=1"}, {"X-Forwarded-For", "6.6.6.6"}, {"Host", "evil"}}, Mode: "cors", Dest: "empty"})
	if err != nil || r.OuterStatus != 200 {
		t.Fatalf("sealed GET: %v %+v", err, r)
	}
	m := readJSON(t, r.Body)
	hs := m["headers"].(map[string]any)
	if m["query"] != "u=https%3A%2F%2Fsecret.example%2Fimg&q=private" || hs["X-Test"] != "1" {
		t.Fatalf("inner request: %v", m)
	}
	if hs["X-Auth-Email"] != alice || hs["Cookie"] != "dsh-auth-x=secretcookie" || hs["X-Forwarded-For"] == "6.6.6.6" || m["host"] != e.addr {
		t.Fatalf("protected headers leaked from the envelope: %v host=%v", hs, m["host"])
	}
	if hs["Sec-Fetch-Mode"] != "cors" || hs["Accept-Encoding"] != "gzip" {
		t.Fatalf("fetch metadata: %v", hs)
	}

	// POST with a 3 MB body
	data := make([]byte, 3<<20)
	rand.Read(data)
	sum := sha256.Sum256(data)
	r, _ = s.Do(ctx, &sealclient.Request{Method: "POST", Path: "/api/echo", Body: data, Header: [][2]string{{"Content-Type", "application/octet-stream"}}})
	m = readJSON(t, r.Body)
	if m["sha256"] != hex.EncodeToString(sum[:]) || m["contentLength"].(float64) != float64(len(data)) {
		t.Fatalf("sealed POST body mismatch")
	}
	if m["headers"].(map[string]any)["Origin"] != "https://dsh.example.com" {
		t.Fatal("POST must carry the outer Origin")
	}

	// gzip stays compressed inside the seal and is flagged
	r, _ = s.Do(ctx, &sealclient.Request{Method: "GET", Path: "/api/gzip"})
	if !r.Gzip || r.Header.Get("Content-Encoding") != "" {
		t.Fatalf("gzip flag: %v %v", r.Gzip, r.Header)
	}
	zr, err := gzip.NewReader(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if m = readJSON(t, zr); m["gzip"] != true {
		t.Fatal("gzip body")
	}

	// redirect is returned, not followed; cookies reach the outer response
	r, _ = s.Do(ctx, &sealclient.Request{Method: "GET", Path: "/api/redirect"})
	if r.Status != 302 || r.Header.Get("Location") != "/api/echo?from=redirect" {
		t.Fatalf("redirect: %d %v", r.Status, r.Header)
	}
	io.Copy(io.Discard, r.Body)
	r, _ = s.Do(ctx, &sealclient.Request{Method: "GET", Path: "/api/cookie"})
	if r.Status != 204 || !strings.Contains(r.OuterHeader.Get("Set-Cookie"), "mockc=v1") {
		t.Fatalf("cookie: %d %v", r.Status, r.OuterHeader)
	}
	io.Copy(io.Discard, r.Body)
	// HEAD and 304 carry no body
	r, _ = s.Do(ctx, &sealclient.Request{Method: "HEAD", Path: "/api/gzip"})
	if b, _ := io.ReadAll(r.Body); len(b) != 0 || r.Status != 200 {
		t.Fatalf("HEAD body %d", len(b))
	}
	r, _ = s.Do(ctx, &sealclient.Request{Method: "GET", Path: "/api/status?c=304"})
	if b, _ := io.ReadAll(r.Body); len(b) != 0 || r.Status != 304 {
		t.Fatal("304")
	}
	// big streaming download
	r, _ = s.Do(ctx, &sealclient.Request{Method: "GET", Path: "/api/big?n=5000000"})
	if n, err := io.Copy(io.Discard, r.Body); n != 5000000 || err != nil {
		t.Fatalf("big: %d %v", n, err)
	}
}

func TestSealedSSEStreams(t *testing.T) {
	e := newEnv(t, ModeOffer)
	s := e.session(alice)
	start := time.Now()
	r, err := s.Do(context.Background(), &sealclient.Request{Method: "GET", Path: "/api/sse?n=3&ms=300", Header: [][2]string{{"Accept", "text/event-stream"}}})
	if err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(r.Body)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(line, "data: tick 0") {
			break
		}
	}
	if d := time.Since(start); d > 250*time.Millisecond {
		t.Fatalf("sealed SSE buffered: first event after %v", d)
	}
	r.Body.Close()
}

func TestSealedRejections(t *testing.T) {
	e := newEnv(t, ModeOffer)
	s := e.session(alice)
	ctx := context.Background()
	env, stream := s.Envelope(&sealclient.Request{Method: "POST", Path: "/api/echo", Body: []byte("once")})
	r, _ := s.Post(ctx, env, stream)
	io.Copy(io.Discard, r.Body)
	if r.Status != 200 {
		t.Fatal("first post")
	}
	if r, _ = s.Post(ctx, env, stream); r.ErrorCode != "SEAL_REPLAY" || r.OuterStatus != 403 {
		t.Fatalf("replay accepted: %+v", r)
	}
	// corrupted frame
	if r, _ = s.Do(ctx, &sealclient.Request{Method: "GET", Path: "/api/echo", Corrupt: true}); r.ErrorCode != "SEAL_FRAME_AUTH" {
		t.Fatalf("corrupt: %+v", r)
	}
	// another identity cannot use this session
	s2 := s.Clone()
	s2.Header = hdr("someone@else.example")
	if r, _ = s2.Do(ctx, &sealclient.Request{Method: "GET", Path: "/api/echo"}); r.OuterStatus != 403 {
		t.Fatalf("identity mismatch: %+v", r)
	}
	// unknown session
	s3 := s.Clone()
	s3.SID = make([]byte, 16)
	if r, _ = s3.Do(ctx, &sealclient.Request{Method: "GET", Path: "/api/echo"}); r.ErrorCode != "SEAL_UNKNOWN_SESSION" || r.OuterStatus != 401 {
		t.Fatalf("unknown session: %+v", r)
	}
	// stream ids far behind the window are refused
	s.SetNext(10000)
	r, _ = s.Do(ctx, &sealclient.Request{Method: "GET", Path: "/api/echo"})
	io.Copy(io.Discard, r.Body)
	if r, _ = s.Do(ctx, &sealclient.Request{Method: "GET", Path: "/api/echo", Stream: 3}); r.ErrorCode != "SEAL_REPLAY" {
		t.Fatalf("old stream id: %+v", r)
	}
	// the envelope may not target /_s/ itself or a scheme relative URL
	// (absolute http(s) URLs are sealed egress, tested in egress_test.go)
	for _, p := range []string{"/_s/h", "//evil.example/x", "javascript:alert(1)", "file:///etc/passwd"} {
		if r, _ = s.Do(ctx, &sealclient.Request{Method: "GET", Path: p}); r.ErrorCode != "SEAL_BAD_REQUEST" {
			t.Fatalf("path %q: %+v", p, r)
		}
	}
	// garbage
	req, _ := http.NewRequest("POST", e.base+"/_s/x", strings.NewReader("garbage that is long enough to be a prefix........"))
	req.Header = hdr(alice)
	resp, _ := e.c.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("garbage: %d", resp.StatusCode)
	}
	if e.seal.M.Replays.Load() < 2 {
		t.Fatal("replay counter")
	}
}

func TestModesAndEligibility(t *testing.T) {
	e := newEnv(t, ModePassthrough)
	resp := e.get("/_s/boot.js", hdr(alice))
	resp.Body.Close()
	if resp.StatusCode != 404 || resp.Header.Get("X-Seal-Error") != "SEAL_DISABLED" {
		t.Fatalf("passthrough boot.js: %d", resp.StatusCode)
	}
	resp = e.get("/_s/sw.js", hdr(alice))
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Contains(b, []byte("unregister")) || resp.Header.Get("Service-Worker-Allowed") != "/" {
		t.Fatal("passthrough must serve the self-unregistering worker")
	}
	resp = e.get("/_s/health", nil)
	m := readJSON(t, resp.Body)
	resp.Body.Close()
	if m["mode"] != "passthrough" || m["ok"] != true {
		t.Fatalf("health %v", m)
	}

	e = newEnv(t, ModeOffer)
	resp = e.get("/_s/boot.js", hdr(bob))
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatal("non-eligible identity got boot.js")
	}
	resp = e.get("/_s/sw.js", hdr(alice))
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.HasPrefix(b, []byte("self.__DSH_SEAL_CFG=")) {
		t.Fatal("offer sw.js")
	}

	e = newEnv(t, ModeRequire)
	for path, want := range map[string]int{"/api/echo": 403, "/": 200, "/favicon.svg": 404, "/report-public/x": 404} {
		resp = e.get(path, hdr(alice))
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("require %s: %d", path, resp.StatusCode)
		}
	}
	resp = e.get("/api/echo", hdr(bob))
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal("require must not affect identities that are not sealed")
	}
	s := e.session(alice)
	r, _ := s.Do(context.Background(), &sealclient.Request{Method: "GET", Path: "/api/echo"})
	io.Copy(io.Discard, r.Body)
	if r.Status != 200 {
		t.Fatal("sealed request in require mode")
	}
}

func TestSecondUserSealedKeepsRouting(t *testing.T) {
	e := newEnv(t, ModeOffer, func(c *Config) { c.Identities = []string{alice, bob} })
	s := e.session(bob)
	r, _ := s.Do(context.Background(), &sealclient.Request{Method: "GET", Path: "/api/echo"})
	m := readJSON(t, r.Body)
	if m["headers"].(map[string]any)["X-Auth-Email"] != bob {
		t.Fatalf("routing identity lost: %v", m["headers"])
	}
}

// Mux ----------------------------------------------------------------------------------------

func sendWS(t *testing.T, m *sealclient.Mux, ch uint32, op byte, data []byte) {
	typ := MBinary
	if op == wsproto.OpText {
		typ = MText
	}
	for {
		n := min(len(data), chunk)
		ty := typ
		if n < len(data) {
			ty |= FlagMore
		}
		if err := m.Send(ty, ch, data[:n]); err != nil {
			t.Fatal(err)
		}
		data = data[n:]
		if len(data) == 0 {
			return
		}
	}
}

// muxRouter collects frames per channel, reassembling fragments.
type muxRouter struct {
	m   *sealclient.Mux
	out map[uint32]chan sealclient.MuxFrame
}

func (r *muxRouter) run() {
	frag := map[uint32][]byte{}
	for {
		f, err := r.m.Recv()
		if err != nil {
			for _, c := range r.out {
				close(c)
			}
			return
		}
		base := f.Type &^ FlagMore
		if base == MCredit {
			continue
		}
		if base == MText || base == MBinary {
			r.m.Send(MCredit, f.Chan, binary.BigEndian.AppendUint32(nil, uint32(len(f.Payload))))
			frag[f.Chan] = append(frag[f.Chan], f.Payload...)
			if f.Type&FlagMore != 0 {
				continue
			}
			f.Payload, frag[f.Chan] = frag[f.Chan], nil
			f.Type = base
		}
		if c, ok := r.out[f.Chan]; ok {
			c <- f
		}
	}
}

func next(t *testing.T, c chan sealclient.MuxFrame) sealclient.MuxFrame {
	t.Helper()
	select {
	case f, ok := <-c:
		if !ok {
			t.Fatal("mux closed")
		}
		return f
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for a mux frame")
	}
	return sealclient.MuxFrame{}
}

func TestMux(t *testing.T) {
	e := newEnv(t, ModeOffer)
	s := e.session(alice)
	m, err := s.DialMux(context.Background(), e.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	r := &muxRouter{m: m, out: map[uint32]chan sealclient.MuxFrame{}}
	for i := uint32(1); i <= 6; i++ {
		r.out[i] = make(chan sealclient.MuxFrame, 2048)
	}
	go r.run()
	open := func(ch uint32, o map[string]any) {
		b, _ := json.Marshal(o)
		if err := m.Send(MOpen, ch, b); err != nil {
			t.Fatal(err)
		}
	}
	// three inner sockets at once
	for ch := uint32(1); ch <= 3; ch++ {
		open(ch, map[string]any{"k": "ws", "u": fmt.Sprintf("/ws/echo?hello=1&n=%d", ch), "p": []string{"chat-v1"}, "h": [][2]string{{"X-Auth-Email", "evil@example.com"}}})
	}
	for ch := uint32(1); ch <= 3; ch++ {
		f := next(t, r.out[ch])
		if f.Type != MOpened || !bytes.Contains(f.Payload, []byte("chat-v1")) {
			t.Fatalf("ch %d opened: %x %s", ch, f.Type, f.Payload)
		}
		f = next(t, r.out[ch])
		var hello map[string]string
		json.Unmarshal(f.Payload, &hello)
		if hello["hello"] != alice || hello["origin"] != "https://dsh.example.com" || hello["cookie"] != "dsh-auth-x=secretcookie" || !strings.HasSuffix(hello["path"], fmt.Sprintf("n=%d", ch)) {
			t.Fatalf("inner socket identity: %v", hello)
		}
	}
	big := make([]byte, 300000)
	rand.Read(big)
	sendWS(t, m, 1, wsproto.OpBinary, big)
	sendWS(t, m, 2, wsproto.OpText, []byte("hello two"))
	sendWS(t, m, 3, wsproto.OpText, []byte("burst 500"))
	if f := next(t, r.out[1]); f.Type != MBinary || !bytes.Equal(f.Payload, big) {
		t.Fatalf("fragmented binary echo failed (%d bytes)", len(f.Payload))
	}
	if f := next(t, r.out[2]); f.Type != MText || string(f.Payload) != "hello two" {
		t.Fatal("text echo")
	}
	for i := 0; i < 500; i++ {
		if f := next(t, r.out[3]); string(f.Payload) != fmt.Sprintf("b%d", i) {
			t.Fatalf("burst order at %d: %s", i, f.Payload)
		}
	}
	// server side close with a code
	sendWS(t, m, 2, wsproto.OpText, []byte("close-me"))
	if f := next(t, r.out[2]); f.Type != MClose || binary.BigEndian.Uint16(f.Payload) != 4001 || string(f.Payload[2:]) != "asked" {
		t.Fatalf("close: %x %v", f.Type, f.Payload)
	}
	// client side close
	m.Send(MClose, 1, closePayload(1000, "bye"))
	if f := next(t, r.out[1]); f.Type != MClose {
		t.Fatal("client close not echoed")
	}
	// refused upstream socket
	open(4, map[string]any{"k": "ws", "u": "/ws/deny"})
	if f := next(t, r.out[4]); f.Type != MError || !bytes.Contains(f.Payload, []byte("403")) {
		t.Fatalf("deny: %s", f.Payload)
	}
	// event stream channel
	open(5, map[string]any{"k": "http", "u": "/api/sse?n=2&ms=20", "h": [][2]string{{"Accept", "text/event-stream"}}})
	if f := next(t, r.out[5]); f.Type != MOpened || !bytes.Contains(f.Payload, []byte("text/event-stream")) {
		t.Fatalf("sse opened: %s", f.Payload)
	}
	var got []byte
	for {
		f := next(t, r.out[5])
		if f.Type == MClose {
			break
		}
		got = append(got, f.Payload...)
	}
	if !bytes.Contains(got, []byte("data: tick 1")) {
		t.Fatalf("sse body: %s", got)
	}
	// keepalive
	m.Send(MPing, 0, []byte("12345678"))
	if e.seal.M.MuxChannels.Load() != 5 {
		t.Fatalf("channels %d", e.seal.M.MuxChannels.Load())
	}
}

func TestMuxRejectsForgery(t *testing.T) {
	e := newEnv(t, ModeOffer)
	s := e.session(alice)
	m, err := s.DialMux(context.Background(), e.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	m.SendRaw(bytes.Repeat([]byte{1}, 40))
	_, err = m.Recv()
	var ce *wsproto.CloseError
	if !asClose(err, &ce) || ce.Code != 4400 {
		t.Fatalf("forged frame accepted: %v", err)
	}
	// unknown session on the mux
	s2 := s.Clone()
	s2.SID = make([]byte, 16)
	m2, err := s2.DialMux(context.Background(), e.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer m2.Close()
	_, err = m2.Recv()
	if !asClose(err, &ce) || ce.Code != 4401 {
		t.Fatalf("unknown session on mux: %v", err)
	}
}

func asClose(err error, ce **wsproto.CloseError) bool {
	c, ok := err.(*wsproto.CloseError)
	if ok {
		*ce = c
	}
	return ok
}

// Fuzz ------------------------------------------------------------------------------------

func FuzzSealedEnvelope(f *testing.F) {
	cfg := Defaults()
	cfg.Identities = []string{alice}
	cfg.Mode = ModeOffer
	cfg.SealAnonymous = true
	cfg.Upstream = "127.0.0.1:1"
	cfg.StateDir = f.TempDir()
	keys, _ := keystore.Open(cfg.StateDir, cfg.KXRotate)
	s := New(cfg, keys, slog.New(slog.NewTextHandler(io.Discard, nil)))
	sid, _, ms, _, _ := sc.ServerHandshake(mustKX(keys), keys.IdentityRaw(), mustClient())
	s.newSession(sid, ms, "")
	good := append([]byte("DSX1"), sid...)
	good = binary.BigEndian.AppendUint64(good, 1)
	out := sc.NewStream(ms, sid, sc.DirC2S, 1)
	good = AppendFrame(good, out.Seal(sc.FHead, []byte(`{"m":"GET","u":"/x","h":[],"n":0}`)))
	f.Add(good)
	f.Add([]byte("DSX1"))
	f.Fuzz(func(t *testing.T, b []byte) {
		req := httptest.NewRequest("POST", "/_s/x", bytes.NewReader(b))
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
	})
}

func mustKX(k *keystore.Store) *ecdh.PrivateKey {
	p, _ := k.KX(k.Bundle().KX.KID)
	return p
}

func mustClient() []byte {
	k, _ := ecdh.P256().GenerateKey(rand.Reader)
	return k.PublicKey().Bytes()
}

// TestMuxInnerSocketKeepsOuterHostOriginProto: inner WebSockets (dsh-phone's
// audio socket /dsh-phone/api/io) are replayed with the outer Host, Origin and
// X-Forwarded-Proto, which the phone gate checks (Origin = Host, wss only
// except loopback); values the page puts inside the envelope never win.
func TestMuxInnerSocketKeepsOuterHostOriginProto(t *testing.T) {
	e := newEnv(t, ModeOffer)
	s := e.session(alice)
	s.Header.Set("Host", "dsh.example.com")
	s.Header.Set("X-Forwarded-Proto", "https")
	m, err := s.DialMux(context.Background(), e.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	r := &muxRouter{m: m, out: map[uint32]chan sealclient.MuxFrame{1: make(chan sealclient.MuxFrame, 16)}}
	go r.run()
	b, _ := json.Marshal(map[string]any{"k": "ws", "u": "/ws/echo?hello=1", "p": []string{"dshp.ticket.abc"},
		"h": [][2]string{{"Origin", "https://evil.example"}, {"Host", "evil.example"}, {"X-Forwarded-Proto", "http"}}})
	if err := m.Send(MOpen, 1, b); err != nil {
		t.Fatal(err)
	}
	if f := next(t, r.out[1]); f.Type != MOpened || !bytes.Contains(f.Payload, []byte("dshp.ticket.abc")) {
		t.Fatalf("opened: %x %s", f.Type, f.Payload)
	}
	var hello map[string]string
	json.Unmarshal(next(t, r.out[1]).Payload, &hello)
	if hello["host"] != "dsh.example.com" || hello["origin"] != "https://dsh.example.com" || hello["xfp"] != "https" || hello["hello"] != alice || hello["cookie"] != "dsh-auth-x=secretcookie" {
		t.Fatalf("inner socket headers: %v", hello)
	}
}
