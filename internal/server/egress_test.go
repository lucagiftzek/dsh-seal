package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dsh-seal/internal/sealclient"
	"dsh-seal/internal/wsproto"
)

func TestEgressIPPolicy(t *testing.T) {
	p := newPolicy(&Config{EgressDenyCIDRs: []string{"1.2.3.4", "2a01:4f8:1:2::/64"}})
	deny := []string{"127.0.0.1", "127.9.9.9", "10.1.2.3", "172.16.0.1", "172.31.255.255", "10.20.30.40", "169.254.169.254",
		"100.64.0.1", "0.0.0.0", "0.1.2.3", "224.0.0.1", "255.255.255.255", "198.18.0.1", "192.0.2.1", "::", "::1", "fe80::1",
		"fc00::1", "fd12:3456::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "64:ff9b::a00:1",
		"2002:7f00:1::1", "2001::1", "2001:db8::1", "ff02::1", "1.2.3.4", "2a01:4f8:1:2::22"}
	for _, s := range deny {
		if p.IPAllowed(netip.MustParseAddr(s)) {
			t.Errorf("%s must be refused", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "104.16.0.1", "::ffff:8.8.8.8", "2606:4700::1111", "2a00:1450:4001::1"} {
		if !p.IPAllowed(netip.MustParseAddr(s)) {
			t.Errorf("%s must be allowed", s)
		}
	}
}

func TestEgressNormalizeTarget(t *testing.T) {
	p := newPolicy(&Config{EgressPorts: []int{8443}, EgressDenyHosts: []string{"tracker.example.org"}})
	ok := map[string]string{
		"https://cdn.example.com/a.woff2?v=1#x": "https://cdn.example.com/a.woff2?v=1",
		"http://cdn.example.com/x":              "https://cdn.example.com/x",
		"http://cdn.example.com:80/x":           "https://cdn.example.com/x",
		"https://cdn.example.com:443":           "https://cdn.example.com/",
		"HTTPS://CDN.Example.COM./p":            "https://cdn.example.com/p",
		"https://cdn.example.com:8443/p":        "https://cdn.example.com:8443/p",
	}
	for in, want := range ok {
		u, ee := p.NormalizeTarget(in, false)
		if ee != nil || u.String() != want {
			t.Errorf("%s: got %v %v, want %s", in, u, ee, want)
		}
	}
	if u, ee := p.NormalizeTarget("ws://echo.example.com/s", true); ee != nil || u.String() != "wss://echo.example.com/s" {
		t.Errorf("ws upgrade: %v %v", u, ee)
	}
	bad := map[string]string{
		"ftp://example.com/":                 "SEAL_EGRESS_SCHEME",
		"https://user:pw@example.com/":       "SEAL_EGRESS_BAD_URL",
		"https://example.com:22/":            "SEAL_EGRESS_PORT",
		"http://example.com:8080/":           "SEAL_EGRESS_PORT",
		"https://localhost/":                 "SEAL_EGRESS_DENIED",
		"https://printer.local/":             "SEAL_EGRESS_DENIED",
		"https://metadata.google.internal/":  "SEAL_EGRESS_DENIED",
		"https://a.tracker.example.org/p.js": "SEAL_EGRESS_DENIED",
		"wss://example.com/":                 "SEAL_EGRESS_SCHEME", // ws scheme on a fetch
		"https://exa mple.com/":              "SEAL_EGRESS_BAD_URL",
	}
	for in, code := range bad {
		if _, ee := p.NormalizeTarget(in, false); ee == nil || ee.Code != code {
			t.Errorf("%s: got %v, want %s", in, ee, code)
		}
	}
}

func TestNeutralizeHints(t *testing.T) {
	in := `<head><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link rel=dns-prefetch href=//cdn.example.com>` +
		`<link rel="preconnect" href="https://dsh.example.com"><link rel="stylesheet" href="https://fonts.googleapis.com/css"><link rel="preload" as="font" href="https://x.example/f.woff2"><link href="https://a.example" rel="prerender"></head>`
	out := string(NeutralizeHints([]byte(in), "dsh.example.com"))
	for _, gone := range []string{"fonts.gstatic.com", "cdn.example.com", "a.example"} {
		if strings.Contains(out, gone) {
			t.Errorf("%s hint kept: %s", gone, out)
		}
	}
	for _, kept := range []string{`href="https://dsh.example.com"`, "fonts.googleapis.com/css", "x.example/f.woff2"} {
		if !strings.Contains(out, kept) {
			t.Errorf("%s removed: %s", kept, out)
		}
	}
	h := http.Header{}
	h.Add("Link", `<https://fonts.gstatic.com>; rel=preconnect, </app.css>; rel=preload; as=style`)
	h.Add("Link", `<https://cdn.example>; rel="dns-prefetch"`)
	dropHintLinks(h)
	if got := strings.Join(h.Values("Link"), "|"); got != `</app.css>; rel=preload; as=style` {
		t.Errorf("Link header: %q", got)
	}
}

// fakeResolver maps names to addresses; "rebind" names answer differently on
// every lookup.
type fakeResolver struct {
	mu    sync.Mutex
	m     map[string][][]string
	calls map[string]int
}

func (f *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	answers, ok := f.m[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	i := f.calls[host]
	f.calls[host]++
	if i >= len(answers) {
		i = len(answers) - 1
	}
	var out []netip.Addr
	for _, s := range answers[i] {
		out = append(out, netip.MustParseAddr(s))
	}
	return out, nil
}

// remote is a TLS "internet site" on loopback with a certificate for
// *.example.net, trusted through egress_ca_file.
type remote struct {
	srv  *httptest.Server
	port string
	mu   sync.Mutex
	seen []http.Header
}

func (rm *remote) last() http.Header {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	return rm.seen[len(rm.seen)-1]
}

func newRemote(t *testing.T) (*remote, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.net"}, DNSNames: []string{"example.net", "*.example.net"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	rm := &remote{}
	big := bytes.Repeat([]byte("0123456789abcdef"), 1<<17) // 2 MiB
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		rm.mu.Lock()
		rm.seen = append(rm.seen, r.Header.Clone())
		rm.mu.Unlock()
		switch {
		case r.URL.Path == "/img.png":
			w.Header().Set("Content-Type", "image/png")
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			w.Header().Set("Set-Cookie", "track=1; Path=/")
			w.Header().Set("Link", "<https://other.example>; rel=preconnect")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Write([]byte("\x89PNG fake"))
		case r.URL.Path == "/echo":
			b, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"method": r.Method, "body": string(b), "host": r.Host})
		case r.URL.Path == "/media.bin":
			http.ServeContent(w, r, "media.bin", time.Unix(0, 0), bytes.NewReader(big))
		case r.URL.Path == "/big":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(big)
		case r.URL.Path == "/gz":
			w.Header().Set("Content-Type", "text/css")
			w.Header().Set("Content-Encoding", "gzip")
			zw := gzip.NewWriter(w)
			zw.Write([]byte("body{color:red}"))
			zw.Close()
		case r.URL.Path == "/slow":
			time.Sleep(800 * time.Millisecond)
			w.Write([]byte("late"))
		case strings.HasPrefix(r.URL.Path, "/redir/"):
			n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/redir/"))
			if n == 0 {
				w.Write([]byte("landed"))
				return
			}
			http.Redirect(w, r, fmt.Sprintf("/redir/%d", n-1), http.StatusFound)
		case r.URL.Path == "/to":
			http.Redirect(w, r, r.URL.Query().Get("u"), http.StatusFound)
		case r.URL.Path == "/post303":
			http.Redirect(w, r, "/echo", http.StatusSeeOther)
		case r.URL.Path == "/sse":
			w.Header().Set("Content-Type", "text/event-stream")
			for i := 0; i < 3; i++ {
				fmt.Fprintf(w, "data: tick %d\n\n", i)
				w.(http.Flusher).Flush()
			}
		case r.URL.Path == "/ws":
			c, err := wsproto.Accept(w, r, "")
			if err != nil {
				return
			}
			defer c.Close()
			for {
				op, msg, err := c.ReadMessage()
				if err != nil {
					return
				}
				c.WriteMessage(op, append([]byte("echo:"+r.Header.Get("Origin")+":"), msg...))
			}
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	rm.srv = srv
	_, rm.port, _ = net.SplitHostPort(srv.Listener.Addr().String())
	return rm, caFile
}

type egressEnv struct {
	*env
	rm     *remote
	res    *fakeResolver
	dialed []string
	dmu    sync.Mutex
}

func newEgressEnv(t *testing.T, mutate ...func(*Config)) *egressEnv {
	rm, ca := newRemote(t)
	port, _ := strconv.Atoi(rm.port)
	e := newEnv(t, ModeOffer, append([]func(*Config){func(c *Config) {
		c.Identities = []string{alice, bob}
		c.EgressPorts = []int{port}
		c.EgressCAFile = ca
		c.EgressUnsafeAllow = []string{"127.0.0.1/32"} // the loopback "internet" only
		c.EgressHeaderWait = 400 * time.Millisecond
	}}, mutate...)...)
	ee := &egressEnv{env: e, rm: rm, res: &fakeResolver{calls: map[string]int{}, m: map[string][][]string{
		"pub.example.net":    {{"127.0.0.1"}},
		"mixed.example.net":  {{"10.0.0.7", "127.0.0.1", "169.254.169.254"}},
		"evil.example.net":   {{"10.0.0.1"}},
		"meta.example.net":   {{"169.254.169.254"}},
		"v6.example.net":     {{"::1"}},
		"mapped.example.net": {{"::ffff:127.0.0.2"}},
		"rebind.example.net": {{"127.0.0.1"}, {"10.20.30.40"}},
	}}}
	e.seal.Egress.Resolver = ee.res
	e.seal.Egress.DialHook = func(a string) { ee.dmu.Lock(); ee.dialed = append(ee.dialed, a); ee.dmu.Unlock() }
	return ee
}

func (ee *egressEnv) url(host, path string) string {
	return "https://" + host + ":" + ee.rm.port + path
}

func (ee *egressEnv) do(s *sealclient.Session, r *sealclient.Request) (*sealclient.Response, []byte) {
	ee.t.Helper()
	resp, err := s.Do(context.Background(), r)
	if err != nil {
		ee.t.Fatal(err)
	}
	if resp.OuterStatus != 200 {
		ee.t.Fatalf("outer %d %s", resp.OuterStatus, resp.ErrorCode)
	}
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func TestEgressFetchHeadersAndCookies(t *testing.T) {
	ee := newEgressEnv(t)
	s := ee.session(alice)
	r, body := ee.do(s, &sealclient.Request{Method: "GET", Path: ee.url("pub.example.net", "/img.png?x=1"), Mode: "no-cors", Dest: "image",
		Header: [][2]string{{"Cookie", "page=1"}, {"X-Forwarded-For", "6.6.6.6"}, {"X-Auth-Email", "evil@example.com"}, {"Authorization", "Bearer page-set"}, {"User-Agent", "MyBrowser/1"}, {"X-Custom", "ok"}}})
	if r.Status != 200 || string(body) != "\x89PNG fake" || r.Header.Get("Content-Type") != "image/png" {
		t.Fatalf("fetch: %d %q %v", r.Status, body, r.Header)
	}
	if r.Header.Get("Set-Cookie") != "" || r.OuterHeader.Get("Set-Cookie") != "" || r.Header.Get("Link") != "" {
		t.Fatalf("remote Set-Cookie or Link leaked: inner %v outer %v", r.Header, r.OuterHeader)
	}
	if r.Header.Get("Cache-Control") == "" || r.FinalURL != ee.url("pub.example.net", "/img.png?x=1") {
		t.Fatalf("cache header or final url: %v %q", r.Header, r.FinalURL)
	}
	h := ee.rm.last()
	if h.Get("Cookie") != "" || h.Get("X-Auth-Email") != "" || h.Get("X-Forwarded-For") != "" || h.Get("Forwarded") != "" {
		t.Fatalf("identity leaked to the remote: %v", h)
	}
	if h.Get("User-Agent") != EgressUA || h.Get("Referer") != ee.url("pub.example.net", "/") || h.Get("Origin") != "" || h.Get("Accept-Language") != "en-US,en;q=0.9" {
		t.Fatalf("generic headers: %v", h)
	}
	if h.Get("Authorization") != "Bearer page-set" || h.Get("X-Custom") != "ok" || h.Get("Sec-Fetch-Dest") != "image" {
		t.Fatalf("page headers: %v", h)
	}
	// cors mode sends the page origin, as a browser would
	ee.do(s, &sealclient.Request{Method: "GET", Path: ee.url("pub.example.net", "/img.png"), Mode: "cors", Dest: "font"})
	if o := ee.rm.last().Get("Origin"); o != "https://dsh.example.com" {
		t.Fatalf("cors origin: %q", o)
	}
	// http is upgraded, never sent in plaintext
	r, body = ee.do(s, &sealclient.Request{Method: "POST", Path: "http://pub.example.net:" + ee.rm.port + "/echo", Body: []byte("hello"), Header: [][2]string{{"Content-Type", "text/plain"}}})
	if r.Status != 200 || !strings.Contains(string(body), `"body":"hello"`) || !strings.HasPrefix(r.FinalURL, "https://") {
		t.Fatalf("upgraded POST: %d %s %s", r.Status, body, r.FinalURL)
	}
	// 303 after POST becomes GET
	_, body = ee.do(s, &sealclient.Request{Method: "POST", Path: ee.url("pub.example.net", "/post303"), Body: []byte("x")})
	if !strings.Contains(string(body), `"method":"GET"`) {
		t.Fatalf("303: %s", body)
	}
}

func TestEgressSSRFGuard(t *testing.T) {
	ee := newEgressEnv(t)
	s := ee.session(alice)
	code := func(target string) string {
		r, _ := ee.do(s, &sealclient.Request{Method: "GET", Path: target})
		return r.Header.Get("X-Seal-Egress-Error")
	}
	cases := map[string]string{
		ee.url("evil.example.net", "/"):                                             "SEAL_EGRESS_FORBIDDEN",
		ee.url("meta.example.net", "/latest/meta-data/"):                            "SEAL_EGRESS_FORBIDDEN",
		ee.url("v6.example.net", "/"):                                               "SEAL_EGRESS_FORBIDDEN",
		ee.url("mapped.example.net", "/"):                                           "SEAL_EGRESS_FORBIDDEN",
		"https://10.0.0.1:" + ee.rm.port + "/":                                      "SEAL_EGRESS_FORBIDDEN",
		"https://[::1]:" + ee.rm.port + "/":                                         "SEAL_EGRESS_FORBIDDEN",
		"https://169.254.169.254/":                                                  "SEAL_EGRESS_FORBIDDEN",
		ee.url("localhost", "/"):                                                    "SEAL_EGRESS_DENIED",
		ee.url("nowhere.example.net", "/"):                                          "SEAL_EGRESS_DNS",
		"https://pub.example.net:22/":                                               "SEAL_EGRESS_PORT",
		ee.url("pub.example.net", "/slow"):                                          "SEAL_EGRESS_TIMEOUT",
		ee.url("pub.example.net", "/redir/6"):                                       "SEAL_EGRESS_REDIRECTS",
		ee.url("pub.example.net", "/to?u=https://10.0.0.1/"):                        "SEAL_EGRESS_FORBIDDEN",
		ee.url("pub.example.net", "/to?u=https://evil.example.net:"+ee.rm.port+"/"): "SEAL_EGRESS_FORBIDDEN",
		ee.url("pub.example.net", "/to?u=https://localhost/"):                       "SEAL_EGRESS_DENIED",
		ee.url("pub.example.net", "/to?u=ftp://pub.example.net/"):                   "SEAL_EGRESS_SCHEME",
	}
	for target, want := range cases {
		if got := code(target); got != want {
			t.Errorf("%s: got %q, want %q", target, got, want)
		}
	}
	// redirects within the limit land, the final URL is reported
	r, body := ee.do(s, &sealclient.Request{Method: "GET", Path: ee.url("pub.example.net", "/redir/5")})
	if string(body) != "landed" || !strings.HasSuffix(r.FinalURL, "/redir/0") {
		t.Fatalf("5 redirects: %s %s", body, r.FinalURL)
	}
	// a name with private and public answers is dialled on the public one only
	r, _ = ee.do(s, &sealclient.Request{Method: "GET", Path: ee.url("mixed.example.net", "/img.png")})
	if r.Status != 200 {
		t.Fatalf("mixed: %d", r.Status)
	}
	ee.dmu.Lock()
	for _, a := range ee.dialed {
		if !strings.HasPrefix(a, "127.0.0.1:") {
			t.Errorf("dialled a refused address: %s", a)
		}
	}
	ee.dmu.Unlock()
	// DNS rebinding: the second lookup answers a private address; the new
	// connection must be refused, never dialled.
	if r, _ = ee.do(s, &sealclient.Request{Method: "GET", Path: ee.url("rebind.example.net", "/img.png")}); r.Status != 200 {
		t.Fatalf("rebind first: %d", r.Status)
	}
	ee.seal.Egress.transport().CloseIdleConnections()
	if got := code(ee.url("rebind.example.net", "/img.png")); got != "SEAL_EGRESS_FORBIDDEN" {
		t.Fatalf("rebind second: %q", got)
	}
	ee.dmu.Lock()
	for _, a := range ee.dialed {
		if strings.HasPrefix(a, "192.168.") || strings.HasPrefix(a, "10.") || strings.HasPrefix(a, "169.254.") {
			t.Errorf("dialled %s", a)
		}
	}
	ee.dmu.Unlock()
	if ee.seal.M.EgressRefused.Load() == 0 {
		t.Fatal("refusals not counted")
	}
}

func TestEgressRangeGzipAndCaps(t *testing.T) {
	ee := newEgressEnv(t, func(c *Config) { c.EgressMaxBytes = 1 << 20; c.EgressMaxReq = 1000 })
	s := ee.session(alice)
	r, body := ee.do(s, &sealclient.Request{Method: "GET", Path: ee.url("pub.example.net", "/media.bin"), Header: [][2]string{{"Range", "bytes=16-31"}}, Dest: "video"})
	if r.Status != 206 || string(body) != "0123456789abcdef" || r.Header.Get("Content-Range") != "bytes 16-31/2097152" {
		t.Fatalf("range: %d %q %v", r.Status, body, r.Header)
	}
	if ae := ee.rm.last().Get("Accept-Encoding"); ae != "identity" {
		t.Fatalf("range must ask identity, got %q", ae)
	}
	r, body = ee.do(s, &sealclient.Request{Method: "GET", Path: ee.url("pub.example.net", "/gz")})
	if !r.Gzip {
		t.Fatal("gzip body must stay compressed inside the envelope")
	}
	zr, _ := gzip.NewReader(bytes.NewReader(body))
	if b, _ := io.ReadAll(zr); string(b) != "body{color:red}" {
		t.Fatalf("gzip: %q", b)
	}
	// response cap: the stream ends with an error frame
	resp, err := s.Do(context.Background(), &sealclient.Request{Method: "GET", Path: ee.url("pub.example.net", "/big")})
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(resp.Body)
	if err == nil || !strings.Contains(err.Error(), "SEAL_EGRESS_TOO_LARGE") || len(b) > 1<<20 {
		t.Fatalf("cap: %d bytes, err %v", len(b), err)
	}
	// request cap
	r, _ = ee.do(s, &sealclient.Request{Method: "POST", Path: ee.url("pub.example.net", "/echo"), Body: make([]byte, 2000)})
	if r.Header.Get("X-Seal-Egress-Error") != "SEAL_EGRESS_TOO_LARGE" || r.Status != 413 {
		t.Fatalf("request cap: %d %v", r.Status, r.Header)
	}
}

func TestEgressSwitchesAndRate(t *testing.T) {
	ee := newEgressEnv(t, func(c *Config) { c.EgressIdentities = []string{alice}; c.EgressRate = 0.0001; c.EgressBurst = 3 })
	s := ee.session(alice)
	for i := 0; i < 3; i++ {
		if r, _ := ee.do(s, &sealclient.Request{Method: "GET", Path: ee.url("pub.example.net", "/img.png")}); r.Status != 200 {
			t.Fatalf("burst %d: %d", i, r.Status)
		}
	}
	if r, _ := ee.do(s, &sealclient.Request{Method: "GET", Path: ee.url("pub.example.net", "/img.png")}); r.Header.Get("X-Seal-Egress-Error") != "SEAL_EGRESS_RATE" {
		t.Fatalf("rate: %v", r.Header)
	}
	// an identity outside egress_identities, and the kill switch
	sa := ee.session(bob)
	if r, _ := ee.do(sa, &sealclient.Request{Method: "GET", Path: ee.url("pub.example.net", "/img.png")}); r.Header.Get("X-Seal-Egress-Error") != "SEAL_EGRESS_OFF" {
		t.Fatalf("not in egress_identities: %v", r.Header)
	}
	c := *ee.seal.Cfg()
	c.Egress = false
	ee.seal.Reload(c)
	if r, _ := ee.do(s, &sealclient.Request{Method: "GET", Path: ee.url("pub.example.net", "/img.png")}); r.Header.Get("X-Seal-Egress-Error") != "SEAL_EGRESS_OFF" {
		t.Fatalf("egress=off: %v", r.Header)
	}
	// the scripts tell the client whether egress is on for this identity
	for _, tc := range []struct {
		email string
		on    bool
		want  string
	}{{alice, false, `"egress":false`}, {alice, true, `"egress":true`}, {bob, true, `"egress":false`}} {
		c.Egress = tc.on
		ee.seal.Reload(c)
		resp := ee.get("/_s/sw.js", hdr(tc.email))
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !bytes.Contains(b, []byte(tc.want)) || !bytes.Contains(b, []byte(`"webrtc":"block"`)) {
			t.Errorf("%s egress=%v: config %.300s", tc.email, tc.on, b)
		}
	}
}

func TestEgressMux(t *testing.T) {
	ee := newEgressEnv(t)
	s := ee.session(alice)
	m, err := s.DialMux(context.Background(), ee.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	r := &muxRouter{m: m, out: map[uint32]chan sealclient.MuxFrame{}}
	for i := uint32(1); i <= 4; i++ {
		r.out[i] = make(chan sealclient.MuxFrame, 64)
	}
	go r.run()
	open := func(ch uint32, o map[string]any) {
		b, _ := json.Marshal(o)
		if err := m.Send(MOpen, ch, b); err != nil {
			t.Fatal(err)
		}
	}
	// cross-origin WebSocket: ws:// is upgraded to wss://, the page origin is sent
	open(1, map[string]any{"k": "ws", "u": "ws://pub.example.net:" + ee.rm.port + "/ws"})
	if f := next(t, r.out[1]); f.Type != MOpened {
		t.Fatalf("ws opened: %x %s", f.Type, f.Payload)
	}
	sendWS(t, m, 1, wsproto.OpText, []byte("ping"))
	if f := next(t, r.out[1]); f.Type != MText || string(f.Payload) != "echo:https://dsh.example.com:ping" {
		t.Fatalf("ws echo: %x %q", f.Type, f.Payload)
	}
	if h := ee.rm.last(); h.Get("Cookie") != "" || h.Get("X-Auth-Email") != "" || h.Get("User-Agent") != EgressUA {
		t.Fatalf("ws headers: %v", h)
	}
	// private target refused
	open(2, map[string]any{"k": "ws", "u": "wss://evil.example.net:" + ee.rm.port + "/ws"})
	if f := next(t, r.out[2]); f.Type != MError || !bytes.Contains(f.Payload, []byte("SEAL_EGRESS_FORBIDDEN")) {
		t.Fatalf("ws private: %x %s", f.Type, f.Payload)
	}
	// cross-origin EventSource
	open(3, map[string]any{"k": "http", "u": ee.url("pub.example.net", "/sse"), "h": [][2]string{{"Accept", "text/event-stream"}}})
	f := next(t, r.out[3])
	if f.Type != MOpened || !bytes.Contains(f.Payload, []byte("text/event-stream")) {
		t.Fatalf("sse opened: %x %s", f.Type, f.Payload)
	}
	var got []byte
	for {
		f = next(t, r.out[3])
		if f.Type == MClose {
			break
		}
		got = append(got, f.Payload...)
	}
	if !strings.Contains(string(got), "data: tick 2") {
		t.Fatalf("sse body: %q", got)
	}
	// egress off for the session identity: refused
	c := *ee.seal.Cfg()
	c.Egress = false
	ee.seal.Reload(c)
	open(4, map[string]any{"k": "ws", "u": "wss://pub.example.net:" + ee.rm.port + "/ws"})
	if f := next(t, r.out[4]); f.Type != MError || !bytes.Contains(f.Payload, []byte("SEAL_EGRESS_OFF")) {
		t.Fatalf("ws egress off: %x %s", f.Type, f.Payload)
	}
	if ee.seal.M.EgressSockets.Load() != 2 {
		t.Fatalf("egress sockets counted %d", ee.seal.M.EgressSockets.Load())
	}
}

func TestEgressSocketLimit(t *testing.T) {
	ee := newEgressEnv(t, func(c *Config) { c.EgressSockets = 1 })
	var n atomic.Int32
	rel, e1 := ee.seal.Egress.admitSocket(alice)
	if e1 != nil {
		t.Fatal(e1)
	}
	if _, e2 := ee.seal.Egress.admitSocket(alice); e2 == nil || e2.Code != "SEAL_EGRESS_RATE" {
		t.Fatalf("second socket: %v", e2)
	}
	rel()
	rel() // idempotent
	if r2, e3 := ee.seal.Egress.admitSocket(alice); e3 != nil {
		t.Fatalf("after release: %v", e3)
	} else {
		r2()
		n.Add(1)
	}
}
