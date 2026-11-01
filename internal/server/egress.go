package server

// Sealed egress: requests the page makes to other hosts travel sealed to
// dsh-seal (inside /_s/x or the mux), and dsh-seal fetches them from the public
// internet itself. An observer between the browser and the server sees only
// the DSH host; the remote site sees this server, never the user's device.
//
// The fetcher is an SSRF-hardened client: https only (http and ws are upgraded,
// never sent in plaintext), public addresses only with DNS resolved and checked
// in the dialer and the checked address dialled (no second lookup, so DNS
// rebinding cannot swap in a private address), every redirect hop re-checked,
// allowed ports only, size and time caps, per-identity limits, and no
// credentials of the user (cookies and identity headers of the outer request
// are never copied).

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"dsh-seal/internal/wsproto"
)

// Generic browser User-Agent sent on every egress request (the user's own is
// never forwarded).
const EgressUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"

// MaxRedirects bounds the redirect hops the server follows.
const MaxRedirects = 5

// EgressError is a refusal or failure of an egress request. It is reported to
// the client inside the sealed response (status + X-Seal-Egress-Error).
type EgressError struct {
	Code   string
	Status int
	Msg    string
}

func (e *EgressError) Error() string { return e.Code + ": " + e.Msg }

func egErr(code string, status int, f string, a ...any) *EgressError {
	return &EgressError{Code: code, Status: status, Msg: fmt.Sprintf(f, a...)}
}

// blockedNets are never dialled, whatever DNS says.
var blockedNets = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64",
		"2001::/23", "2001:db8::/32", "2002::/16", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// defaultDenyHosts are host suffixes that never leave (local names).
var defaultDenyHosts = []string{"localhost", "local", "internal", "lan", "home.arpa", "localdomain", "onion", "invalid", "test", "example"}

// Resolver is the DNS interface the guard uses (tests replace it).
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// egressPolicy is built from the config on every reload.
type egressPolicy struct {
	ports     map[int]bool
	denyHosts []string
	denyNets  []netip.Prefix
	allowNets []netip.Prefix // test only: treated as public
}

func newPolicy(c *Config) *egressPolicy {
	p := &egressPolicy{ports: map[int]bool{443: true}}
	for _, n := range c.EgressPorts {
		p.ports[n] = true
	}
	p.denyHosts = append(append([]string(nil), defaultDenyHosts...), c.EgressDenyHosts...)
	for _, s := range c.EgressDenyCIDRs {
		if pf, err := parseNet(s); err == nil {
			p.denyNets = append(p.denyNets, pf)
		}
	}
	for _, s := range c.EgressUnsafeAllow {
		if pf, err := parseNet(s); err == nil {
			p.allowNets = append(p.allowNets, pf)
		}
	}
	return p
}

func parseNet(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// IPAllowed reports whether an address may be dialled.
func (p *egressPolicy) IPAllowed(ip netip.Addr) bool {
	ip = ip.Unmap().WithZone("")
	if !ip.IsValid() {
		return false
	}
	for _, n := range p.denyNets {
		if n.Contains(ip) {
			return false
		}
	}
	for _, n := range p.allowNets {
		if n.Contains(ip) {
			return true
		}
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	for _, n := range blockedNets {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

// HostAllowed reports whether a host name is not on the deny list.
func (p *egressPolicy) HostAllowed(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	if h == "" {
		return false
	}
	for _, d := range p.denyHosts {
		if d != "" && (h == d || strings.HasSuffix(h, "."+d)) {
			return false
		}
	}
	return true
}

// NormalizeTarget validates an absolute URL from the page and returns the URL
// that is actually fetched: https (or wss) only, an allowed port, no userinfo,
// no fragment. ws is true for WebSocket targets.
func (p *egressPolicy) NormalizeTarget(raw string, ws bool) (*url.URL, *EgressError) {
	if len(raw) > 8192 || strings.ContainsAny(raw, " \r\n\t") {
		return nil, egErr("SEAL_EGRESS_BAD_URL", 400, "malformed URL")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return nil, egErr("SEAL_EGRESS_BAD_URL", 400, "malformed URL")
	}
	if u.User != nil {
		return nil, egErr("SEAL_EGRESS_BAD_URL", 400, "credentials in URL")
	}
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	switch {
	case !ws && (scheme == "https" || scheme == "http"), ws && (scheme == "wss" || scheme == "ws"):
	default:
		return nil, egErr("SEAL_EGRESS_SCHEME", 400, "scheme %q not allowed", scheme)
	}
	if scheme == "http" || scheme == "ws" {
		// Upgrade: plaintext never leaves the server. Port 80 becomes 443.
		if port == "80" {
			port = ""
		}
		if ws {
			scheme = "wss"
		} else {
			scheme = "https"
		}
	}
	if port == "443" {
		port = ""
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if !p.HostAllowed(host) {
		return nil, egErr("SEAL_EGRESS_DENIED", 403, "host is on the deny list")
	}
	n := 443
	if port != "" {
		v, err := strconv.Atoi(port)
		if err != nil {
			return nil, egErr("SEAL_EGRESS_BAD_URL", 400, "bad port")
		}
		n = v
	}
	if !p.ports[n] {
		return nil, egErr("SEAL_EGRESS_PORT", 403, "port %d not allowed", n)
	}
	out := &url.URL{Scheme: scheme, Host: host, Path: u.Path, RawPath: u.RawPath, RawQuery: u.RawQuery}
	if strings.Contains(host, ":") {
		out.Host = "[" + host + "]"
	}
	if port != "" {
		out.Host += ":" + port
	}
	if out.Path == "" {
		out.Path = "/"
	}
	return out, nil
}

// Egress is the server side fetcher.
type Egress struct {
	srv      *Server
	Resolver Resolver
	dialer   *net.Dialer
	// DialHook, when set, records every dialled address (tests).
	DialHook func(addr string)

	mu      sync.Mutex
	policy  *egressPolicy
	tr      *http.Transport
	roots   *x509.CertPool
	caFile  string
	hdrWait time.Duration

	lmu    sync.Mutex
	limits map[string]*idLimit

	smu   sync.Mutex
	stats map[statKey]*statVal
}

type idLimit struct {
	tokens  float64
	last    time.Time
	sem     chan struct{}
	sockets int
}

type statKey struct{ id, host string }
type statVal struct {
	n, bytes int64
	codes    map[string]int
}

func newEgress(s *Server) *Egress {
	e := &Egress{srv: s, Resolver: net.DefaultResolver, dialer: &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second},
		limits: map[string]*idLimit{}, stats: map[statKey]*statVal{}}
	e.reload(s.Cfg())
	return e
}

func (e *Egress) reload(c *Config) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policy = newPolicy(c)
	if e.tr == nil || c.EgressCAFile != e.caFile || c.EgressHeaderWait != e.hdrWait {
		e.caFile = c.EgressCAFile
		e.hdrWait = c.EgressHeaderWait
		e.roots = nil
		if c.EgressCAFile != "" {
			pool, err := x509.SystemCertPool()
			if err != nil || pool == nil {
				pool = x509.NewCertPool()
			}
			if pem, err := os.ReadFile(c.EgressCAFile); err == nil {
				pool.AppendCertsFromPEM(pem)
			}
			e.roots = pool
		}
		if e.tr != nil {
			e.tr.CloseIdleConnections()
		}
		e.tr = &http.Transport{
			Proxy:                  nil,
			DialContext:            e.dial,
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: e.roots},
			TLSHandshakeTimeout:    10 * time.Second,
			ResponseHeaderTimeout:  c.EgressHeaderWait,
			ExpectContinueTimeout:  time.Second,
			MaxIdleConns:           64,
			MaxIdleConnsPerHost:    6,
			IdleConnTimeout:        60 * time.Second,
			MaxResponseHeaderBytes: 64 << 10,
			DisableCompression:     true,
			ForceAttemptHTTP2:      true,
		}
	}
}

// Policy returns the live policy.
func (e *Egress) Policy() *egressPolicy {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy
}

func (e *Egress) transport() *http.Transport {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.tr
}

// dial resolves the host, checks every address, and dials a checked one. It
// is the only way the egress client opens connections.
func (e *Egress) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	pol := e.Policy()
	host, portS, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, egErr("SEAL_EGRESS_BAD_URL", 400, "bad address")
	}
	port, err := strconv.Atoi(portS)
	if err != nil || !pol.ports[port] {
		return nil, egErr("SEAL_EGRESS_PORT", 403, "port %s not allowed", portS)
	}
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip}
	} else {
		if !pol.HostAllowed(host) {
			return nil, egErr("SEAL_EGRESS_DENIED", 403, "host is on the deny list")
		}
		lctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		ips, err = e.Resolver.LookupNetIP(lctx, "ip", host)
		cancel()
		if err != nil || len(ips) == 0 {
			return nil, egErr("SEAL_EGRESS_DNS", 502, "name did not resolve")
		}
	}
	var ok []netip.Addr
	for _, ip := range ips {
		if pol.IPAllowed(ip) {
			ok = append(ok, ip.Unmap().WithZone(""))
		}
	}
	if len(ok) == 0 {
		return nil, egErr("SEAL_EGRESS_FORBIDDEN", 403, "address not public")
	}
	var last error
	for i, ip := range ok {
		if i == 3 {
			break
		}
		a := netip.AddrPortFrom(ip, uint16(port)).String()
		if e.DialHook != nil {
			e.DialHook(a)
		}
		c, err := e.dialer.DialContext(ctx, "tcp", a)
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, &EgressError{Code: "SEAL_EGRESS_CONNECT", Status: 502, Msg: "connect failed: " + errText(last)}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 {
		s = s[i+2:]
	}
	return s
}

// asEgressError maps transport errors to stable codes.
func asEgressError(err error) *EgressError {
	var ee *EgressError
	if errors.As(err, &ee) {
		return ee
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return egErr("SEAL_EGRESS_TIMEOUT", 504, "remote timed out")
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return egErr("SEAL_EGRESS_TIMEOUT", 504, "remote timed out")
	}
	var ce *tls.CertificateVerificationError
	if errors.As(err, &ce) {
		return egErr("SEAL_EGRESS_TLS", 502, "remote certificate not trusted")
	}
	if strings.Contains(err.Error(), "tls:") || strings.Contains(err.Error(), "x509:") {
		return egErr("SEAL_EGRESS_TLS", 502, "TLS failed")
	}
	return egErr("SEAL_EGRESS_FAILED", 502, "remote unreachable")
}

// Limits -----------------------------------------------------------------------------

func (e *Egress) lim(id string, c *Config) *idLimit {
	e.lmu.Lock()
	defer e.lmu.Unlock()
	l := e.limits[id]
	if l == nil {
		par := c.EgressParallel
		if par < 1 {
			par = 1
		}
		l = &idLimit{tokens: float64(c.EgressBurst), last: time.Now(), sem: make(chan struct{}, par)}
		e.limits[id] = l
	}
	return l
}

// admit takes a rate token and a concurrency slot; release must be called.
func (e *Egress) admit(ctx context.Context, id string) (func(), *EgressError) {
	c := e.srv.Cfg()
	l := e.lim(id, c)
	e.lmu.Lock()
	now := time.Now()
	l.tokens = math.Min(float64(c.EgressBurst), l.tokens+now.Sub(l.last).Seconds()*c.EgressRate)
	l.last = now
	if l.tokens < 1 {
		e.lmu.Unlock()
		return nil, egErr("SEAL_EGRESS_RATE", 429, "too many egress requests")
	}
	l.tokens--
	e.lmu.Unlock()
	t := time.NewTimer(30 * time.Second)
	defer t.Stop()
	select {
	case l.sem <- struct{}{}:
		return func() { <-l.sem }, nil
	case <-ctx.Done():
		return nil, egErr("SEAL_EGRESS_TIMEOUT", 504, "cancelled while queued")
	case <-t.C:
		return nil, egErr("SEAL_EGRESS_RATE", 429, "too many parallel egress requests")
	}
}

func (e *Egress) admitSocket(id string) (func(), *EgressError) {
	c := e.srv.Cfg()
	l := e.lim(id, c)
	e.lmu.Lock()
	defer e.lmu.Unlock()
	if l.sockets >= c.EgressSockets {
		return nil, egErr("SEAL_EGRESS_RATE", 429, "too many egress sockets")
	}
	l.sockets++
	var once sync.Once
	return func() { once.Do(func() { e.lmu.Lock(); l.sockets--; e.lmu.Unlock() }) }, nil
}

// Logging ------------------------------------------------------------------------------

// IDHash is the short identity hash used in logs.
func IDHash(email string) string {
	h := sha256.Sum256([]byte("dsh-seal/egress " + email))
	return hex.EncodeToString(h[:4])
}

func (e *Egress) record(id, host string, status int, code string, n int64) {
	k := statKey{IDHash(id), host}
	cls := code
	if cls == "" {
		cls = strconv.Itoa(status/100) + "xx"
	}
	e.smu.Lock()
	v := e.stats[k]
	if v == nil {
		if len(e.stats) > 4096 {
			e.smu.Unlock()
			return
		}
		v = &statVal{codes: map[string]int{}}
		e.stats[k] = v
	}
	v.n++
	v.bytes += n
	v.codes[cls]++
	e.smu.Unlock()
	if code != "" {
		e.srv.Log.Info("egress refused", "idh", k.id, "host", host, "code", code)
	}
}

// FlushStats logs one summary line per identity and host and resets.
func (e *Egress) FlushStats(log *slog.Logger) {
	e.smu.Lock()
	st := e.stats
	e.stats = map[statKey]*statVal{}
	e.smu.Unlock()
	keys := make([]statKey, 0, len(st))
	for k := range st {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].id+keys[i].host < keys[j].id+keys[j].host })
	for _, k := range keys {
		v := st[k]
		cs := make([]string, 0, len(v.codes))
		for c, n := range v.codes {
			cs = append(cs, c+"="+strconv.Itoa(n))
		}
		sort.Strings(cs)
		log.Info("egress", "idh", k.id, "host", k.host, "requests", v.n, "bytes", v.bytes, "status", strings.Join(cs, ","))
	}
}

// Requests -------------------------------------------------------------------------------

// egressDropReq are page headers never forwarded to a remote site.
func egressDropReq(k string) bool {
	switch k {
	case "Host", "Cookie", "Cookie2", "Content-Length", "Origin", "Referer", "User-Agent", "Accept-Encoding",
		"Forwarded", "Via", "X-Real-Ip", "True-Client-Ip", "X-Client-Ip", "Accept-Language", "Service-Worker",
		"Purpose", "Dnt", "Priority":
		return true
	}
	if hopByHop[k] {
		return true
	}
	for _, p := range []string{"X-Auth-", "X-Forwarded-", "Cf-", "Sec-", "Proxy-", "Remote-", "X-Seal-"} {
		if strings.HasPrefix(k, p) {
			return true
		}
	}
	return false
}

// egressDropResp are remote response headers never returned to the page.
func egressDropResp(k string) bool {
	switch k {
	case "Set-Cookie", "Set-Cookie2", "Link", "Alt-Svc", "Strict-Transport-Security", "Public-Key-Pins",
		"Public-Key-Pins-Report-Only", "Report-To", "Reporting-Endpoints", "Nel", "Clear-Site-Data",
		"Service-Worker-Allowed", "Refresh", "Expect-Ct", "Origin-Trial", "Accept-Ch", "Critical-Ch":
		return true
	}
	return hopByHop[k]
}

// EgressRequest is one fetch from the page.
type EgressRequest struct {
	Method   string
	URL      string // absolute
	Header   [][2]string
	Body     []byte
	Mode     string // fetch mode of the page request
	Dest     string
	Redirect string // follow (default), error, manual
	Origin   string // page origin (https://dsh.example.com)
	Identity string
}

// EgressResponse is the remote answer (Body must be closed).
type EgressResponse struct {
	Status   int
	Header   http.Header
	Body     io.ReadCloser
	FinalURL string
	Gzip     bool
}

func (e *Egress) buildHeader(r *EgressRequest, target *url.URL) http.Header {
	h := http.Header{}
	for _, kv := range r.Header {
		k := http.CanonicalHeaderKey(strings.TrimSpace(kv[0]))
		if k == "" || egressDropReq(k) || strings.ContainsAny(k, " \r\n:") || strings.ContainsAny(kv[1], "\r\n") {
			continue
		}
		h.Add(k, kv[1])
	}
	h.Set("User-Agent", EgressUA)
	h.Set("Accept-Language", "en-US,en;q=0.9")
	if h.Get("Accept") == "" {
		switch r.Dest {
		case "image":
			h.Set("Accept", "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8")
		case "style":
			h.Set("Accept", "text/css,*/*;q=0.1")
		default:
			h.Set("Accept", "*/*")
		}
	}
	h.Set("Referer", target.Scheme+"://"+target.Host+"/")
	if r.Origin != "" && (r.Mode == "cors" || (r.Method != "GET" && r.Method != "HEAD")) {
		h.Set("Origin", r.Origin)
	}
	h.Set("Sec-Fetch-Site", "cross-site")
	if r.Mode != "" {
		h.Set("Sec-Fetch-Mode", r.Mode)
	}
	if r.Dest != "" {
		h.Set("Sec-Fetch-Dest", r.Dest)
	}
	if h.Get("Range") != "" {
		h.Set("Accept-Encoding", "identity")
	} else {
		h.Set("Accept-Encoding", "gzip")
	}
	return h
}

// Fetch performs one egress request, following redirects (each hop re-checked).
func (e *Egress) Fetch(ctx context.Context, r *EgressRequest) (*EgressResponse, *EgressError) {
	c := e.srv.Cfg()
	if int64(len(r.Body)) > c.EgressMaxReq {
		return nil, egErr("SEAL_EGRESS_TOO_LARGE", 413, "request body too large")
	}
	pol := e.Policy()
	target, ee := pol.NormalizeTarget(r.URL, false)
	if ee != nil {
		return nil, ee
	}
	method, body := r.Method, r.Body
	for hop := 0; ; hop++ {
		var rd io.Reader
		if len(body) > 0 {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, target.String(), rd)
		if err != nil {
			return nil, egErr("SEAL_EGRESS_BAD_URL", 400, "request rejected")
		}
		req.Header = e.buildHeader(r, target)
		if method == "GET" || method == "HEAD" {
			req.Header.Del("Content-Type")
		}
		req.ContentLength = int64(len(body))
		resp, err := e.transport().RoundTrip(req)
		if err != nil {
			return nil, asEgressError(err)
		}
		loc := resp.Header.Get("Location")
		isRedirect := loc != "" && (resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 303 || resp.StatusCode == 307 || resp.StatusCode == 308)
		if !isRedirect || (r.Redirect != "" && r.Redirect != "follow") {
			return e.wrap(resp, target, c, method), nil
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		if hop >= MaxRedirects {
			return nil, egErr("SEAL_EGRESS_REDIRECTS", 502, "too many redirects")
		}
		next, err := target.Parse(loc)
		if err != nil {
			return nil, egErr("SEAL_EGRESS_BAD_URL", 502, "bad redirect")
		}
		nt, ee := pol.NormalizeTarget(next.String(), false)
		if ee != nil {
			return nil, ee
		}
		if resp.StatusCode == 303 || ((resp.StatusCode == 301 || resp.StatusCode == 302) && method == "POST") {
			if method != "HEAD" {
				method = "GET"
			}
			body = nil
		}
		target = nt
	}
}

func (e *Egress) wrap(resp *http.Response, target *url.URL, c *Config, method string) *EgressResponse {
	h := http.Header{}
	for k, vs := range resp.Header {
		if egressDropResp(k) {
			continue
		}
		h[k] = vs
	}
	out := &EgressResponse{Status: resp.StatusCode, Header: h, FinalURL: target.String()}
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") && method != "HEAD" && resp.StatusCode != 204 && resp.StatusCode != 304 {
		out.Gzip = true
		h.Del("Content-Encoding")
		h.Del("Content-Length")
	}
	out.Body = &capReader{rc: resp.Body, left: c.EgressMaxBytes}
	return out
}

// ErrTooLarge ends an egress body that passed the size cap.
var ErrEgressTooLarge = errors.New("SEAL_EGRESS_TOO_LARGE")

// capReader enforces the response size cap and a per-read idle timeout.
type capReader struct {
	rc   io.ReadCloser
	left int64
	n    int64
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.left <= 0 {
		return 0, ErrEgressTooLarge
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.rc.Read(p)
	c.left -= int64(n)
	c.n += int64(n)
	if err == nil && c.left <= 0 {
		// One more byte would exceed the cap: probe.
		var one [1]byte
		m, e2 := c.rc.Read(one[:])
		if m > 0 {
			return n, ErrEgressTooLarge
		}
		if e2 != nil {
			err = e2
		}
	}
	return n, err
}

func (c *capReader) Close() error { return c.rc.Close() }

// idleBody cancels the request when no bytes arrive for d.
type idleBody struct {
	r      io.ReadCloser
	t      *time.Timer
	d      time.Duration
	cancel context.CancelFunc
}

func withIdle(r io.ReadCloser, d time.Duration, cancel context.CancelFunc) *idleBody {
	return &idleBody{r: r, d: d, cancel: cancel, t: time.AfterFunc(d, cancel)}
}

func (b *idleBody) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if n > 0 {
		b.t.Reset(b.d)
	}
	return n, err
}

func (b *idleBody) Close() error {
	b.t.Stop()
	b.cancel()
	return b.r.Close()
}

// WebSockets -----------------------------------------------------------------------------

// DialWS opens a WebSocket to a public wss endpoint through the same guard.
func (e *Egress) DialWS(ctx context.Context, raw string, protocols []string, origin string) (*wsproto.Conn, *wsproto.DialResult, *EgressError) {
	pol := e.Policy()
	target, ee := pol.NormalizeTarget(raw, true)
	if ee != nil {
		return nil, nil, ee
	}
	port := target.Port()
	if port == "" {
		port = "443"
	}
	host := target.Hostname()
	raw0, err := e.dial(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, nil, asEgressError(err)
	}
	e.mu.Lock()
	roots := e.roots
	e.mu.Unlock()
	tc := tls.Client(raw0, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, RootCAs: roots, NextProtos: []string{"http/1.1"}})
	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err = tc.HandshakeContext(hctx)
	cancel()
	if err != nil {
		raw0.Close()
		return nil, nil, asEgressError(err)
	}
	h := http.Header{}
	h.Set("Host", target.Host)
	h.Set("User-Agent", EgressUA)
	if origin != "" {
		h.Set("Origin", origin)
	}
	if len(protocols) > 0 {
		h.Set("Sec-WebSocket-Protocol", strings.Join(protocols, ", "))
	}
	conn, res, err := wsproto.DialConn(ctx, tc, target.Host, target.RequestURI(), h)
	if err != nil {
		return nil, nil, asEgressError(err)
	}
	if conn == nil {
		st := 502
		if res != nil {
			st = res.Status
		}
		return nil, res, egErr("SEAL_EGRESS_REFUSED", st, "remote refused the socket")
	}
	return conn, res, nil
}

// pageOrigin is the origin the page runs on, as the browser would send it.
func pageOrigin(outer *http.Request) string {
	if o := outer.Header.Get("Origin"); o != "" && o != "null" {
		return o
	}
	proto := outer.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		proto = "https"
	}
	return proto + "://" + outer.Host
}

// isAbsoluteURL tells an egress target from a same-origin path.
func isAbsoluteURL(u string) bool {
	l := strings.ToLower(u)
	return strings.HasPrefix(l, "https://") || strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "wss://") || strings.HasPrefix(l, "ws://")
}

// hostOf returns the host of an absolute URL for logs (never the path).
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "?"
	}
	return strings.ToLower(u.Hostname())
}
