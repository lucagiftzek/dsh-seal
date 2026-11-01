// Package server is the dsh-seal HTTP service: a byte-faithful reverse proxy
// in front of dsh-proxy that additionally terminates the sealed endpoints
// under /_s/ (handshake, sealed fetch, sealed WebSocket mux, client scripts).
package server

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dsh-seal/internal/keystore"
	sc "dsh-seal/internal/sealcrypto"
)

// Version of the service (also folded into the client script hash).
const Version = "0.5.0"

// Prefix of every endpoint dsh-seal answers itself.
const Prefix = "/_s/"

// Metrics are plain counters, exported on /_s/health and /_s/metrics.
type Metrics struct {
	Passthrough, WSTunnels, Injected, InjectSkipped                 atomic.Int64
	Handshakes, HandshakeFail, Sealed, SealedFail, Replays          atomic.Int64
	MuxConns, MuxChannels, MuxLive, PlainRefused, NotEligible       atomic.Int64
	BytesIn, BytesOut, UnknownSession, IdentityMismatch, KillWorker atomic.Int64
	Bootstrapped, HardReload, Probes, MuxPings                      atomic.Int64
	Egress, EgressFail, EgressRefused, EgressBytes, EgressSockets   atomic.Int64
}

// Session is one handshake: a master secret bound to the outer identity.
type Session struct {
	ID      []byte
	MS      []byte
	Email   string
	Created time.Time
	mu      sync.Mutex
	last    time.Time
	win     sc.Window
}

// Server is the whole service.
type Server struct {
	cfg     atomic.Pointer[Config]
	Keys    *keystore.Store
	Log     *slog.Logger
	M       Metrics
	started time.Time

	smu      sync.Mutex
	sessions map[string]*Session

	upstream *http.Transport
	proxy    http.Handler
	assets   *assetCache
	Egress   *Egress
}

// New builds a server from a config and an opened key store.
func New(cfg Config, keys *keystore.Store, log *slog.Logger) *Server {
	s := &Server{Keys: keys, Log: log, started: time.Now(), sessions: map[string]*Session{}}
	s.cfg.Store(&cfg)
	s.upstream = &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		DisableCompression:    true,
		MaxIdleConns:          128,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       60 * time.Second,
		ResponseHeaderTimeout: 0,
		ForceAttemptHTTP2:     false,
	}
	s.proxy = s.newProxy()
	s.assets = &assetCache{}
	s.Egress = newEgress(s)
	return s
}

// Cfg returns the live configuration.
func (s *Server) Cfg() *Config { return s.cfg.Load() }

// Reload swaps the configuration (listen and state_dir need a restart).
func (s *Server) Reload(c Config) {
	s.cfg.Store(&c)
	s.assets.reset()
	s.Egress.reload(&c)
}

func (s *Server) identity(r *http.Request) string {
	return strings.ToLower(strings.TrimSpace(r.Header.Get(s.Cfg().IdentityHeader)))
}

// ServeHTTP routes /_s/* to the seal handlers and everything else to the proxy.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, Prefix) {
		s.serveSeal(w, r)
		return
	}
	cfg := s.Cfg()
	if cfg.Mode == ModeRequire && cfg.Eligible(s.identity(r)) && !s.plainAllowed(cfg, r) {
		s.M.PlainRefused.Add(1)
		sealError(w, http.StatusForbidden, "SEAL_PLAIN_REFUSED", "this browser must use the sealed channel")
		return
	}
	s.proxy.ServeHTTP(w, r)
}

func (s *Server) plainAllowed(cfg *Config, r *http.Request) bool {
	p := r.URL.Path
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && matchPath(cfg.ShellPaths, p) {
		return true
	}
	return hasPrefixAny(cfg.PlainPaths, p) || hasPrefixAny(cfg.ExcludePrefixes, p)
}

func sealError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Seal-Error", code)
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"code": code, "message": msg})
}

func (s *Server) serveSeal(w http.ResponseWriter, r *http.Request) {
	cfg := s.Cfg()
	p := r.URL.Path
	switch p {
	case "/_s/health":
		s.serveHealth(w, r)
		return
	case "/_s/metrics":
		s.serveMetrics(w, r)
		return
	case "/_s/p":
		// Network probe of the client: any answer proves the network is up
		// (offer mode falls back to plain only then). Nothing in it.
		s.M.Probes.Add(1)
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	eligible := cfg.Eligible(s.identity(r))
	switch p {
	case "/_s/sw.js":
		// Always answer: in passthrough mode (or for an identity that is not
		// sealed) the answer is a worker that unregisters itself, which is
		// how an installed worker is retired by the kill switch.
		s.serveScript(w, r, "sw", cfg.Mode == ModePassthrough || !eligible)
		return
	}
	if cfg.Mode == ModePassthrough {
		sealError(w, http.StatusNotFound, "SEAL_DISABLED", "dsh-seal is in passthrough mode")
		return
	}
	if !eligible {
		s.M.NotEligible.Add(1)
		sealError(w, http.StatusForbidden, "SEAL_NOT_ELIGIBLE", "sealing is not enabled for this identity")
		return
	}
	switch p {
	case "/_s/boot.js":
		s.serveScript(w, r, "boot", false)
	case "/_s/h":
		s.serveHandshake(w, r)
	case "/_s/x":
		s.serveSealedFetch(w, r)
	case "/_s/ws":
		s.serveMux(w, r)
	default:
		sealError(w, http.StatusNotFound, "SEAL_NOT_FOUND", "no such seal endpoint")
	}
}

// Sessions ---------------------------------------------------------------------

func (s *Server) newSession(sid, ms []byte, email string) {
	now := time.Now()
	sess := &Session{ID: sid, MS: ms, Email: email, Created: now, last: now}
	s.smu.Lock()
	defer s.smu.Unlock()
	if max := s.Cfg().MaxSessions; max > 0 && len(s.sessions) >= max {
		s.evictLocked(len(s.sessions) - max + 1)
	}
	s.sessions[string(sid)] = sess
}

func (s *Server) evictLocked(n int) {
	all := make([]*Session, 0, len(s.sessions))
	for _, v := range s.sessions {
		all = append(all, v)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].lastSeen().Before(all[j].lastSeen()) })
	for i := 0; i < n && i < len(all); i++ {
		delete(s.sessions, string(all[i].ID))
	}
}

func (ss *Session) lastSeen() time.Time {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.last
}

// errSeal carries a stable code and the HTTP status of an outer error.
type errSeal struct {
	status int
	code   string
	msg    string
}

func (e *errSeal) Error() string { return e.code + ": " + e.msg }

// lookup finds a live session, checks it belongs to the same outer identity,
// and claims a fresh stream id in its replay window.
func (s *Server) lookup(sid []byte, stream uint64, email string) (*Session, *errSeal) {
	s.smu.Lock()
	sess := s.sessions[string(sid)]
	s.smu.Unlock()
	ttl := s.Cfg().SessionTTL
	if sess == nil {
		s.M.UnknownSession.Add(1)
		return nil, &errSeal{http.StatusUnauthorized, "SEAL_UNKNOWN_SESSION", "handshake again"}
	}
	if subtle.ConstantTimeCompare([]byte(sess.Email), []byte(email)) != 1 {
		s.M.IdentityMismatch.Add(1)
		return nil, &errSeal{http.StatusForbidden, "SEAL_IDENTITY_MISMATCH", "session belongs to another identity"}
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	now := time.Now()
	if now.Sub(sess.last) > ttl || now.Sub(sess.Created) > 2*ttl {
		s.M.UnknownSession.Add(1)
		return nil, &errSeal{http.StatusUnauthorized, "SEAL_UNKNOWN_SESSION", "session expired, handshake again"}
	}
	if !sess.win.Accept(stream) {
		s.M.Replays.Add(1)
		return nil, &errSeal{http.StatusForbidden, "SEAL_REPLAY", "stream id already used"}
	}
	sess.last = now
	return sess, nil
}

// GC drops idle and over-age sessions. Call it periodically.
func (s *Server) GC() int {
	ttl := s.Cfg().SessionTTL
	now := time.Now()
	s.smu.Lock()
	defer s.smu.Unlock()
	n := 0
	for k, v := range s.sessions {
		if now.Sub(v.lastSeen()) > ttl || now.Sub(v.Created) > 2*ttl {
			delete(s.sessions, k)
			n++
		}
	}
	return n
}

// SessionCount reports the number of live sessions.
func (s *Server) SessionCount() int {
	s.smu.Lock()
	defer s.smu.Unlock()
	return len(s.sessions)
}

// Health -----------------------------------------------------------------------

func (s *Server) counters() map[string]int64 {
	m := &s.M
	return map[string]int64{
		"passthrough": m.Passthrough.Load(), "ws_tunnels": m.WSTunnels.Load(),
		"injected": m.Injected.Load(), "inject_skipped": m.InjectSkipped.Load(),
		"handshakes": m.Handshakes.Load(), "handshake_fail": m.HandshakeFail.Load(),
		"sealed": m.Sealed.Load(), "sealed_fail": m.SealedFail.Load(), "replays": m.Replays.Load(),
		"mux_conns": m.MuxConns.Load(), "mux_channels": m.MuxChannels.Load(), "mux_live": m.MuxLive.Load(),
		"plain_refused": m.PlainRefused.Load(), "not_eligible": m.NotEligible.Load(),
		"bytes_in": m.BytesIn.Load(), "bytes_out": m.BytesOut.Load(),
		"unknown_session": m.UnknownSession.Load(), "identity_mismatch": m.IdentityMismatch.Load(),
		"kill_worker_served": m.KillWorker.Load(), "bootstrapped": m.Bootstrapped.Load(),
		"hard_reload_bootstrap": m.HardReload.Load(), "probes": m.Probes.Load(), "mux_server_pings": m.MuxPings.Load(),
		"egress": m.Egress.Load(), "egress_fail": m.EgressFail.Load(), "egress_refused": m.EgressRefused.Load(),
		"egress_bytes": m.EgressBytes.Load(), "egress_sockets": m.EgressSockets.Load(),
	}
}

func (s *Server) serveHealth(w http.ResponseWriter, r *http.Request) {
	cfg := s.Cfg()
	b := s.Keys.Bundle()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{
		"ok": true, "service": "dsh-seal", "version": Version, "mode": cfg.Mode, "egress": cfg.Egress,
		"upstream": cfg.Upstream, "fingerprint": b.FP, "kid": b.KX.KID,
		"kx_expires": time.Unix(int64(b.KX.Exp), 0).UTC().Format(time.RFC3339),
		"sessions":   s.SessionCount(), "uptime_s": int(time.Since(s.started).Seconds()),
		"counters": s.counters(),
	})
}

func (s *Server) serveMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	c := s.counters()
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(w, "dsh_seal_%s %d\n", k, c[k])
	}
	fmt.Fprintf(w, "dsh_seal_sessions %d\n", s.SessionCount())
}
