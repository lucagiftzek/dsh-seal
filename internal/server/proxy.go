package server

import (
	"bytes"
	"compress/gzip"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"

	"dsh-seal/internal/wsproto"
)

type ctxKey int

const injectKey ctxKey = 1

// injectState travels from Rewrite to ModifyResponse for shell requests.
type injectState struct {
	clientGzip bool
	bootstrap  bool // browser has no seal client yet: serve the bootstrap page
	hard       bool // ... or it did a hard reload (not controlled by its worker)
}

// SealCookie marks a browser that already ran boot.js. Without it, a shell
// request gets the bootstrap page (boot.js only), so the first visit never
// loads DSH code in plain before the service worker is in control. The name
// avoids "dsh": dsh-proxy treats any cookie containing "dsh" as a session.
const SealCookie = "sealboot"

// ReloadCookie is set by boot.js for about 30 s right before it reloads a page
// the service worker did not control (a hard reload): that reload gets the
// real shell even when it also carries no-cache (DevTools "Disable cache").
const ReloadCookie = "sealhr"

// hardReload: a hard reload (Shift reload, Cmd+Shift+R, Ctrl+F5) bypasses the
// service worker; Chrome, Firefox and Safari send no-cache on it, a normal
// reload sends max-age=0 or nothing.
func hardReload(h http.Header) bool {
	if strings.Contains(strings.ToLower(h.Get("Pragma")), "no-cache") {
		return true
	}
	for _, d := range strings.Split(strings.ToLower(h.Get("Cache-Control")), ",") {
		if strings.TrimSpace(d) == "no-cache" {
			return true
		}
	}
	return false
}

func hasSealCookie(h http.Header) bool { return hasCookie(h, SealCookie) }

func hasCookie(h http.Header, name string) bool {
	for _, c := range (&http.Request{Header: h}).Cookies() {
		if c.Name == name {
			return true
		}
	}
	return false
}

// stripSealCookie removes our own marker cookie before a request goes upstream.
func stripSealCookie(h http.Header) {
	vals := h.Values("Cookie")
	if len(vals) == 0 {
		return
	}
	var keep []string
	for _, v := range vals {
		for _, part := range strings.Split(v, ";") {
			p := strings.TrimSpace(part)
			if p == "" || strings.HasPrefix(p, SealCookie+"=") || strings.HasPrefix(p, ReloadCookie+"=") {
				continue
			}
			keep = append(keep, p)
		}
	}
	h.Del("Cookie")
	if len(keep) > 0 {
		h.Set("Cookie", strings.Join(keep, "; "))
	}
}

func (s *Server) newProxy() http.Handler {
	rp := &httputil.ReverseProxy{
		Transport:     s.upstream,
		FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			cfg := s.Cfg()
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = cfg.Upstream
			pr.Out.Host = pr.In.Host
			// Rewrite mode strips the inbound X-Forwarded-* headers; put the
			// originals back unchanged and add X-Forwarded-For only when the
			// caller sent none, so dsh-proxy sees what traefik sent.
			for _, h := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
				if v, ok := pr.In.Header[h]; ok {
					pr.Out.Header[h] = v
				}
			}
			stripSealCookie(pr.Out.Header)
			if _, ok := pr.In.Header["X-Forwarded-For"]; !ok {
				if ip, _, err := net.SplitHostPort(pr.In.RemoteAddr); err == nil {
					pr.Out.Header.Set("X-Forwarded-For", ip)
				}
			}
			if st, ok := pr.In.Context().Value(injectKey).(*injectState); ok && st != nil {
				// Only gzip or identity can be decoded with the standard library.
				pr.Out.Header.Set("Accept-Encoding", "gzip")
			}
		},
		ModifyResponse: s.modifyResponse,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.Log.Warn("upstream error", "code", "SEAL_UPSTREAM_DOWN", "path", r.URL.Path, "err", err)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			io.WriteString(w, "dsh-seal: upstream unreachable (SEAL_UPSTREAM_DOWN)\n")
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := s.Cfg()
		if wsproto.IsUpgrade(r) {
			s.M.WSTunnels.Add(1)
		} else {
			s.M.Passthrough.Add(1)
		}
		if cfg.Mode != ModePassthrough && r.Method == http.MethodGet && matchPath(cfg.ShellPaths, r.URL.Path) && cfg.Eligible(s.identity(r)) && !wsproto.IsUpgrade(r) {
			// A browser with the seal client that hard-reloads is not controlled
			// by its worker for this page view: it gets the bootstrap page too,
			// so no DSH code or asset loads in plain; boot.js then does a normal
			// reload, which the worker controls.
			hard := hasSealCookie(r.Header) && hardReload(r.Header) && !hasCookie(r.Header, ReloadCookie)
			st := &injectState{clientGzip: acceptsGzip(r.Header.Get("Accept-Encoding")), bootstrap: !hasSealCookie(r.Header) || hard, hard: hard}
			r = r.WithContext(contextWith(r, st))
		}
		rp.ServeHTTP(w, r)
	})
}

func acceptsGzip(ae string) bool {
	for _, p := range strings.Split(ae, ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(p), ";")
		if strings.EqualFold(strings.TrimSpace(name), "gzip") {
			params = strings.ReplaceAll(params, " ", "")
			if q, ok := strings.CutPrefix(params, "q="); ok {
				f, err := strconv.ParseFloat(q, 64)
				return err == nil && f > 0
			}
			return true
		}
	}
	return false
}

// maxShell bounds how much of an HTML shell is buffered for injection.
const maxShell = 16 << 20

func (s *Server) modifyResponse(resp *http.Response) error {
	st, ok := resp.Request.Context().Value(injectKey).(*injectState)
	if !ok || st == nil {
		return nil
	}
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") {
		return nil
	}
	enc := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	if enc != "" && enc != "identity" && enc != "gzip" {
		s.M.InjectSkipped.Add(1)
		s.Log.Warn("shell not injected", "code", "SEAL_INJECT_SKIPPED", "encoding", enc)
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxShell+1))
	if err != nil {
		return err
	}
	if len(raw) > maxShell {
		s.M.InjectSkipped.Add(1)
		resp.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(raw), resp.Body), resp.Body}
		return nil
	}
	resp.Body.Close()
	html := raw
	if enc == "gzip" {
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err == nil {
			html, err = io.ReadAll(io.LimitReader(zr, 4*maxShell))
		}
		if err != nil {
			s.M.InjectSkipped.Add(1)
			s.Log.Warn("shell not injected", "code", "SEAL_INJECT_SKIPPED", "err", err)
			resp.Body = io.NopCloser(bytes.NewReader(raw))
			return nil
		}
	}
	out := InjectBoot(NeutralizeHints(html, resp.Request.Host), s.bootTag(resp.Request))
	dropHintLinks(resp.Header)
	if st.bootstrap {
		// rel=icon data: stops the browser from asking for /favicon.ico in plain
		out = []byte(`<!doctype html><html><head><meta name="dsh-seal-bootstrap" content="1"><link rel="icon" href="data:,">` + string(s.bootTag(resp.Request)) + `</head><body></body></html>`)
		s.M.Bootstrapped.Add(1)
		if st.hard {
			s.M.HardReload.Add(1)
		}
	}
	resp.Header.Del("Content-Encoding")
	if st.clientGzip {
		var b bytes.Buffer
		zw, _ := gzip.NewWriterLevel(&b, gzip.BestSpeed)
		zw.Write(out)
		zw.Close()
		out = b.Bytes()
		resp.Header.Set("Content-Encoding", "gzip")
	}
	resp.Header.Del("ETag")
	resp.Header.Del("Last-Modified")
	resp.Header.Del("Content-Length")
	resp.Header.Set("Cache-Control", "no-store")
	resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
	resp.ContentLength = int64(len(out))
	resp.TransferEncoding = nil
	resp.Body = io.NopCloser(bytes.NewReader(out))
	s.M.Injected.Add(1)
	return nil
}

func (s *Server) bootTag(r *http.Request) []byte {
	return []byte(`<meta http-equiv="x-dns-prefetch-control" content="off"><script src="/_s/boot.js?v=` + s.assets.hash(s, "boot", s.Cfg().EgressFor(s.identity(r))) + `"></script>`)
}

// InjectBoot puts tag as the first element inside <head>. It tolerates a UTF-8
// BOM, any letter case, attributes on <head>, and a missing <head> (a head is
// created after <html>, or at the very start when there is no <html> either).
func InjectBoot(html, tag []byte) []byte {
	start := 0
	if bytes.HasPrefix(html, []byte("\xEF\xBB\xBF")) {
		start = 3
	}
	lower := bytes.ToLower(html)
	if i := findTag(lower, start, "head"); i >= 0 {
		if j := bytes.IndexByte(lower[i:], '>'); j >= 0 {
			at := i + j + 1
			return splice(html, at, tag)
		}
	}
	wrapped := append(append([]byte("<head>"), tag...), "</head>"...)
	if i := findTag(lower, start, "html"); i >= 0 {
		if j := bytes.IndexByte(lower[i:], '>'); j >= 0 {
			return splice(html, i+j+1, wrapped)
		}
	}
	// No <html>: keep a doctype first if present.
	if bytes.HasPrefix(lower[start:], []byte("<!doctype")) {
		if j := bytes.IndexByte(lower[start:], '>'); j >= 0 {
			return splice(html, start+j+1, tag)
		}
	}
	return splice(html, start, tag)
}

// findTag returns the index of "<name" followed by '>' or whitespace, skipping
// comments, so "<header>" never matches "head".
func findTag(lower []byte, from int, name string) int {
	pat := []byte("<" + name)
	i := from
	for {
		k := bytes.Index(lower[i:], pat)
		if k < 0 {
			return -1
		}
		k += i
		if c := bytes.Index(lower[i:k], []byte("<!--")); c >= 0 {
			end := bytes.Index(lower[i+c:], []byte("-->"))
			if end < 0 {
				return -1
			}
			i = i + c + end + 3
			continue
		}
		n := k + len(pat)
		if n < len(lower) {
			switch lower[n] {
			case '>', ' ', '\t', '\n', '\r', '/':
				return k
			}
		}
		i = n
	}
}

func splice(b []byte, at int, ins []byte) []byte {
	out := make([]byte, 0, len(b)+len(ins))
	out = append(out, b[:at]...)
	out = append(out, ins...)
	return append(out, b[at:]...)
}
