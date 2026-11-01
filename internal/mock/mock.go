// Package mock is an upstream that imitates DSH for the tests and the end to
// end harness: an HTML shell at "/", JSON echo APIs, an SSE stream, large and
// gzip bodies, redirects, cookies and a WebSocket echo.
package mock

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"dsh-seal/internal/wsproto"
)

// Shell is the HTML the mock serves at "/" (shaped like the DSH shell).
const Shell = "<!doctype html>\n<html lang=\"en\">\n  <head><base href=\"./\"><style>body{background:#151517}</style><script>window.__MOCK_INLINE__=1</script>\n<script type=\"module\" src=\"./assets/app.js\"></script></head>\n<body><div id=\"app\">mock dsh</div></body></html>\n"

// AppJS is served at /assets/app.js: it exercises fetch, WebSocket and
// EventSource like the real GUI does, and records results on window.__mock.
const AppJS = `window.__mock = {fetch:null, ws:null, sse:[]};
fetch('./api/echo?q=hello%20world', {headers:{'x-test':'1'}}).then(r=>r.json()).then(j=>{window.__mock.fetch=j});
const ws = new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host+'/ws/echo');
ws.onopen=()=>ws.send('ping-from-page');
ws.onmessage=(e)=>{window.__mock.ws=e.data};
const es = new EventSource('/api/sse?n=3&ms=50');
es.onmessage=(e)=>{window.__mock.sse.push(e.data); if(window.__mock.sse.length>=3) es.close()};
`

// Handler returns the mock upstream.
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("ETag", `"shell-1"`)
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			zw := gzip.NewWriter(w)
			io.WriteString(zw, Shell)
			zw.Close()
			return
		}
		io.WriteString(w, Shell)
	})
	mux.HandleFunc("/remote/img.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Header().Set("Set-Cookie", "track=1; Path=/")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		io.WriteString(w, "\x89PNG remote")
	})
	mux.HandleFunc("/remote/media.bin", func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 1<<20)
		for i := range b {
			b[i] = byte(i)
		}
		http.ServeContent(w, r, "media.bin", time.Unix(0, 0), bytes.NewReader(b))
	})
	mux.HandleFunc("/remote/to", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Query().Get("u"), http.StatusFound)
	})
	mux.HandleFunc("/assets/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		io.WriteString(w, AppJS)
	})
	mux.HandleFunc("/report/x.html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, "<html><head><title>report</title></head><body>r</body></html>")
	})
	mux.HandleFunc("/api/echo", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		h := sha256.Sum256(body)
		hdr := map[string]string{}
		for k := range r.Header {
			hdr[k] = r.Header.Get(k)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Mock", "echo")
		json.NewEncoder(w).Encode(map[string]any{
			"method": r.Method, "path": r.URL.Path, "query": r.URL.RawQuery, "host": r.Host,
			"headers": hdr, "len": len(body), "sha256": hex.EncodeToString(h[:]),
			"contentLength": r.ContentLength, "chunked": len(r.TransferEncoding) > 0,
		})
	})
	mux.HandleFunc("/api/gzip", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		payload := []byte(`{"gzip":true,"pad":"` + strings.Repeat("abc", 2000) + `"}`)
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			var b bytes.Buffer
			zw := gzip.NewWriter(&b)
			zw.Write(payload)
			zw.Close()
			w.Header().Set("Content-Length", strconv.Itoa(b.Len()))
			w.Write(b.Bytes())
			return
		}
		w.Write(payload)
	})
	mux.HandleFunc("/api/big", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		w.Header().Set("Content-Type", "application/octet-stream")
		buf := make([]byte, 32<<10)
		for i := range buf {
			buf[i] = byte(i * 7)
		}
		for n > 0 {
			k := min(n, len(buf))
			w.Write(buf[:k])
			n -= k
		}
	})
	mux.HandleFunc("/api/sse", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		ms, _ := strconv.Atoi(r.URL.Query().Get("ms"))
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		fl := w.(http.Flusher)
		io.WriteString(w, ": hello\n\n")
		fl.Flush()
		for i := 0; i < n; i++ {
			fmt.Fprintf(w, "id: %d\nevent: %s\ndata: tick %d\ndata: at %d\n\n", i+1, map[bool]string{true: "message", false: "named"}[i%2 == 0], i, time.Now().UnixMilli())
			fl.Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(time.Duration(ms) * time.Millisecond):
			}
		}
	})
	mux.HandleFunc("/api/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/api/echo?from=redirect", http.StatusFound)
	})
	mux.HandleFunc("/api/cookie", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "mockc", Value: "v1", Path: "/"})
		w.WriteHeader(204)
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		c, _ := strconv.Atoi(r.URL.Query().Get("c"))
		w.WriteHeader(c)
		if c != 204 && c != 304 {
			io.WriteString(w, "status body")
		}
	})
	mux.HandleFunc("/ws/", func(w http.ResponseWriter, r *http.Request) {
		proto := ""
		if p := r.Header.Get("Sec-WebSocket-Protocol"); p != "" {
			proto = strings.TrimSpace(strings.Split(p, ",")[0])
		}
		if r.Header.Get("X-Deny") != "" || r.URL.Path == "/ws/deny" {
			http.Error(w, "denied", 403)
			return
		}
		c, err := wsproto.Accept(w, r, proto)
		if err != nil {
			return
		}
		defer c.Close()
		// The first message tells the client who it is (identity survives).
		hello, _ := json.Marshal(map[string]string{"hello": r.Header.Get("X-Auth-Email"), "path": r.URL.RequestURI(), "origin": r.Header.Get("Origin"), "proto": proto, "cookie": r.Header.Get("Cookie"), "host": r.Host, "xfp": r.Header.Get("X-Forwarded-Proto")})
		if r.URL.Query().Get("hello") == "1" {
			c.WriteMessage(wsproto.OpText, hello)
		}
		for {
			op, msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			if op == wsproto.OpText && string(msg) == "close-me" {
				c.WriteClose(4001, "asked")
				return
			}
			if op == wsproto.OpText && strings.HasPrefix(string(msg), "burst ") {
				n, _ := strconv.Atoi(strings.TrimPrefix(string(msg), "burst "))
				for i := 0; i < n; i++ {
					c.WriteMessage(wsproto.OpText, []byte(fmt.Sprintf("b%d", i)))
				}
				continue
			}
			if err := c.WriteMessage(op, msg); err != nil {
				return
			}
		}
	})
	return mux
}
