// Command fakeedge stands in for a reverse proxy plus an auth gateway in the loopback browser
// tests: it sets X-Auth-Email on EVERY request (as an auth gateway's forwardAuth does),
// proxies to dsh-seal (WebSocket upgrades included) and writes one line per
// request to a log: that log is exactly what an observer between the browser
// and the server would see as request lines. Token values are redacted.
//
//	fakeedge -listen 127.0.0.1:3083 -upstream 127.0.0.1:3082 -email alice@example.com -log /var/tmp/edge.log
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"regexp"
	"sync"
	"time"
)

var tokenRE = regexp.MustCompile(`token=[A-Za-z0-9_-]+`)

func main() {
	listen := flag.String("listen", "127.0.0.1:3083", "listen address")
	upstream := flag.String("upstream", "127.0.0.1:3082", "dsh-seal address")
	email := flag.String("email", "alice@example.com", "identity to assert")
	logPath := flag.String("log", "/var/tmp/fakeedge.log", "request log")
	flag.Parse()
	f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		log.Fatal(err)
	}
	var mu sync.Mutex
	rp := &httputil.ReverseProxy{
		FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = *upstream
			pr.Out.Host = pr.In.Host
			pr.Out.Header.Del("X-Auth-Email")
			pr.Out.Header.Set("X-Auth-Email", *email)
			pr.SetXForwarded()
		},
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := ""
		if r.Header.Get("Upgrade") != "" {
			up = " upgrade=" + r.Header.Get("Upgrade")
		}
		mu.Lock()
		fmt.Fprintf(f, "%d %s %s len=%d%s\n", time.Now().UnixMilli(), r.Method, tokenRE.ReplaceAllString(r.URL.RequestURI(), "token=<redacted>"), r.ContentLength, up)
		mu.Unlock()
		rp.ServeHTTP(w, r)
	})
	log.Fatal(http.ListenAndServe(*listen, h))
}
