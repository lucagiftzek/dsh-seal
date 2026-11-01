// Command sealbench measures what dsh-seal adds per request against a live
// upstream: direct (dsh-proxy), pass-through (via dsh-seal, plain) and sealed
// (via dsh-seal /_s/x with the Go client). The launch token is read from the
// DSH_TOKEN environment variable and never printed.
//
//	sealbench -direct http://127.0.0.1:3081 -seal http://127.0.0.1:3082 -n 200 -path /manifest.webmanifest
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"sort"
	"strings"
	"time"

	"dsh-seal/internal/sealclient"
)

func main() {
	direct := flag.String("direct", "http://127.0.0.1:3081", "upstream base")
	seal := flag.String("seal", "http://127.0.0.1:3082", "dsh-seal base")
	n := flag.Int("n", 200, "requests per mode")
	paths := flag.String("path", "/manifest.webmanifest", "comma separated paths")
	email := flag.String("email", "alice@example.com", "X-Auth-Email to send")
	flag.Parse()
	h := http.Header{}
	h.Set("X-Auth-Email", *email)
	ctx := context.Background()
	client := func(base string) *http.Client {
		jar, _ := cookiejar.New(nil)
		c := &http.Client{Jar: jar, Transport: &http.Transport{DisableCompression: true, MaxIdleConnsPerHost: 4}}
		if tok := os.Getenv("DSH_TOKEN"); tok != "" {
			req, _ := http.NewRequest("GET", base+"/?token="+tok, nil)
			req.Header = h.Clone()
			if r, err := c.Do(req); err == nil {
				io.Copy(io.Discard, r.Body)
				r.Body.Close()
			}
		}
		return c
	}
	cd, cs := client(*direct), client(*seal)
	b, err := sealclient.Bundle(ctx, cs, *seal, h)
	if err != nil {
		fmt.Println("bundle:", err)
		os.Exit(1)
	}
	t0 := time.Now()
	sess, _, err := sealclient.Handshake(ctx, cs, *seal, h, b, "")
	if err != nil {
		fmt.Println("handshake:", err)
		os.Exit(1)
	}
	fmt.Printf("handshake: %.2f ms\n", float64(time.Since(t0).Microseconds())/1000)
	// the sealed client must carry the same cookies as a browser would
	sealURL, _ := http.NewRequest("GET", *seal+"/", nil)
	var ck []string
	for _, c := range cs.Jar.Cookies(sealURL.URL) {
		ck = append(ck, c.Name+"="+c.Value)
	}
	if len(ck) > 0 {
		sess.Header.Set("Cookie", strings.Join(ck, "; "))
	}
	for _, p := range strings.Split(*paths, ",") {
		plain := func(c *http.Client, base string) func() (int, int64) {
			return func() (int, int64) {
				req, _ := http.NewRequest("GET", base+p, nil)
				req.Header = h.Clone()
				r, err := c.Do(req)
				if err != nil {
					return 0, 0
				}
				nb, _ := io.Copy(io.Discard, r.Body)
				r.Body.Close()
				return r.StatusCode, nb
			}
		}
		sealed := func() (int, int64) {
			r, err := sess.Do(ctx, &sealclient.Request{Method: "GET", Path: p})
			if err != nil || r.Body == nil {
				return 0, 0
			}
			nb, _ := io.Copy(io.Discard, r.Body)
			r.Body.Close()
			return r.Status, nb
		}
		fmt.Printf("\npath %s (n=%d, sequential)\n", p, *n)
		var base50 float64
		for _, m := range []struct {
			name string
			f    func() (int, int64)
		}{{"direct dsh-proxy", plain(cd, *direct)}, {"via dsh-seal plain", plain(cs, *seal)}, {"via dsh-seal sealed", sealed}} {
			m.f() // warm up
			lat := make([]float64, 0, *n)
			var status int
			var size int64
			start := time.Now()
			for i := 0; i < *n; i++ {
				t := time.Now()
				status, size = m.f()
				lat = append(lat, float64(time.Since(t).Microseconds())/1000)
			}
			total := time.Since(start)
			sort.Float64s(lat)
			p50, p95 := lat[len(lat)/2], lat[len(lat)*95/100]
			if base50 == 0 {
				base50 = p50
			}
			fmt.Printf("  %-20s status %d size %7d  p50 %7.2f ms  p95 %7.2f ms  added p50 %+6.2f ms  %.1f MB/s\n", m.name, status, size, p50, p95, p50-base50, float64(size)*float64(*n)/total.Seconds()/1e6)
		}
	}
}
