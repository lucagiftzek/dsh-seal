package server

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"dsh-seal/client"
	sc "dsh-seal/internal/sealcrypto"
)

// clientCfg is embedded in boot.js and sw.js next to the key bundle.
type clientCfg struct {
	Mode       string   `json:"mode"`
	Shell      []string `json:"shell"`
	Exclude    []string `json:"exclude"`
	SealedOnly bool     `json:"sealedOnly"`
	Version    string   `json:"version"`
	Egress     bool     `json:"egress"`
	WebRTC     string   `json:"webrtc"`
}

type assetCache struct {
	mu    sync.Mutex
	key   string
	items map[string][]byte
	tags  map[string]string
}

func (a *assetCache) reset() {
	a.mu.Lock()
	a.key = ""
	a.mu.Unlock()
}

// build returns the script body and its short hash. The cache is keyed on the
// key bundle and the mode, so a rotation or reload changes the scripts.
func (a *assetCache) build(s *Server, name string, egress bool) ([]byte, string) {
	cfg := s.Cfg()
	if egress {
		name0 := name
		name = name0 + "+egress"
	}
	base := strings.TrimSuffix(name, "+egress")
	b := s.Keys.Bundle()
	key := b.KX.KID + "|" + b.FP + "|" + cfg.Mode
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.key != key {
		a.key = key
		a.items = map[string][]byte{}
		a.tags = map[string]string{}
	}
	if v, ok := a.items[name]; ok {
		return v, a.tags[name]
	}
	var body []byte
	switch base {
	case "sw-kill":
		body = client.KillSW
	default:
		conf := struct {
			Bundle any       `json:"bundle"`
			Cfg    clientCfg `json:"cfg"`
		}{b, clientCfg{Mode: cfg.Mode, Shell: cfg.ShellPaths, Exclude: cfg.ExcludePrefixes, SealedOnly: cfg.Mode == ModeRequire, Version: Version, Egress: egress, WebRTC: cfg.EgressWebRTC}}
		j, _ := json.Marshal(conf)
		code := client.Boot
		if base == "sw" {
			code = client.SW
		}
		body = append([]byte("self.__DSH_SEAL_CFG="), j...)
		body = append(body, ";\n"...)
		body = append(body, code...)
	}
	h := sha256.Sum256(body)
	tag := sc.B64.EncodeToString(h[:9])
	a.items[name], a.tags[name] = body, tag
	return body, tag
}

func (a *assetCache) hash(s *Server, name string, egress bool) string {
	_, t := a.build(s, name, egress)
	return t
}

func (s *Server) serveScript(w http.ResponseWriter, r *http.Request, name string, kill bool) {
	if kill {
		name = "sw-kill"
		s.M.KillWorker.Add(1)
	}
	body, tag := s.assets.build(s, name, name != "sw-kill" && s.Cfg().EgressFor(s.identity(r)))
	etag := `"` + tag + `"`
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", etag)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if name != "boot" {
		w.Header().Set("Service-Worker-Allowed", "/")
	}
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Write(body)
}
