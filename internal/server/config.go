package server

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Modes.
const (
	ModePassthrough = "passthrough"
	ModeOffer       = "offer"
	ModeRequire     = "require"
)

// Config is the runtime configuration. It is immutable once built; a reload
// swaps the whole value.
type Config struct {
	Listen          string
	Upstream        string
	Mode            string
	StateDir        string
	Identities      []string // lower case emails, "*" = everyone
	SealAnonymous   bool     // seal requests without X-Auth-Email (loopback tests)
	ShellPaths      []string // exact paths, or prefixes ending in "*"
	ExcludePrefixes []string // never sealed by the client (other traefik services)
	PlainPaths      []string // allowed in plain even in require mode (prefix match)
	KXRotate        time.Duration
	SessionTTL      time.Duration
	MaxSessions     int
	MaxBody         int64
	MuxWindow       int64
	IdentityHeader  string

	// Sealed egress (cross-origin requests fetched by the server).
	Egress           bool
	EgressIdentities []string // "*" = every sealed identity
	EgressDenyHosts  []string // host suffixes refused (lower case)
	EgressDenyCIDRs  []string // extra address ranges refused
	EgressPorts      []int    // allowed ports besides 443
	EgressMaxBytes   int64    // response body cap
	EgressMaxReq     int64    // request body cap
	EgressRate       float64  // requests per second per identity
	EgressBurst      int
	EgressParallel   int    // concurrent requests per identity
	EgressSockets    int    // concurrent egress sockets per identity
	EgressWebRTC     string // "block" or "allow" (client side)
	EgressHeaderWait time.Duration
	// Test only: ranges treated as public and an extra CA file (e2e TLS mock).
	EgressUnsafeAllow []string
	EgressCAFile      string
}

// Defaults returns the built-in configuration (passthrough: nothing changes).
func Defaults() Config {
	return Config{
		Listen:           "127.0.0.1:3082",
		Upstream:         "127.0.0.1:3081",
		Mode:             ModePassthrough,
		StateDir:         os.ExpandEnv("$HOME/.local/state/dsh-seal"),
		Identities:       nil,
		ShellPaths:       []string{"/"},
		ExcludePrefixes:  nil,
		PlainPaths:       []string{"/favicon.svg", "/favicon-dark.svg", "/favicon.ico", "/manifest.webmanifest", "/report-public/"},
		KXRotate:         7 * 24 * time.Hour,
		SessionTTL:       24 * time.Hour,
		MaxSessions:      20000,
		MaxBody:          256 << 20,
		MuxWindow:        4 << 20,
		IdentityHeader:   "X-Auth-Email",
		Egress:           true,
		EgressIdentities: []string{"*"},
		EgressMaxBytes:   50 << 20,
		EgressMaxReq:     16 << 20,
		EgressRate:       30,
		EgressBurst:      300,
		EgressParallel:   48,
		EgressSockets:    32,
		EgressWebRTC:     "block",
		EgressHeaderWait: 30 * time.Second,
	}
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Set applies one key=value setting.
func (c *Config) Set(k, v string) error {
	v = strings.TrimSpace(v)
	var err error
	switch strings.ToLower(strings.TrimSpace(k)) {
	case "listen":
		c.Listen = v
	case "upstream":
		c.Upstream = v
	case "mode":
		switch v {
		case ModePassthrough, ModeOffer, ModeRequire:
			c.Mode = v
		default:
			return fmt.Errorf("SEAL_CONFIG: mode must be passthrough, offer or require, not %q", v)
		}
	case "state_dir":
		c.StateDir = os.ExpandEnv(v)
	case "identities":
		c.Identities = nil
		for _, e := range splitList(v) {
			c.Identities = append(c.Identities, strings.ToLower(e))
		}
	case "seal_anonymous":
		c.SealAnonymous, err = strconv.ParseBool(v)
	case "shell_paths":
		c.ShellPaths = splitList(v)
	case "exclude_prefixes":
		c.ExcludePrefixes = splitList(v)
	case "plain_paths":
		c.PlainPaths = splitList(v)
	case "kx_rotate":
		c.KXRotate, err = time.ParseDuration(v)
	case "session_ttl":
		c.SessionTTL, err = time.ParseDuration(v)
	case "max_sessions":
		c.MaxSessions, err = strconv.Atoi(v)
	case "max_body":
		c.MaxBody, err = strconv.ParseInt(v, 10, 64)
	case "mux_window":
		c.MuxWindow, err = strconv.ParseInt(v, 10, 64)
	case "identity_header":
		c.IdentityHeader = v
	case "egress":
		switch strings.ToLower(v) {
		case "on", "true", "1", "yes":
			c.Egress = true
		case "off", "false", "0", "no":
			c.Egress = false
		default:
			return fmt.Errorf("SEAL_CONFIG: egress must be on or off, not %q", v)
		}
	case "egress_identities":
		c.EgressIdentities = nil
		for _, e := range splitList(v) {
			c.EgressIdentities = append(c.EgressIdentities, strings.ToLower(e))
		}
	case "egress_deny_hosts":
		c.EgressDenyHosts = nil
		for _, e := range splitList(v) {
			c.EgressDenyHosts = append(c.EgressDenyHosts, strings.Trim(strings.ToLower(e), "."))
		}
	case "egress_deny_cidrs":
		c.EgressDenyCIDRs = splitList(v)
	case "egress_unsafe_allow_nets":
		c.EgressUnsafeAllow = splitList(v)
	case "egress_ca_file":
		c.EgressCAFile = v
	case "egress_ports":
		c.EgressPorts = nil
		for _, p := range splitList(v) {
			n, e := strconv.Atoi(p)
			if e != nil || n < 1 || n > 65535 {
				return fmt.Errorf("SEAL_CONFIG: egress_ports: bad port %q", p)
			}
			c.EgressPorts = append(c.EgressPorts, n)
		}
	case "egress_max_bytes":
		c.EgressMaxBytes, err = strconv.ParseInt(v, 10, 64)
	case "egress_max_request":
		c.EgressMaxReq, err = strconv.ParseInt(v, 10, 64)
	case "egress_rate":
		c.EgressRate, err = strconv.ParseFloat(v, 64)
	case "egress_burst":
		c.EgressBurst, err = strconv.Atoi(v)
	case "egress_parallel":
		c.EgressParallel, err = strconv.Atoi(v)
	case "egress_sockets":
		c.EgressSockets, err = strconv.Atoi(v)
	case "egress_header_timeout":
		c.EgressHeaderWait, err = time.ParseDuration(v)
	case "egress_webrtc":
		if v != "block" && v != "allow" {
			return fmt.Errorf("SEAL_CONFIG: egress_webrtc must be block or allow, not %q", v)
		}
		c.EgressWebRTC = v
	default:
		return fmt.Errorf("SEAL_CONFIG: unknown key %q", k)
	}
	if err != nil {
		return fmt.Errorf("SEAL_CONFIG: %s: %w", k, err)
	}
	return nil
}

// Load reads defaults, then the file (key=value lines, # comments), then the
// environment (DSH_SEAL_<KEY>, e.g. DSH_SEAL_MODE).
func Load(path string) (Config, error) {
	c := Defaults()
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return c, fmt.Errorf("SEAL_CONFIG: %w", err)
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		n := 0
		for sc.Scan() {
			n++
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				return c, fmt.Errorf("SEAL_CONFIG: %s:%d: expected key=value", path, n)
			}
			if err := c.Set(k, v); err != nil {
				return c, fmt.Errorf("%s:%d: %w", path, n, err)
			}
		}
		if err := sc.Err(); err != nil {
			return c, err
		}
	}
	for _, k := range []string{"listen", "upstream", "mode", "state_dir", "identities", "seal_anonymous", "shell_paths", "exclude_prefixes", "plain_paths", "kx_rotate", "session_ttl", "max_sessions", "max_body", "mux_window", "identity_header", "egress", "egress_identities", "egress_deny_hosts", "egress_deny_cidrs", "egress_ports", "egress_max_bytes", "egress_max_request", "egress_rate", "egress_burst", "egress_parallel", "egress_sockets", "egress_webrtc", "egress_header_timeout", "egress_unsafe_allow_nets", "egress_ca_file"} {
		if v, ok := os.LookupEnv("DSH_SEAL_" + strings.ToUpper(k)); ok {
			if err := c.Set(k, v); err != nil {
				return c, err
			}
		}
	}
	return c, nil
}

func matchPath(list []string, p string) bool {
	for _, e := range list {
		if strings.HasSuffix(e, "*") {
			if strings.HasPrefix(p, strings.TrimSuffix(e, "*")) {
				return true
			}
		} else if p == e {
			return true
		}
	}
	return false
}

func hasPrefixAny(list []string, p string) bool {
	for _, e := range list {
		if strings.HasPrefix(p, e) {
			return true
		}
	}
	return false
}

// Eligible reports whether traffic of this identity is sealed.
func (c *Config) Eligible(email string) bool {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return c.SealAnonymous
	}
	for _, e := range c.Identities {
		if e == "*" || e == email {
			return true
		}
	}
	return false
}

// EgressFor reports whether sealed egress is enabled for this identity.
func (c *Config) EgressFor(email string) bool {
	if !c.Egress || c.Mode == ModePassthrough || !c.Eligible(email) {
		return false
	}
	email = strings.ToLower(strings.TrimSpace(email))
	for _, e := range c.EgressIdentities {
		if e == "*" || e == email {
			return true
		}
	}
	return false
}
