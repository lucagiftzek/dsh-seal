package server

import (
	"net/http"
	"regexp"
	"strings"
)

// Resource hints open connections to other hosts without a fetch the service
// worker could intercept (DNS prefetch, preconnect, prerender). dsh-seal
// removes the ones pointing at other hosts from the HTML it injects into, and
// from Link response headers. preload and prefetch stay: they are fetches and
// go through the worker (sealed egress).

var (
	linkTagRe = regexp.MustCompile(`(?is)<link\b[^>]*>`)
	relAttrRe = regexp.MustCompile(`(?is)\srel\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
	hrefRe    = regexp.MustCompile(`(?is)\shref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
)

func attrVal(m []string) string {
	for _, v := range m[1:] {
		if v != "" {
			return v
		}
	}
	return ""
}

// connectingHint reports whether a rel value opens a connection by itself.
func connectingHint(rel string) bool {
	for _, t := range strings.Fields(strings.ToLower(rel)) {
		switch t {
		case "preconnect", "dns-prefetch", "prerender":
			return true
		}
	}
	return false
}

// foreignHref reports whether href points at a host other than self.
func foreignHref(href, self string) bool {
	h := strings.ToLower(strings.TrimSpace(href))
	var rest string
	switch {
	case strings.HasPrefix(h, "//"):
		rest = h[2:]
	case strings.HasPrefix(h, "https://"):
		rest = h[8:]
	case strings.HasPrefix(h, "http://"):
		rest = h[7:]
	default:
		return false
	}
	host := rest
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	return host != strings.ToLower(self)
}

// NeutralizeHints removes <link rel=preconnect|dns-prefetch|prerender> tags
// that point at other hosts.
func NeutralizeHints(html []byte, self string) []byte {
	return linkTagRe.ReplaceAllFunc(html, func(tag []byte) []byte {
		rm := relAttrRe.FindStringSubmatch(string(tag))
		hm := hrefRe.FindStringSubmatch(string(tag))
		if rm == nil || hm == nil || !connectingHint(attrVal(rm)) || !foreignHref(attrVal(hm), self) {
			return tag
		}
		return []byte("<!-- dsh-seal: connection hint removed -->")
	})
}

// dropHintLinks removes Link header values that are connecting hints.
func dropHintLinks(h http.Header) {
	vs := h.Values("Link")
	if len(vs) == 0 {
		return
	}
	var keep []string
	for _, v := range vs {
		var parts []string
		for _, p := range strings.Split(v, ",") {
			if !connectingHint(strings.NewReplacer("rel=", " ", `"`, " ", ";", " ").Replace(p)) {
				parts = append(parts, strings.TrimSpace(p))
			}
		}
		if len(parts) > 0 {
			keep = append(keep, strings.Join(parts, ", "))
		}
	}
	h.Del("Link")
	for _, v := range keep {
		h.Add("Link", v)
	}
}
