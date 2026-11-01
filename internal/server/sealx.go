package server

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	sc "dsh-seal/internal/sealcrypto"
)

func contextWith(r *http.Request, st *injectState) context.Context {
	return context.WithValue(r.Context(), injectKey, st)
}

// Handshake ---------------------------------------------------------------------

type hsReq struct {
	V    int    `json:"v"`
	KID  string `json:"kid"`
	CPub string `json:"cpub"`
}

type hsResp struct {
	V   int    `json:"v"`
	SID string `json:"sid"`
	SN  string `json:"sn"`
	CF  string `json:"cf"`
	TTL int    `json:"ttl"`
}

func (s *Server) serveHandshake(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sealError(w, http.StatusMethodNotAllowed, "SEAL_METHOD", "POST only")
		return
	}
	var req hsReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil || req.V != 1 {
		s.M.HandshakeFail.Add(1)
		sealError(w, http.StatusBadRequest, "SEAL_HS_BAD_REQUEST", "malformed handshake")
		return
	}
	kx, ok := s.Keys.KX(req.KID)
	if !ok {
		s.M.HandshakeFail.Add(1)
		sealError(w, http.StatusConflict, "SEAL_HS_UNKNOWN_KEY", "key exchange key unknown or expired, reload")
		return
	}
	cpub, err := sc.B64.DecodeString(req.CPub)
	if err != nil {
		s.M.HandshakeFail.Add(1)
		sealError(w, http.StatusBadRequest, "SEAL_HS_BAD_KEY", "client key encoding")
		return
	}
	sid, sn, ms, cf, err := sc.ServerHandshake(kx, s.Keys.IdentityRaw(), cpub)
	if err != nil {
		s.M.HandshakeFail.Add(1)
		sealError(w, http.StatusBadRequest, "SEAL_HS_BAD_KEY", "client key rejected")
		return
	}
	s.newSession(sid, ms, s.identity(r))
	s.M.Handshakes.Add(1)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(hsResp{V: 1, SID: sc.B64.EncodeToString(sid), SN: sc.B64.EncodeToString(sn), CF: sc.B64.EncodeToString(cf), TTL: int(s.Cfg().SessionTTL.Seconds())})
}

// Inner request headers -------------------------------------------------------------

// innerMeta is the HEAD frame of a sealed request.
type innerMeta struct {
	M  string      `json:"m"`            // method
	U  string      `json:"u"`            // path and query, must start with "/"
	H  [][2]string `json:"h"`            // header pairs as the page set them
	N  int64       `json:"n"`            // body length in bytes
	MD string      `json:"md,omitempty"` // fetch mode (navigate, cors, ...)
	DT string      `json:"dt,omitempty"` // fetch destination (document, script, ...)
	RD string      `json:"rd,omitempty"` // redirect mode (egress): follow, error, manual
}

// innerHead is the HEAD frame of a sealed response.
type innerHead struct {
	S int         `json:"s"`
	T string      `json:"t,omitempty"`
	H [][2]string `json:"h"`
	Z string      `json:"z,omitempty"` // body still compressed with this coding
	U string      `json:"u,omitempty"` // egress: final URL after redirects
}

var hopByHop = map[string]bool{
	"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true, "Proxy-Authorization": true,
	"Proxy-Connection": true, "Te": true, "Trailer": true, "Transfer-Encoding": true, "Upgrade": true,
}

// protectedInner names headers a page may never set inside the envelope: they
// carry identity or routing and come from the outer request, which passed
// the reverse proxy and the auth gateway.
func protectedInner(k string) bool {
	switch k {
	case "Host", "Cookie", "Cookie2", "Content-Length", "Forwarded", "X-Real-Ip", "Origin",
		"Accept-Encoding", "Sec-Websocket-Key", "Sec-Websocket-Version", "Sec-Websocket-Extensions", "Sec-Websocket-Accept":
		return true
	}
	if hopByHop[k] {
		return true
	}
	for _, p := range []string{"X-Auth-", "X-Forwarded-", "Cf-", "Sec-Fetch-", "Proxy-", "Remote-", "X-Seal-"} {
		if strings.HasPrefix(k, p) {
			return true
		}
	}
	return false
}

// inheritOuter names outer headers copied into every inner request.
func inheritOuter(k string) bool {
	switch k {
	case "Cookie", "Forwarded", "X-Real-Ip":
		return true
	}
	for _, p := range []string{"X-Auth-", "X-Forwarded-", "Cf-"} {
		if strings.HasPrefix(k, p) {
			return true
		}
	}
	return false
}

// buildInnerHeader merges the page headers with the identity and routing
// headers of the outer request.
func (s *Server) buildInnerHeader(outer *http.Request, pairs [][2]string, method, mode, dest string) http.Header {
	h := http.Header{}
	for _, kv := range pairs {
		k := http.CanonicalHeaderKey(strings.TrimSpace(kv[0]))
		if k == "" || protectedInner(k) || strings.ContainsAny(k, " \r\n:") || strings.ContainsAny(kv[1], "\r\n") {
			continue
		}
		h.Add(k, kv[1])
	}
	for k, vs := range outer.Header {
		if inheritOuter(k) {
			h[k] = append([]string(nil), vs...)
		}
	}
	stripSealCookie(h)
	if _, ok := outer.Header["X-Forwarded-For"]; !ok {
		if ip, _, err := net.SplitHostPort(outer.RemoteAddr); err == nil {
			h.Set("X-Forwarded-For", ip)
		}
	}
	for _, k := range []string{"User-Agent", "Accept-Language"} {
		if h.Get(k) == "" && outer.Header.Get(k) != "" {
			h.Set(k, outer.Header.Get(k))
		}
	}
	if method != http.MethodGet && method != http.MethodHead {
		if o := outer.Header.Get("Origin"); o != "" {
			h.Set("Origin", o)
		}
	}
	if v := outer.Header.Get("Sec-Fetch-Site"); v != "" {
		h.Set("Sec-Fetch-Site", v)
	}
	if mode != "" {
		h.Set("Sec-Fetch-Mode", mode)
	}
	if dest != "" {
		h.Set("Sec-Fetch-Dest", dest)
	}
	h.Set("Host", outer.Host)
	return h
}

func validInnerPath(u string) bool {
	return strings.HasPrefix(u, "/") && !strings.HasPrefix(u, "//") && !strings.HasPrefix(u, Prefix) && !strings.ContainsAny(u, " \r\n\t#")
}

// Frame IO ------------------------------------------------------------------------

// FrameReader reads length-prefixed frames ([u32 BE length][ciphertext]).
type FrameReader struct{ R io.Reader }

// Next returns the next raw ciphertext frame.
func (f FrameReader) Next() ([]byte, error) {
	var l [4]byte
	if _, err := io.ReadFull(f.R, l[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(l[:])
	if n > sc.MaxFrame || n < 17 {
		return nil, sc.ErrTooLarge
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(f.R, b); err != nil {
		return nil, io.ErrUnexpectedEOF
	}
	return b, nil
}

// AppendFrame appends a length-prefixed frame to dst.
func AppendFrame(dst, ct []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(ct)))
	return append(dst, ct...)
}

// MagicX starts every sealed fetch body: "DSX1" || sid(16) || stream(8).
const MagicX = "DSX1"

// MagicW is the first message on a mux socket: "DSW1" || sid(16) || stream(8).
const MagicW = "DSW1"

func parsePrefix(b []byte, magic string) (sid []byte, stream uint64, ok bool) {
	if len(b) != 28 || string(b[:4]) != magic {
		return nil, 0, false
	}
	return b[4:20], binary.BigEndian.Uint64(b[20:28]), true
}

// Sealed fetch -------------------------------------------------------------------------

func (s *Server) serveSealedFetch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sealError(w, http.StatusMethodNotAllowed, "SEAL_METHOD", "POST only")
		return
	}
	cfg := s.Cfg()
	body := http.MaxBytesReader(w, r.Body, cfg.MaxBody)
	br := bufio.NewReaderSize(body, 64<<10)
	pre := make([]byte, 28)
	if _, err := io.ReadFull(br, pre); err != nil {
		s.M.SealedFail.Add(1)
		sealError(w, http.StatusBadRequest, "SEAL_BAD_ENVELOPE", "short prefix")
		return
	}
	sid, stream, ok := parsePrefix(pre, MagicX)
	if !ok {
		s.M.SealedFail.Add(1)
		sealError(w, http.StatusBadRequest, "SEAL_BAD_ENVELOPE", "bad magic")
		return
	}
	sess, serr := s.lookup(sid, stream, s.identity(r))
	if serr != nil {
		s.M.SealedFail.Add(1)
		sealError(w, serr.status, serr.code, serr.msg)
		return
	}
	in := sc.NewStream(sess.MS, sess.ID, sc.DirC2S, stream)
	fr := FrameReader{br}
	ct, err := fr.Next()
	if err != nil {
		s.M.SealedFail.Add(1)
		sealError(w, http.StatusBadRequest, "SEAL_BAD_ENVELOPE", "missing head frame")
		return
	}
	typ, payload, err := in.Open(ct)
	if err != nil || typ != sc.FHead {
		s.M.SealedFail.Add(1)
		sealError(w, http.StatusBadRequest, "SEAL_FRAME_AUTH", "head frame did not authenticate")
		return
	}
	var meta innerMeta
	if err := json.Unmarshal(payload, &meta); err != nil || (!validInnerPath(meta.U) && !isAbsoluteURL(meta.U)) || meta.N < 0 || meta.N > cfg.MaxBody || !validMethod(meta.M) {
		s.M.SealedFail.Add(1)
		sealError(w, http.StatusBadRequest, "SEAL_BAD_REQUEST", "malformed inner request")
		return
	}
	s.M.BytesIn.Add(r.ContentLength)
	if isAbsoluteURL(meta.U) {
		s.serveEgressFetch(w, r, sess, stream, fr, in, meta)
		return
	}

	// The request body streams from the sealed frames into the upstream
	// request; its length was declared in the head, because dsh-proxy needs a
	// Content-Length.
	var upBody io.Reader
	pr, pw := io.Pipe()
	bodyErr := make(chan error, 1)
	go func() {
		var got int64
		for {
			ct, err := fr.Next()
			if err != nil {
				err = fmt.Errorf("SEAL_BAD_ENVELOPE: %w", err)
				pw.CloseWithError(err)
				bodyErr <- err
				return
			}
			typ, p, err := in.Open(ct)
			if err != nil {
				pw.CloseWithError(err)
				bodyErr <- err
				return
			}
			switch typ {
			case sc.FData:
				got += int64(len(p))
				if got > meta.N {
					err := errors.New("SEAL_BAD_REQUEST: body longer than declared")
					pw.CloseWithError(err)
					bodyErr <- err
					return
				}
				if _, err := pw.Write(p); err != nil {
					bodyErr <- err
					return
				}
			case sc.FEnd:
				if got != meta.N {
					err := errors.New("SEAL_BAD_REQUEST: body shorter than declared")
					pw.CloseWithError(err)
					bodyErr <- err
					return
				}
				pw.Close()
				bodyErr <- nil
				return
			default:
				err := errors.New("SEAL_BAD_REQUEST: unexpected frame type")
				pw.CloseWithError(err)
				bodyErr <- err
				return
			}
		}
	}()
	if meta.N > 0 {
		upBody = pr
	}
	ctx := r.Context()
	ureq, err := http.NewRequestWithContext(ctx, meta.M, "http://"+cfg.Upstream+meta.U, upBody)
	if err != nil {
		pr.CloseWithError(err)
		s.M.SealedFail.Add(1)
		sealError(w, http.StatusBadRequest, "SEAL_BAD_REQUEST", "inner request rejected")
		return
	}
	ureq.Header = s.buildInnerHeader(r, meta.H, meta.M, meta.MD, meta.DT)
	ureq.Host = r.Host
	ureq.Header.Del("Host")
	ureq.Header.Set("Accept-Encoding", "gzip")
	ureq.ContentLength = meta.N
	if meta.N == 0 {
		// Still require the END frame before replaying, so a truncated or
		// forged envelope is never executed.
		if err := <-bodyErr; err != nil {
			pr.Close()
			s.M.SealedFail.Add(1)
			sealError(w, http.StatusBadRequest, "SEAL_BAD_ENVELOPE", "envelope did not end cleanly")
			return
		}
		ureq.Body = http.NoBody
	}

	out := sc.NewStream(sess.MS, sess.ID, sc.DirS2C, stream)
	resp, err := s.upstream.RoundTrip(ureq)
	if meta.N > 0 {
		pr.Close()
		if err == nil {
			if berr := <-bodyErr; berr != nil {
				// The upstream already answered; the body error is reported
				// below only when the round trip itself failed.
				_ = berr
			}
		}
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	if err != nil {
		s.M.SealedFail.Add(1)
		s.Log.Warn("sealed upstream error", "code", "SEAL_UPSTREAM_DOWN", "err", err)
		w.WriteHeader(http.StatusOK)
		head, _ := json.Marshal(innerHead{S: 502, H: [][2]string{{"Content-Type", "text/plain; charset=utf-8"}}})
		msg := []byte("dsh-seal: upstream unreachable (SEAL_UPSTREAM_DOWN)\n")
		var b []byte
		b = AppendFrame(b, out.Seal(sc.FHead, head))
		b = AppendFrame(b, out.Seal(sc.FData, msg))
		b = AppendFrame(b, out.Seal(sc.FEnd, nil))
		w.Write(b)
		return
	}
	defer resp.Body.Close()
	// Cookies must reach the browser jar, which only reads real response
	// headers: copy them to the outer response (documented limit).
	for _, c := range resp.Header.Values("Set-Cookie") {
		w.Header().Add("Set-Cookie", c)
	}
	ih := innerHead{S: resp.StatusCode, H: make([][2]string, 0, len(resp.Header))}
	enc := strings.ToLower(resp.Header.Get("Content-Encoding"))
	if enc == "gzip" && meta.M != http.MethodHead && resp.StatusCode != 204 && resp.StatusCode != 304 {
		ih.Z = "gzip"
	}
	for k, vs := range resp.Header {
		if hopByHop[k] || k == "Set-Cookie" || (ih.Z != "" && (k == "Content-Encoding" || k == "Content-Length")) {
			continue
		}
		for _, v := range vs {
			ih.H = append(ih.H, [2]string{k, v})
		}
	}
	head, _ := json.Marshal(ih)
	w.WriteHeader(http.StatusOK)
	fl, _ := w.(http.Flusher)
	n := s.streamSealed(w, fl, out, head, resp.Body, meta.M == http.MethodHead)
	s.M.BytesOut.Add(n)
	s.M.Sealed.Add(1)
}

// streamSealed writes the HEAD frame, then DATA frames as the upstream body
// arrives (flushing each, so event streams stay live), then END or ERROR.
func (s *Server) streamSealed(w io.Writer, fl http.Flusher, out *sc.Stream, head []byte, body io.Reader, noBody bool) int64 {
	var total int64
	write := func(b []byte) bool {
		n, err := w.Write(b)
		total += int64(n)
		if err != nil {
			return false
		}
		if fl != nil {
			fl.Flush()
		}
		return true
	}
	if !write(AppendFrame(nil, out.Seal(sc.FHead, head))) {
		return total
	}
	if !noBody {
		buf := make([]byte, sc.MaxPayload)
		for {
			n, err := body.Read(buf)
			if n > 0 {
				if !write(AppendFrame(nil, out.Seal(sc.FData, buf[:n]))) {
					return total
				}
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				code := "SEAL_UPSTREAM_BROKEN"
				if errors.Is(err, ErrEgressTooLarge) {
					code = "SEAL_EGRESS_TOO_LARGE"
				}
				msg, _ := json.Marshal(map[string]string{"code": code, "message": "upstream body ended early"})
				write(AppendFrame(nil, out.Seal(sc.FError, msg)))
				return total
			}
		}
	}
	write(AppendFrame(nil, out.Seal(sc.FEnd, nil)))
	return total
}

func validMethod(m string) bool {
	switch m {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
		return true
	}
	return false
}

// Sealed egress fetch -------------------------------------------------------------

// serveEgressFetch answers an inner request whose target is another host: the
// server fetches it (see egress.go) and streams the answer back sealed.
// Refusals are sealed inner responses too, so an observer cannot tell them
// from any other answer.
func (s *Server) serveEgressFetch(w http.ResponseWriter, r *http.Request, sess *Session, stream uint64, fr FrameReader, in *sc.Stream, meta innerMeta) {
	cfg := s.Cfg()
	var body []byte
	tooBig := meta.N > cfg.EgressMaxReq
	for !tooBig {
		ct, err := fr.Next()
		if err != nil {
			s.M.SealedFail.Add(1)
			sealError(w, http.StatusBadRequest, "SEAL_BAD_ENVELOPE", "envelope did not end cleanly")
			return
		}
		typ, p, err := in.Open(ct)
		if err != nil || (typ != sc.FData && typ != sc.FEnd) || int64(len(body)+len(p)) > meta.N || int64(len(body)+len(p)) > cfg.EgressMaxReq+1 {
			s.M.SealedFail.Add(1)
			sealError(w, http.StatusBadRequest, "SEAL_BAD_ENVELOPE", "envelope did not authenticate")
			return
		}
		if typ == sc.FEnd {
			if int64(len(body)) != meta.N {
				s.M.SealedFail.Add(1)
				sealError(w, http.StatusBadRequest, "SEAL_BAD_REQUEST", "body shorter than declared")
				return
			}
			break
		}
		body = append(body, p...)
	}
	out := sc.NewStream(sess.MS, sess.ID, sc.DirS2C, stream)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	host := hostOf(meta.U)
	refuse := func(ee *EgressError) {
		s.M.EgressRefused.Add(1)
		s.Egress.record(sess.Email, host, ee.Status, ee.Code, 0)
		head, _ := json.Marshal(innerHead{S: ee.Status, H: [][2]string{{"Content-Type", "text/plain; charset=utf-8"}, {"X-Seal-Egress-Error", ee.Code}}})
		var b []byte
		b = AppendFrame(b, out.Seal(sc.FHead, head))
		b = AppendFrame(b, out.Seal(sc.FData, []byte("dsh-seal egress: "+ee.Code+": "+ee.Msg+"\n")))
		b = AppendFrame(b, out.Seal(sc.FEnd, nil))
		w.WriteHeader(http.StatusOK)
		w.Write(b)
	}
	if tooBig {
		refuse(egErr("SEAL_EGRESS_TOO_LARGE", 413, "request body too large"))
		return
	}
	if !cfg.EgressFor(sess.Email) {
		refuse(egErr("SEAL_EGRESS_OFF", 403, "egress is off for this identity"))
		return
	}
	release, ee := s.Egress.admit(r.Context(), sess.Email)
	if ee != nil {
		refuse(ee)
		return
	}
	defer release()
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Minute)
	defer cancel()
	resp, ee := s.Egress.Fetch(ctx, &EgressRequest{Method: meta.M, URL: meta.U, Header: meta.H, Body: body, Mode: meta.MD, Dest: meta.DT,
		Redirect: meta.RD, Origin: pageOrigin(r), Identity: sess.Email})
	if ee != nil {
		if ee.Status >= 500 {
			s.M.EgressFail.Add(1)
		}
		refuse(ee)
		return
	}
	rb := withIdle(resp.Body, 120*time.Second, cancel)
	defer rb.Close()
	ih := innerHead{S: resp.Status, H: make([][2]string, 0, len(resp.Header)), U: resp.FinalURL}
	if resp.Gzip {
		ih.Z = "gzip"
	}
	for k, vs := range resp.Header {
		for _, v := range vs {
			ih.H = append(ih.H, [2]string{k, v})
		}
	}
	head, _ := json.Marshal(ih)
	w.WriteHeader(http.StatusOK)
	fl, _ := w.(http.Flusher)
	n := s.streamSealed(w, fl, out, head, rb, meta.M == http.MethodHead)
	s.M.BytesOut.Add(n)
	s.M.Egress.Add(1)
	s.M.EgressBytes.Add(n)
	s.Egress.record(sess.Email, host, resp.Status, "", n)
}
