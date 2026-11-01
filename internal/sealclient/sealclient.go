// Package sealclient is a Go implementation of the dsh-seal client side. The
// browser uses the TypeScript client; this one exists for the Go tests, the
// end to end harness and the overhead measurements (cmd/sealbench).
package sealclient

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"dsh-seal/internal/keystore"
	sc "dsh-seal/internal/sealcrypto"
	"dsh-seal/internal/wsproto"
)

// Session is a completed handshake.
type Session struct {
	Base   string // e.g. http://127.0.0.1:3082
	Header http.Header
	SID    []byte
	MS     []byte
	next   atomic.Uint64
	HTTP   *http.Client
}

// NextStream returns a fresh stream id.
func (s *Session) NextStream() uint64 { return s.next.Add(1) }

// SetNext moves the stream counter (tests of the replay window).
func (s *Session) SetNext(v uint64) { s.next.Store(v) }

// Bundle fetches /_s/boot.js and extracts the embedded key bundle.
func Bundle(ctx context.Context, c *http.Client, base string, h http.Header) (keystore.Bundle, error) {
	var b keystore.Bundle
	req, _ := http.NewRequestWithContext(ctx, "GET", base+"/_s/boot.js", nil)
	req.Header = h.Clone()
	resp, err := c.Do(req)
	if err != nil {
		return b, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return b, fmt.Errorf("boot.js: HTTP %d %s", resp.StatusCode, body)
	}
	s := string(body)
	s = strings.TrimPrefix(s, "self.__DSH_SEAL_CFG=")
	end := strings.Index(s, ";\n")
	if end < 0 {
		return b, errors.New("boot.js: no config")
	}
	var conf struct {
		Bundle keystore.Bundle `json:"bundle"`
	}
	if err := json.Unmarshal([]byte(s[:end]), &conf); err != nil {
		return b, err
	}
	return conf.Bundle, nil
}

// Handshake verifies the bundle against pinned (may be "") and runs /_s/h.
func Handshake(ctx context.Context, c *http.Client, base string, h http.Header, b keystore.Bundle, pinned string) (*Session, string, error) {
	fp, err := keystore.VerifyBundle(b, pinned, timeNow())
	if err != nil {
		return nil, "", err
	}
	priv, _ := ecdh.P256().GenerateKey(rand.Reader)
	cpub := priv.PublicKey().Bytes()
	body, _ := json.Marshal(map[string]any{"v": 1, "kid": b.KX.KID, "cpub": sc.B64.EncodeToString(cpub)})
	req, _ := http.NewRequestWithContext(ctx, "POST", base+"/_s/h", bytes.NewReader(body))
	req.Header = h.Clone()
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		rb, _ := io.ReadAll(resp.Body)
		return nil, "", fmt.Errorf("handshake: HTTP %d %s", resp.StatusCode, rb)
	}
	var hs struct{ SID, SN, CF string }
	if err := json.NewDecoder(resp.Body).Decode(&hs); err != nil {
		return nil, "", err
	}
	sid, _ := sc.B64.DecodeString(hs.SID)
	sn, _ := sc.B64.DecodeString(hs.SN)
	cf, _ := sc.B64.DecodeString(hs.CF)
	kxRaw, _ := sc.B64.DecodeString(b.KX.Pub)
	idRaw, _ := sc.B64.DecodeString(b.ID)
	kxPub, err := ecdh.P256().NewPublicKey(kxRaw)
	if err != nil {
		return nil, "", err
	}
	shared, err := priv.ECDH(kxPub)
	if err != nil {
		return nil, "", err
	}
	th := sc.TranscriptHash(idRaw, kxRaw, cpub, sid, sn)
	ms := sc.MasterSecret(shared, th)
	if !bytes.Equal(sc.Confirm(ms, th), cf) {
		return nil, "", errors.New("SEAL_HS_CONFIRM")
	}
	return &Session{Base: base, Header: h.Clone(), SID: sid, MS: ms, HTTP: c}, fp, nil
}

// Request is an inner request.
type Request struct {
	Method   string
	Path     string
	Header   [][2]string
	Body     []byte
	Stream   uint64 // 0 = next fresh id
	Mode     string
	Dest     string
	Redirect string
	Corrupt  bool // flip a ciphertext byte (tests)
}

// Response is an inner response; Body yields the decrypted stream.
type Response struct {
	OuterStatus int
	OuterHeader http.Header
	Status      int
	Header      http.Header
	Gzip        bool
	Body        io.ReadCloser
	ErrorCode   string
	FinalURL    string
}

// Envelope builds the sealed request body.
func (s *Session) Envelope(r *Request) ([]byte, uint64) {
	stream := r.Stream
	if stream == 0 {
		stream = s.NextStream()
	}
	out := sc.NewStream(s.MS, s.SID, sc.DirC2S, stream)
	head, _ := json.Marshal(map[string]any{"m": r.Method, "u": r.Path, "h": r.Header, "n": len(r.Body), "md": r.Mode, "dt": r.Dest, "rd": r.Redirect})
	var b []byte
	b = append(b, "DSX1"...)
	b = append(b, s.SID...)
	b = binary.BigEndian.AppendUint64(b, stream)
	b = appendFrame(b, out.Seal(sc.FHead, head))
	for o := 0; o < len(r.Body); o += sc.MaxPayload {
		e := min(len(r.Body), o+sc.MaxPayload)
		b = appendFrame(b, out.Seal(sc.FData, r.Body[o:e]))
	}
	b = appendFrame(b, out.Seal(sc.FEnd, nil))
	if r.Corrupt {
		b[40] ^= 1
	}
	return b, stream
}

func appendFrame(dst, ct []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(ct)))
	return append(dst, ct...)
}

// Do sends a sealed request and returns the decrypted response.
func (s *Session) Do(ctx context.Context, r *Request) (*Response, error) {
	env, stream := s.Envelope(r)
	return s.Post(ctx, env, stream)
}

// Post sends a prepared envelope (tests replay it).
func (s *Session) Post(ctx context.Context, env []byte, stream uint64) (*Response, error) {
	req, _ := http.NewRequestWithContext(ctx, "POST", s.Base+"/_s/x", bytes.NewReader(env))
	req.Header = s.Header.Clone()
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	out := &Response{OuterStatus: resp.StatusCode, OuterHeader: resp.Header}
	if resp.StatusCode != 200 {
		var e struct{ Code string }
		json.NewDecoder(resp.Body).Decode(&e)
		resp.Body.Close()
		out.ErrorCode = e.Code
		return out, nil
	}
	in := sc.NewStream(s.MS, s.SID, sc.DirS2C, stream)
	fr := frameReader{resp.Body}
	ct, err := fr.next()
	if err != nil {
		resp.Body.Close()
		return nil, err
	}
	typ, p, err := in.Open(ct)
	if err != nil || typ != sc.FHead {
		resp.Body.Close()
		return nil, fmt.Errorf("bad head frame: %v", err)
	}
	var h struct {
		S int
		H [][2]string
		Z string
		U string
	}
	json.Unmarshal(p, &h)
	out.Status, out.Gzip, out.FinalURL = h.S, h.Z == "gzip", h.U
	out.Header = http.Header{}
	for _, kv := range h.H {
		out.Header.Add(kv[0], kv[1])
	}
	pr, pw := io.Pipe()
	go func() {
		defer resp.Body.Close()
		for {
			ct, err := fr.next()
			if err != nil {
				pw.CloseWithError(fmt.Errorf("SEAL_TRUNCATED: %w", err))
				return
			}
			typ, p, err := in.Open(ct)
			if err != nil {
				pw.CloseWithError(err)
				return
			}
			switch typ {
			case sc.FData:
				if _, err := pw.Write(p); err != nil {
					return
				}
			case sc.FEnd:
				pw.Close()
				return
			default:
				pw.CloseWithError(fmt.Errorf("frame type %d: %s", typ, p))
				return
			}
		}
	}()
	out.Body = pr
	return out, nil
}

type frameReader struct{ r io.Reader }

func (f frameReader) next() ([]byte, error) {
	var l [4]byte
	if _, err := io.ReadFull(f.r, l[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(l[:])
	if n > sc.MaxFrame {
		return nil, sc.ErrTooLarge
	}
	b := make([]byte, n)
	_, err := io.ReadFull(f.r, b)
	return b, err
}

// Mux ----------------------------------------------------------------------------

// Mux is a minimal mux client: frames in, frames out, no flow control beyond
// granting credit for everything received.
type Mux struct {
	ws  *wsproto.Conn
	out *sc.Stream
	in  *sc.Stream
	wmu sync.Mutex // seal + write in wire order (tests send from several goroutines)
}

// MuxFrame is one decrypted mux frame.
type MuxFrame struct {
	Type    byte
	Chan    uint32
	Payload []byte
}

// DialMux opens /_s/ws (wsAddr is host:port) and sends the prefix.
func (s *Session) DialMux(ctx context.Context, wsAddr string) (*Mux, error) {
	h := s.Header.Clone()
	if h.Get("Host") == "" {
		h.Set("Host", wsAddr)
	}
	ws, res, err := wsproto.Dial(ctx, wsAddr, "/_s/ws", h)
	if err != nil {
		return nil, err
	}
	if ws == nil {
		return nil, fmt.Errorf("mux: HTTP %d", res.Status)
	}
	stream := s.NextStream()
	pre := append([]byte("DSW1"), s.SID...)
	pre = binary.BigEndian.AppendUint64(pre, stream)
	if err := ws.WriteMessage(wsproto.OpBinary, pre); err != nil {
		return nil, err
	}
	return &Mux{ws: ws, out: sc.NewStream(s.MS, s.SID, sc.DirC2S, stream), in: sc.NewStream(s.MS, s.SID, sc.DirS2C, stream)}, nil
}

// Send seals and sends one frame.
func (m *Mux) Send(typ byte, ch uint32, payload []byte) error {
	p := binary.BigEndian.AppendUint32(nil, ch)
	p = append(p, payload...)
	m.wmu.Lock()
	defer m.wmu.Unlock()
	return m.ws.WriteMessage(wsproto.OpBinary, m.out.Seal(typ, p))
}

// SendRaw sends bytes as they are (tests of forged frames).
func (m *Mux) SendRaw(b []byte) error {
	m.wmu.Lock()
	defer m.wmu.Unlock()
	return m.ws.WriteMessage(wsproto.OpBinary, b)
}

// Recv reads and decrypts one frame (a close of the mux returns the error).
func (m *Mux) Recv() (MuxFrame, error) {
	_, msg, err := m.ws.ReadMessage()
	if err != nil {
		return MuxFrame{}, err
	}
	typ, p, err := m.in.Open(msg)
	if err != nil {
		return MuxFrame{}, err
	}
	if len(p) < 4 {
		return MuxFrame{Type: typ}, nil
	}
	return MuxFrame{Type: typ, Chan: binary.BigEndian.Uint32(p), Payload: p[4:]}, nil
}

// Close closes the mux socket.
func (m *Mux) Close() { m.ws.Close() }

// Clone copies a session (tests use it to forge identity or session ids).
func (s *Session) Clone() *Session {
	c := &Session{Base: s.Base, Header: s.Header.Clone(), SID: append([]byte(nil), s.SID...), MS: s.MS, HTTP: s.HTTP}
	c.next.Store(s.next.Load() + 1000)
	return c
}
