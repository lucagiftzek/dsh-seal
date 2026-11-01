// Package wsproto is a small RFC 6455 WebSocket implementation: the server
// side for the /_s/ws mux socket and the client side for the inner sockets
// dsh-seal opens to the upstream. No extensions are negotiated (no
// permessage-deflate), which keeps it short enough to audit.
package wsproto

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Opcodes.
const (
	OpCont   = 0x0
	OpText   = 0x1
	OpBinary = 0x2
	OpClose  = 0x8
	OpPing   = 0x9
	OpPong   = 0xA
)

const guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// DefaultMaxMessage bounds one reassembled message.
const DefaultMaxMessage = 64 << 20

// CloseError is returned by ReadMessage when the peer closed the socket.
type CloseError struct {
	Code   int
	Reason string
}

func (e *CloseError) Error() string { return fmt.Sprintf("websocket closed: %d %s", e.Code, e.Reason) }

// Conn is one WebSocket connection. Reads must come from one goroutine;
// writes may come from many.
type Conn struct {
	c       net.Conn
	br      *bufio.Reader
	client  bool
	wmu     sync.Mutex
	closed  bool
	MaxMsg  int
	OnPing  func()
	closeMu sync.Once
}

// AcceptKey computes Sec-WebSocket-Accept for a key.
func AcceptKey(key string) string {
	h := sha1.Sum([]byte(key + guid))
	return base64.StdEncoding.EncodeToString(h[:])
}

func headerHas(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, p := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(p), token) {
				return true
			}
		}
	}
	return false
}

// IsUpgrade reports whether r asks for a WebSocket upgrade.
func IsUpgrade(r *http.Request) bool {
	return headerHas(r.Header, "Connection", "upgrade") && headerHas(r.Header, "Upgrade", "websocket")
}

// Accept completes the server handshake and hijacks the connection.
func Accept(w http.ResponseWriter, r *http.Request, protocol string) (*Conn, error) {
	if r.Method != http.MethodGet || !IsUpgrade(r) {
		http.Error(w, "websocket upgrade required", http.StatusBadRequest)
		return nil, errors.New("not an upgrade")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" || r.Header.Get("Sec-WebSocket-Version") != "13" {
		w.Header().Set("Sec-WebSocket-Version", "13")
		http.Error(w, "unsupported websocket version", http.StatusBadRequest)
		return nil, errors.New("bad version or key")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return nil, errors.New("hijack unsupported")
	}
	c, brw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n")
	b.WriteString("Sec-WebSocket-Accept: " + AcceptKey(key) + "\r\n")
	if protocol != "" {
		b.WriteString("Sec-WebSocket-Protocol: " + protocol + "\r\n")
	}
	b.WriteString("\r\n")
	c.SetDeadline(time.Time{})
	if _, err := c.Write([]byte(b.String())); err != nil {
		c.Close()
		return nil, err
	}
	return &Conn{c: c, br: brw.Reader, MaxMsg: DefaultMaxMessage}, nil
}

// DialResult describes the upstream's answer to a client handshake.
type DialResult struct {
	Status   int
	Header   http.Header
	Body     []byte // only when Status != 101 (bounded)
	Protocol string
}

// Dial opens a client WebSocket to addr (host:port) for path, sending header
// (which must carry Host). A non-101 answer is returned in DialResult with a
// nil Conn and a nil error.
func Dial(ctx context.Context, addr, path string, header http.Header) (*Conn, *DialResult, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	return DialConn(ctx, c, addr, path, header)
}

// DialConn performs the client handshake on an established connection (plain
// TCP or TLS); addr is the authority used for the request line and Host.
// The connection is closed on failure.
func DialConn(ctx context.Context, c net.Conn, addr, path string, header http.Header) (*Conn, *DialResult, error) {
	keyb := make([]byte, 16)
	rand.Read(keyb)
	key := base64.StdEncoding.EncodeToString(keyb)
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+path, nil)
	if err != nil {
		c.Close()
		return nil, nil, err
	}
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if h := header.Get("Host"); h != "" {
		req.Host = h
		req.Header.Del("Host")
	}
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", key)
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Del("Sec-WebSocket-Extensions")
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	if err := req.Write(c); err != nil {
		c.Close()
		return nil, nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		c.Close()
		return nil, nil, err
	}
	res := &DialResult{Status: resp.StatusCode, Header: resp.Header, Protocol: resp.Header.Get("Sec-WebSocket-Protocol")}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		res.Body, _ = io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		c.Close()
		return nil, res, nil
	}
	if resp.Header.Get("Sec-WebSocket-Accept") != AcceptKey(key) {
		c.Close()
		return nil, nil, errors.New("upstream sent a bad Sec-WebSocket-Accept")
	}
	c.SetDeadline(time.Time{})
	return &Conn{c: c, br: br, client: true, MaxMsg: DefaultMaxMessage}, res, nil
}

// NetConn exposes the underlying connection (deadlines).
func (c *Conn) NetConn() net.Conn { return c.c }

func (c *Conn) writeFrame(op byte, data []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	hdr := make([]byte, 0, 14)
	hdr = append(hdr, 0x80|op)
	mbit := byte(0)
	if c.client {
		mbit = 0x80
	}
	n := len(data)
	switch {
	case n < 126:
		hdr = append(hdr, mbit|byte(n))
	case n <= 0xFFFF:
		hdr = append(hdr, mbit|126)
		hdr = binary.BigEndian.AppendUint16(hdr, uint16(n))
	default:
		hdr = append(hdr, mbit|127)
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(n))
	}
	payload := data
	if c.client {
		var mask [4]byte
		rand.Read(mask[:])
		hdr = append(hdr, mask[:]...)
		payload = make([]byte, n)
		for i := range data {
			payload[i] = data[i] ^ mask[i&3]
		}
	}
	if op == OpClose {
		c.closed = true
	}
	buf := make([]byte, 0, len(hdr)+len(payload))
	buf = append(buf, hdr...)
	buf = append(buf, payload...)
	_, err := c.c.Write(buf)
	return err
}

// WriteMessage sends one complete message (OpText or OpBinary).
func (c *Conn) WriteMessage(op byte, data []byte) error { return c.writeFrame(op, data) }

// Ping sends a ping control frame.
func (c *Conn) Ping(data []byte) error { return c.writeFrame(OpPing, data) }

// WriteClose sends a close frame with a status code and reason.
func (c *Conn) WriteClose(code int, reason string) error {
	if len(reason) > 120 {
		reason = reason[:120]
	}
	var p []byte
	if code > 0 {
		p = binary.BigEndian.AppendUint16(nil, uint16(code))
		p = append(p, reason...)
	}
	return c.writeFrame(OpClose, p)
}

// Close tears the connection down without a close handshake.
func (c *Conn) Close() error {
	var err error
	c.closeMu.Do(func() {
		c.wmu.Lock()
		c.closed = true
		c.wmu.Unlock()
		err = c.c.Close()
	})
	return err
}

func (c *Conn) readFrame() (fin bool, op byte, data []byte, err error) {
	var h [2]byte
	if _, err = io.ReadFull(c.br, h[:]); err != nil {
		return
	}
	fin = h[0]&0x80 != 0
	if h[0]&0x70 != 0 {
		err = errors.New("websocket: reserved bits set")
		return
	}
	op = h[0] & 0x0F
	masked := h[1]&0x80 != 0
	if !c.client && !masked {
		err = errors.New("websocket: client frame not masked")
		return
	}
	n := uint64(h[1] & 0x7F)
	switch n {
	case 126:
		var b [2]byte
		if _, err = io.ReadFull(c.br, b[:]); err != nil {
			return
		}
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err = io.ReadFull(c.br, b[:]); err != nil {
			return
		}
		n = binary.BigEndian.Uint64(b[:])
	}
	if op >= 0x8 && (n > 125 || !fin) {
		err = errors.New("websocket: bad control frame")
		return
	}
	if n > uint64(c.MaxMsg) {
		err = errors.New("websocket: frame too large")
		return
	}
	var mask [4]byte
	if masked {
		if _, err = io.ReadFull(c.br, mask[:]); err != nil {
			return
		}
	}
	data = make([]byte, n)
	if _, err = io.ReadFull(c.br, data); err != nil {
		return
	}
	if masked {
		for i := range data {
			data[i] ^= mask[i&3]
		}
	}
	return
}

// ReadMessage returns the next complete data message. Pings are answered,
// pongs dropped; a close frame is answered and returned as *CloseError.
func (c *Conn) ReadMessage() (byte, []byte, error) {
	var msgOp byte
	var msg []byte
	started := false
	for {
		fin, op, data, err := c.readFrame()
		if err != nil {
			return 0, nil, err
		}
		switch op {
		case OpPing:
			if c.OnPing != nil {
				c.OnPing()
			}
			c.writeFrame(OpPong, data)
			continue
		case OpPong:
			if c.OnPing != nil {
				c.OnPing()
			}
			continue
		case OpClose:
			ce := &CloseError{Code: 1005}
			if len(data) >= 2 {
				ce.Code = int(binary.BigEndian.Uint16(data))
				ce.Reason = string(data[2:])
			}
			code := ce.Code
			if code == 1005 {
				code = 1000
			}
			c.WriteClose(code, "")
			return 0, nil, ce
		case OpText, OpBinary:
			if started {
				return 0, nil, errors.New("websocket: new message inside a fragmented one")
			}
			msgOp, msg, started = op, data, true
		case OpCont:
			if !started {
				return 0, nil, errors.New("websocket: continuation without a start")
			}
			if len(msg)+len(data) > c.MaxMsg {
				return 0, nil, errors.New("websocket: message too large")
			}
			msg = append(msg, data...)
		default:
			return 0, nil, fmt.Errorf("websocket: unknown opcode %d", op)
		}
		if fin {
			return msgOp, msg, nil
		}
	}
}
