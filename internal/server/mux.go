package server

import (
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	sc "dsh-seal/internal/sealcrypto"
	"dsh-seal/internal/wsproto"
)

// Mux frame types (the type byte of a sealed mux frame). FlagMore on TEXT and
// BINARY marks a fragment that continues in the next frame of the channel.
const (
	MOpen   byte = 0x10
	MOpened byte = 0x11
	MText   byte = 0x12
	MBinary byte = 0x13
	MClose  byte = 0x14
	MError  byte = 0x15
	MCredit byte = 0x16
	MPing   byte = 0x17
	MPong   byte = 0x18

	FlagMore byte = 0x80
)

// MaxChannels bounds the inner sockets of one mux connection.
const MaxChannels = 512

// chunk is the largest payload of one mux data frame (4 bytes go to the channel).
const chunk = sc.MaxPayload - 4

type openMsg struct {
	K  string      `json:"k"` // "ws" or "http"
	U  string      `json:"u"`
	P  []string    `json:"p,omitempty"`
	M  string      `json:"m,omitempty"`
	H  [][2]string `json:"h,omitempty"`
	MD string      `json:"md,omitempty"`
	DT string      `json:"dt,omitempty"`
}

type muxConn struct {
	s      *Server
	outer  *http.Request
	ws     *wsproto.Conn
	sess   *Session
	stream uint64
	window int64

	wmu sync.Mutex // seal + write must be atomic so seq matches wire order
	out *sc.Stream

	cmu   sync.Mutex
	chans map[uint32]*muxChan
	ctx   context.Context
	stop  context.CancelFunc
}

type muxChan struct {
	id   uint32
	kind string

	// send window towards the client (bytes); refilled by MCredit
	cmu    sync.Mutex
	cond   *sync.Cond
	credit int64
	closed bool

	up      *wsproto.Conn // ws kind
	cancel  func()        // http kind
	toUp    chan upMsg    // ws kind: ordered queue towards the upstream
	inFrag  []byte        // reassembly of a fragmented client message
	inOp    byte
	pending sync.WaitGroup
}

type upMsg struct {
	op   byte
	data []byte
}

// muxPingEvery is the server's keepalive ping on a mux, in nanoseconds (tests shorten it).
var muxPingEvery atomic.Int64

func init() { muxPingEvery.Store(int64(30 * time.Second)) }

func (s *Server) serveMux(w http.ResponseWriter, r *http.Request) {
	ws, err := wsproto.Accept(w, r, "")
	if err != nil {
		return
	}
	ws.MaxMsg = sc.MaxFrame + 64
	defer ws.Close()
	ws.NetConn().SetReadDeadline(time.Now().Add(20 * time.Second))
	op, first, err := ws.ReadMessage()
	if err != nil || op != wsproto.OpBinary {
		ws.WriteClose(4400, "SEAL_BAD_ENVELOPE")
		return
	}
	sid, stream, ok := parsePrefix(first, MagicW)
	if !ok {
		ws.WriteClose(4400, "SEAL_BAD_ENVELOPE")
		return
	}
	sess, serr := s.lookup(sid, stream, s.identity(r))
	if serr != nil {
		code := 4403
		if serr.code == "SEAL_UNKNOWN_SESSION" {
			code = 4401
		}
		ws.WriteClose(code, serr.code)
		return
	}
	s.M.MuxConns.Add(1)
	s.M.MuxLive.Add(1)
	defer s.M.MuxLive.Add(-1)
	ctx, stop := context.WithCancel(context.Background())
	m := &muxConn{s: s, outer: r, ws: ws, sess: sess, stream: stream, window: s.Cfg().MuxWindow,
		out: sc.NewStream(sess.MS, sess.ID, sc.DirS2C, stream), chans: map[uint32]*muxChan{}, ctx: ctx, stop: stop}
	defer m.shutdown()
	// The server pings too: a quiet socket stays under Cloudflare's idle
	// timeout (about 100 s for proxied WebSockets) even when the browser
	// throttles the page's timers; a client answers with a pong.
	go func() {
		t := time.NewTicker(time.Duration(muxPingEvery.Load()))
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				if m.send(MPing, 0, binary.BigEndian.AppendUint64(nil, uint64(now.UnixMilli()))) != nil {
					return
				}
				s.M.MuxPings.Add(1)
			}
		}
	}()
	in := sc.NewStream(sess.MS, sess.ID, sc.DirC2S, stream)
	for {
		// Clients ping every 25 s; three missed pings end the mux.
		ws.NetConn().SetReadDeadline(time.Now().Add(90 * time.Second))
		op, msg, err := ws.ReadMessage()
		if err != nil {
			return
		}
		if op != wsproto.OpBinary {
			ws.WriteClose(4400, "SEAL_BAD_ENVELOPE")
			return
		}
		s.M.BytesIn.Add(int64(len(msg)))
		typ, p, err := in.Open(msg)
		if err != nil {
			ws.WriteClose(4400, "SEAL_FRAME_AUTH")
			return
		}
		if typ == MPing {
			m.send(MPong, 0, p)
			continue
		}
		if len(p) < 4 {
			ws.WriteClose(4400, "SEAL_BAD_ENVELOPE")
			return
		}
		ch := binary.BigEndian.Uint32(p[:4])
		if err := m.handle(typ, ch, p[4:]); err != nil {
			ws.WriteClose(4400, "SEAL_MUX_PROTOCOL")
			return
		}
	}
}

// send seals and writes one frame for channel ch.
func (m *muxConn) send(typ byte, ch uint32, payload []byte) error {
	buf := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(buf, ch)
	copy(buf[4:], payload)
	m.wmu.Lock()
	defer m.wmu.Unlock()
	ct := m.out.Seal(typ, buf)
	m.s.M.BytesOut.Add(int64(len(ct)))
	return m.ws.WriteMessage(wsproto.OpBinary, ct)
}

func (m *muxConn) sendErr(ch uint32, code, msg string, status int) {
	b, _ := json.Marshal(map[string]any{"code": code, "message": msg, "status": status})
	m.send(MError, ch, b)
}

// sendData splits a message into fragments, waiting for credit.
func (m *muxConn) sendData(c *muxChan, op byte, data []byte) error {
	typ := MBinary
	if op == wsproto.OpText {
		typ = MText
	}
	for {
		n := len(data)
		if n > chunk {
			n = chunk
		}
		if err := c.take(int64(n)); err != nil {
			return err
		}
		t := typ
		if n < len(data) {
			t |= FlagMore
		}
		if err := m.send(t, c.id, data[:n]); err != nil {
			return err
		}
		data = data[n:]
		if len(data) == 0 {
			return nil
		}
	}
}

func (c *muxChan) take(n int64) error {
	c.cmu.Lock()
	defer c.cmu.Unlock()
	for c.credit < n && c.credit < chunk && !c.closed {
		c.cond.Wait()
	}
	if c.closed {
		return io.EOF
	}
	c.credit -= n
	return nil
}

func (c *muxChan) give(n int64) {
	c.cmu.Lock()
	c.credit += n
	c.cmu.Unlock()
	c.cond.Broadcast()
}

func (c *muxChan) markClosed() {
	c.cmu.Lock()
	c.closed = true
	c.cmu.Unlock()
	c.cond.Broadcast()
}

func (m *muxConn) get(ch uint32) *muxChan {
	m.cmu.Lock()
	defer m.cmu.Unlock()
	return m.chans[ch]
}

func (m *muxConn) drop(ch uint32) {
	m.cmu.Lock()
	c := m.chans[ch]
	delete(m.chans, ch)
	m.cmu.Unlock()
	if c != nil {
		c.markClosed()
		if c.up != nil {
			c.up.Close()
		}
		if c.cancel != nil {
			c.cancel()
		}
	}
}

func (m *muxConn) shutdown() {
	m.stop()
	m.cmu.Lock()
	ids := make([]uint32, 0, len(m.chans))
	for id := range m.chans {
		ids = append(ids, id)
	}
	m.cmu.Unlock()
	for _, id := range ids {
		m.drop(id)
	}
}

func (m *muxConn) handle(typ byte, ch uint32, p []byte) error {
	base := typ &^ FlagMore
	switch base {
	case MOpen:
		return m.open(ch, p)
	case MText, MBinary:
		c := m.get(ch)
		if c == nil || c.kind != "ws" {
			return nil // late data for a closed channel
		}
		op := byte(wsproto.OpBinary)
		if base == MText {
			op = wsproto.OpText
		}
		if c.inFrag == nil {
			c.inOp = op
		}
		c.inFrag = append(c.inFrag, p...)
		if len(c.inFrag) > wsproto.DefaultMaxMessage {
			return errors.New("message too large")
		}
		if typ&FlagMore == 0 {
			msg := c.inFrag
			c.inFrag = nil
			select {
			case c.toUp <- upMsg{c.inOp, msg}:
			case <-m.ctx.Done():
			}
		}
		return nil
	case MCredit:
		if len(p) != 4 {
			return errors.New("bad credit")
		}
		if c := m.get(ch); c != nil {
			c.give(int64(binary.BigEndian.Uint32(p)))
		}
		return nil
	case MClose:
		c := m.get(ch)
		if c == nil {
			return nil
		}
		if c.kind == "ws" {
			code, reason := 1000, ""
			if len(p) >= 2 {
				code = int(binary.BigEndian.Uint16(p))
				reason = string(p[2:])
			}
			select {
			case c.toUp <- upMsg{wsproto.OpClose, closePayload(code, reason)}:
			case <-m.ctx.Done():
			}
		} else {
			m.drop(ch)
		}
		return nil
	case MPong:
		return nil
	}
	return errors.New("unknown mux frame")
}

func closePayload(code int, reason string) []byte {
	b := binary.BigEndian.AppendUint16(nil, uint16(code))
	return append(b, reason...)
}

func (m *muxConn) open(ch uint32, p []byte) error {
	var o openMsg
	if err := json.Unmarshal(p, &o); err != nil {
		return err
	}
	m.cmu.Lock()
	if _, dup := m.chans[ch]; dup || len(m.chans) >= MaxChannels || ch == 0 {
		m.cmu.Unlock()
		m.sendErr(ch, "SEAL_MUX_PROTOCOL", "channel id in use or too many channels", 0)
		return nil
	}
	c := &muxChan{id: ch, kind: o.K, credit: m.window}
	c.cond = sync.NewCond(&c.cmu)
	m.chans[ch] = c
	m.cmu.Unlock()
	if isAbsoluteURL(o.U) {
		if !m.s.Cfg().EgressFor(m.sess.Email) {
			m.drop(ch)
			m.sendErr(ch, "SEAL_EGRESS_OFF", "egress is off for this identity", 403)
			return nil
		}
		m.s.M.MuxChannels.Add(1)
		switch o.K {
		case "ws":
			c.toUp = make(chan upMsg, 64)
			go m.runEgressWS(c, o)
		case "http":
			ctx, cancel := context.WithCancel(m.ctx)
			c.cancel = cancel
			go m.runEgressHTTP(ctx, c, o)
		default:
			m.drop(ch)
			m.sendErr(ch, "SEAL_BAD_REQUEST", "unknown channel kind", 0)
		}
		return nil
	}
	if !validInnerPath(o.U) {
		m.drop(ch)
		m.sendErr(ch, "SEAL_BAD_REQUEST", "bad inner path", 0)
		return nil
	}
	m.s.M.MuxChannels.Add(1)
	switch o.K {
	case "ws":
		c.toUp = make(chan upMsg, 64)
		go m.runWS(c, o)
	case "http":
		ctx, cancel := context.WithCancel(m.ctx)
		c.cancel = cancel
		go m.runHTTP(ctx, c, o)
	default:
		m.drop(ch)
		m.sendErr(ch, "SEAL_BAD_REQUEST", "unknown channel kind", 0)
	}
	return nil
}

// runWS opens one inner WebSocket to the upstream and pumps both directions.
func (m *muxConn) runWS(c *muxChan, o openMsg) {
	cfg := m.s.Cfg()
	h := m.s.buildInnerHeader(m.outer, o.H, http.MethodGet, "websocket", "websocket")
	if org := m.outer.Header.Get("Origin"); org != "" {
		h.Set("Origin", org)
	}
	h.Del("Sec-Fetch-Mode")
	h.Del("Sec-Fetch-Dest")
	if len(o.P) > 0 {
		h.Set("Sec-WebSocket-Protocol", strings.Join(o.P, ", "))
	}
	ctx, cancel := context.WithTimeout(m.ctx, 30*time.Second)
	up, res, err := wsproto.Dial(ctx, cfg.Upstream, o.U, h)
	cancel()
	if err != nil || up == nil {
		status := 0
		if res != nil {
			status = res.Status
		}
		m.drop(c.id)
		m.sendErr(c.id, "SEAL_UPSTREAM_REFUSED", "upstream refused the socket", status)
		return
	}
	m.pumpWS(c, up, res.Protocol)
}

// pumpWS relays one established inner socket in both directions.
func (m *muxConn) pumpWS(c *muxChan, up *wsproto.Conn, protocol string) {
	m.cmu.Lock()
	if _, live := m.chans[c.id]; !live {
		m.cmu.Unlock()
		up.Close()
		return
	}
	c.up = up
	m.cmu.Unlock()
	b, _ := json.Marshal(map[string]string{"p": protocol, "x": ""})
	m.send(MOpened, c.id, b)

	// client -> upstream, in order; credit flows back as bytes are written.
	go func() {
		for {
			select {
			case msg := <-c.toUp:
				if msg.op == wsproto.OpClose {
					code := int(binary.BigEndian.Uint16(msg.data))
					up.WriteClose(code, string(msg.data[2:]))
					// wait for the upstream close reply in the reader below
					up.NetConn().SetReadDeadline(time.Now().Add(5 * time.Second))
					return
				}
				if err := up.WriteMessage(msg.op, msg.data); err != nil {
					return
				}
				m.send(MCredit, c.id, binary.BigEndian.AppendUint32(nil, uint32(len(msg.data))))
			case <-m.ctx.Done():
				return
			}
		}
	}()
	// upstream -> client
	for {
		op, data, err := up.ReadMessage()
		if err != nil {
			code, reason := 1006, ""
			var ce *wsproto.CloseError
			if errors.As(err, &ce) {
				code, reason = ce.Code, ce.Reason
			}
			if code == 1005 {
				code = 1000
			}
			m.send(MClose, c.id, closePayload(code, reason))
			m.drop(c.id)
			return
		}
		if err := m.sendData(c, op, data); err != nil {
			m.drop(c.id)
			return
		}
	}
}

// runHTTP performs one inner HTTP request (EventSource) and streams its body.
func (m *muxConn) runHTTP(ctx context.Context, c *muxChan, o openMsg) {
	cfg := m.s.Cfg()
	method := o.M
	if method == "" {
		method = http.MethodGet
	}
	if method != http.MethodGet {
		m.drop(c.id)
		m.sendErr(c.id, "SEAL_BAD_REQUEST", "mux http channels are GET only", 0)
		return
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://"+cfg.Upstream+o.U, nil)
	if err != nil {
		m.drop(c.id)
		m.sendErr(c.id, "SEAL_BAD_REQUEST", "inner request rejected", 0)
		return
	}
	req.Header = m.s.buildInnerHeader(m.outer, o.H, method, o.MD, o.DT)
	req.Host = m.outer.Host
	req.Header.Del("Host")
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := m.s.upstream.RoundTrip(req)
	if err != nil {
		m.drop(c.id)
		m.sendErr(c.id, "SEAL_UPSTREAM_DOWN", "upstream unreachable", 502)
		return
	}
	defer resp.Body.Close()
	ih := innerHead{S: resp.StatusCode, H: [][2]string{}}
	for k, vs := range resp.Header {
		if hopByHop[k] {
			continue
		}
		for _, v := range vs {
			ih.H = append(ih.H, [2]string{k, v})
		}
	}
	b, _ := json.Marshal(ih)
	m.send(MOpened, c.id, b)
	buf := make([]byte, chunk)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if e := m.sendData(c, wsproto.OpBinary, append([]byte(nil), buf[:n]...)); e != nil {
				m.drop(c.id)
				return
			}
		}
		if err != nil {
			code := 1000
			if err != io.EOF {
				code = 1011
			}
			m.send(MClose, c.id, closePayload(code, ""))
			m.drop(c.id)
			return
		}
	}
}

// runEgressWS dials a WebSocket on another host for the page (sealed egress).
func (m *muxConn) runEgressWS(c *muxChan, o openMsg) {
	host := hostOf(o.U)
	release, ee := m.s.Egress.admitSocket(m.sess.Email)
	if ee == nil {
		ctx, cancel := context.WithTimeout(m.ctx, 30*time.Second)
		var up *wsproto.Conn
		var res *wsproto.DialResult
		up, res, ee = m.s.Egress.DialWS(ctx, o.U, o.P, pageOrigin(m.outer))
		cancel()
		if ee == nil {
			m.s.M.EgressSockets.Add(1)
			m.s.Egress.record(m.sess.Email, host, 101, "", 0)
			defer release()
			m.pumpWS(c, up, res.Protocol)
			return
		}
		release()
	}
	m.s.M.EgressRefused.Add(1)
	m.s.Egress.record(m.sess.Email, host, ee.Status, ee.Code, 0)
	m.drop(c.id)
	m.sendErr(c.id, ee.Code, ee.Msg, ee.Status)
}

// runEgressHTTP streams a GET (EventSource) from another host for the page.
func (m *muxConn) runEgressHTTP(ctx context.Context, c *muxChan, o openMsg) {
	host := hostOf(o.U)
	fail := func(ee *EgressError) {
		m.s.M.EgressRefused.Add(1)
		m.s.Egress.record(m.sess.Email, host, ee.Status, ee.Code, 0)
		m.drop(c.id)
		m.sendErr(c.id, ee.Code, ee.Msg, ee.Status)
	}
	if o.M != "" && o.M != http.MethodGet {
		fail(egErr("SEAL_BAD_REQUEST", 400, "mux http channels are GET only"))
		return
	}
	release, ee := m.s.Egress.admitSocket(m.sess.Email)
	if ee != nil {
		fail(ee)
		return
	}
	defer release()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	resp, ee := m.s.Egress.Fetch(ctx, &EgressRequest{Method: http.MethodGet, URL: o.U, Header: o.H, Mode: o.MD, Dest: o.DT, Origin: pageOrigin(m.outer), Identity: m.sess.Email})
	if ee != nil {
		fail(ee)
		return
	}
	var body io.ReadCloser = withIdle(resp.Body, 10*time.Minute, cancel)
	defer body.Close()
	if resp.Gzip {
		zr, err := gzip.NewReader(body)
		if err != nil {
			fail(egErr("SEAL_EGRESS_FAILED", 502, "bad gzip"))
			return
		}
		body = io.NopCloser(zr)
	}
	ih := innerHead{S: resp.Status, H: [][2]string{}, U: resp.FinalURL}
	for k, vs := range resp.Header {
		for _, v := range vs {
			ih.H = append(ih.H, [2]string{k, v})
		}
	}
	b, _ := json.Marshal(ih)
	m.send(MOpened, c.id, b)
	m.s.M.EgressSockets.Add(1)
	var total int64
	buf := make([]byte, chunk)
	defer func() { m.s.Egress.record(m.sess.Email, host, resp.Status, "", total) }()
	for {
		n, err := body.Read(buf)
		if n > 0 {
			total += int64(n)
			if e := m.sendData(c, wsproto.OpBinary, append([]byte(nil), buf[:n]...)); e != nil {
				m.drop(c.id)
				return
			}
		}
		if err != nil {
			code := 1000
			if err != io.EOF {
				code = 1011
			}
			m.send(MClose, c.id, closePayload(code, ""))
			m.drop(c.id)
			return
		}
	}
}
