package http2

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/skaterzeal/syncburst/internal/engine"
	"github.com/skaterzeal/syncburst/internal/request"
)

// Engine sends synchronized HTTP/2 bursts using the single-packet attack.
type Engine struct {
	DialTimeout time.Duration
	ReadTimeout time.Duration
	SettleDelay time.Duration
	Insecure    bool
}

// New returns an Engine with sensible defaults.
func New() *Engine {
	return &Engine{
		DialTimeout: 10 * time.Second,
		ReadTimeout: 15 * time.Second,
		SettleDelay: 30 * time.Millisecond,
		Insecure:    false,
	}
}

// Protocol implements engine.Firer.
func (e *Engine) Protocol() string { return "HTTP/2" }

const (
	maxFramePayload     = 1 << 20
	defaultPeerMaxFrame = 16 * 1024
	defaultFlowWindow   = 65_535
)

type peerSettings struct {
	maxFrameSize      uint32
	initialWindowSize uint32
	maxConcurrent     uint32
	hasMaxConcurrent  bool
}

type streamState struct {
	reqIndex        int
	headerAcc       []byte
	gotHeaders      bool
	headerEndStream bool
	status          int
	bodyLen         int
	body            []byte
	done            bool
	doneAt          time.Time
	err             error
}

// Fire opens one h2 connection, pre-sends every stream's HEADERS (and body),
// then releases one END_STREAM DATA frame per stream in a single write.
func (e *Engine) Fire(reqs []request.Request) ([]engine.Response, error) {
	if len(reqs) == 0 {
		return nil, fmt.Errorf("no requests")
	}
	auth := reqs[0].Authority
	for i, r := range reqs {
		if err := r.Validate(); err != nil {
			return nil, fmt.Errorf("request %d: %w", i+1, err)
		}
		if r.Scheme != "https" {
			return nil, fmt.Errorf("HTTP/2 engine supports TLS targets only; use -proto http1 for %q", r.Scheme)
		}
		if r.Authority != auth {
			return nil, fmt.Errorf("HTTP/2 burst requires a single authority; got %q and %q", auth, r.Authority)
		}
	}

	conn, err := e.dial(reqs[0])
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	br := bufio.NewReaderSize(conn, 64*1024)

	// Connection preface + our SETTINGS + a large connection-level window.
	var setup []byte
	setup = append(setup, clientPreface...)
	setup = appendFrame(setup, frameSettings, 0, 0, settingsPayload(
		[2]uint32{settingHeaderTableSize, 0},         // disable server's dynamic table
		[2]uint32{settingEnablePush, 0},              // this client does not accept server push
		[2]uint32{settingInitialWindowSize, 1 << 30}, // large receive window per stream
	))
	setup = appendFrame(setup, frameWindowUpdate, 0, 0, windowUpdatePayload(1<<30))
	if err := conn.SetWriteDeadline(time.Now().Add(e.ReadTimeout)); err != nil {
		return nil, fmt.Errorf("set setup write deadline: %w", err)
	}
	if err := writeOnce(conn, setup); err != nil {
		return nil, fmt.Errorf("write preface/settings: %w", err)
	}
	peer, err := e.readPeerSettings(conn, br)
	if err != nil {
		return nil, err
	}
	if peer.hasMaxConcurrent && uint32(len(reqs)) > peer.maxConcurrent {
		return nil, fmt.Errorf("server permits at most %d concurrent HTTP/2 streams; requested %d", peer.maxConcurrent, len(reqs))
	}

	streams := make(map[uint32]*streamState, len(reqs))
	order := make([]uint32, len(reqs))

	// Pre-send phase: HEADERS (+ body) for every stream, no END_STREAM yet.
	var pre []byte
	totalBodyBytes := 0
	for i := range reqs {
		id := uint32(2*i + 1)
		order[i] = id
		streams[id] = &streamState{reqIndex: i}
		block, err := encodeRequestHeaders(reqs[i])
		if err != nil {
			return nil, fmt.Errorf("stream %d headers: %w", id, err)
		}
		if len(block) > maxFramePayload {
			return nil, fmt.Errorf("stream %d: header block too large", id)
		}
		pre = appendHeaderFrames(pre, id, block, int(peer.maxFrameSize))
		if len(reqs[i].Body) > 0 {
			if uint32(len(reqs[i].Body)) > peer.initialWindowSize {
				return nil, fmt.Errorf("stream %d body (%d bytes) exceeds peer's initial flow-control window (%d bytes)", id, len(reqs[i].Body), peer.initialWindowSize)
			}
			totalBodyBytes += len(reqs[i].Body)
			if totalBodyBytes > defaultFlowWindow {
				return nil, fmt.Errorf("burst request bodies total %d bytes, exceeding the initial connection flow-control window (%d bytes)", totalBodyBytes, defaultFlowWindow)
			}
			pre = appendDataFrames(pre, id, reqs[i].Body, int(peer.maxFrameSize))
		}
	}
	if err := conn.SetWriteDeadline(time.Now().Add(e.ReadTimeout)); err != nil {
		return nil, fmt.Errorf("set pre-send write deadline: %w", err)
	}
	if err := writeOnce(conn, pre); err != nil {
		return nil, fmt.Errorf("write headers: %w", err)
	}

	if e.SettleDelay > 0 {
		time.Sleep(e.SettleDelay)
	}

	// Release phase: one empty END_STREAM DATA frame per stream, single write.
	var release []byte
	for _, id := range order {
		release = appendFrame(release, frameData, flagEndStream, id, nil)
	}
	t0 := time.Now()
	if err := conn.SetWriteDeadline(t0.Add(e.ReadTimeout)); err != nil {
		return nil, fmt.Errorf("set release write deadline: %w", err)
	}
	if err := writeOnce(conn, release); err != nil {
		return nil, fmt.Errorf("write release packet: %w", err)
	}
	_ = conn.SetWriteDeadline(time.Time{})

	deadline := t0.Add(e.ReadTimeout)
	if err := e.readLoop(conn, br, streams, deadline); err != nil {
		for _, s := range streams {
			if !s.done && s.err == nil {
				s.err = fmt.Errorf("connection read: %w", err)
			}
		}
	}

	return collect(reqs, streams, order, t0), nil
}

func (e *Engine) readPeerSettings(conn net.Conn, br *bufio.Reader) (peerSettings, error) {
	peer := peerSettings{
		maxFrameSize:      defaultPeerMaxFrame,
		initialWindowSize: defaultFlowWindow,
	}
	if err := conn.SetReadDeadline(time.Now().Add(e.ReadTimeout)); err != nil {
		return peer, fmt.Errorf("set SETTINGS read deadline: %w", err)
	}
	f, err := readFrame(br, maxFramePayload)
	if err != nil {
		return peer, fmt.Errorf("read server SETTINGS: %w", err)
	}
	if f.Type != frameSettings || f.StreamID != 0 || f.Flags&flagAck != 0 {
		return peer, fmt.Errorf("invalid HTTP/2 handshake: first server frame must be non-ACK SETTINGS")
	}
	if len(f.Payload)%6 != 0 {
		return peer, fmt.Errorf("invalid server SETTINGS length %d", len(f.Payload))
	}
	for off := 0; off < len(f.Payload); off += 6 {
		id := binary.BigEndian.Uint16(f.Payload[off : off+2])
		value := binary.BigEndian.Uint32(f.Payload[off+2 : off+6])
		switch id {
		case settingMaxConcurrent:
			peer.maxConcurrent = value
			peer.hasMaxConcurrent = true
		case settingInitialWindowSize:
			if value > 1<<31-1 {
				return peer, fmt.Errorf("invalid SETTINGS_INITIAL_WINDOW_SIZE %d", value)
			}
			peer.initialWindowSize = value
		case settingMaxFrameSize:
			if value < defaultPeerMaxFrame || value > 1<<24-1 {
				return peer, fmt.Errorf("invalid SETTINGS_MAX_FRAME_SIZE %d", value)
			}
			peer.maxFrameSize = value
		}
	}
	if err := conn.SetWriteDeadline(time.Now().Add(e.ReadTimeout)); err != nil {
		return peer, fmt.Errorf("set SETTINGS ACK write deadline: %w", err)
	}
	if err := writeOnce(conn, appendFrame(nil, frameSettings, flagAck, 0, nil)); err != nil {
		return peer, fmt.Errorf("write SETTINGS ACK: %w", err)
	}
	_ = conn.SetReadDeadline(time.Time{})
	_ = conn.SetWriteDeadline(time.Time{})
	return peer, nil
}

func appendHeaderFrames(dst []byte, streamID uint32, block []byte, maxSize int) []byte {
	if len(block) == 0 {
		return appendFrame(dst, frameHeaders, flagEndHeaders, streamID, nil)
	}
	first := true
	for len(block) > 0 {
		n := min(len(block), maxSize)
		typ := byte(frameContinuation)
		if first {
			typ = frameHeaders
			first = false
		}
		flags := byte(0)
		if n == len(block) {
			flags = flagEndHeaders
		}
		dst = appendFrame(dst, typ, flags, streamID, block[:n])
		block = block[n:]
	}
	return dst
}

func appendDataFrames(dst []byte, streamID uint32, body []byte, maxSize int) []byte {
	for len(body) > 0 {
		n := min(len(body), maxSize)
		dst = appendFrame(dst, frameData, 0, streamID, body[:n])
		body = body[n:]
	}
	return dst
}

func writeOnce(conn net.Conn, payload []byte) error {
	n, err := conn.Write(payload)
	if err != nil {
		return err
	}
	if n != len(payload) {
		return fmt.Errorf("short write: wrote %d of %d bytes", n, len(payload))
	}
	return nil
}

func (e *Engine) readLoop(conn net.Conn, br *bufio.Reader, streams map[uint32]*streamState, deadline time.Time) error {
	remaining := len(streams)
	var continuationStream uint32
	for remaining > 0 {
		_ = conn.SetReadDeadline(deadline)
		f, err := readFrame(br, maxFramePayload)
		if err != nil {
			return err
		}
		if continuationStream != 0 {
			if f.Type != frameContinuation || f.StreamID != continuationStream {
				return fmt.Errorf("expected CONTINUATION for stream %d", continuationStream)
			}
		} else if f.Type == frameContinuation {
			return fmt.Errorf("unexpected CONTINUATION for stream %d", f.StreamID)
		}
		switch f.Type {
		case frameSettings:
			if f.StreamID != 0 || len(f.Payload)%6 != 0 {
				return fmt.Errorf("malformed SETTINGS frame")
			}
			if f.Flags&flagAck != 0 && len(f.Payload) != 0 {
				return fmt.Errorf("SETTINGS ACK must have an empty payload")
			}
			if f.Flags&flagAck == 0 {
				if err := conn.SetWriteDeadline(deadline); err != nil {
					return err
				}
				if err := writeOnce(conn, appendFrame(nil, frameSettings, flagAck, 0, nil)); err != nil {
					return fmt.Errorf("acknowledge SETTINGS: %w", err)
				}
			}
		case framePing:
			if f.StreamID != 0 || len(f.Payload) != 8 {
				return fmt.Errorf("malformed PING frame")
			}
			if f.Flags&flagAck == 0 {
				if err := conn.SetWriteDeadline(deadline); err != nil {
					return err
				}
				if err := writeOnce(conn, appendFrame(nil, framePing, flagAck, 0, f.Payload)); err != nil {
					return fmt.Errorf("acknowledge PING: %w", err)
				}
			}
		case frameGoAway:
			return fmt.Errorf("server sent GOAWAY")
		case frameWindowUpdate, frameRSTStream:
			if f.Type == frameRSTStream {
				if s := streams[f.StreamID]; s != nil && !s.done {
					s.err = fmt.Errorf("stream reset by server")
					s.done = true
					s.doneAt = time.Now()
					remaining--
				}
			}
		case frameHeaders, frameContinuation:
			if f.StreamID == 0 {
				return fmt.Errorf("header frame on stream 0")
			}
			if f.Type == frameHeaders && f.Flags&flagEndHeaders == 0 {
				continuationStream = f.StreamID
			}
			if f.Type == frameContinuation && f.Flags&flagEndHeaders != 0 {
				continuationStream = 0
			}
			s := streams[f.StreamID]
			if s == nil || s.done {
				continue
			}
			var fragment []byte
			if f.Type == frameHeaders {
				s.headerAcc = nil
				s.headerEndStream = f.Flags&flagEndStream != 0
				block, err := f.headerBlock()
				if err != nil {
					s.err = err
				} else {
					fragment = block
				}
			} else {
				fragment = f.Payload
			}
			if len(s.headerAcc)+len(fragment) > maxFramePayload {
				s.err = fmt.Errorf("response header block exceeds %d bytes", maxFramePayload)
			} else {
				s.headerAcc = append(s.headerAcc, fragment...)
			}
			if f.Flags&flagEndHeaders != 0 {
				if !s.gotHeaders && s.err == nil {
					st, err := statusFromBlock(s.headerAcc)
					switch {
					case err != nil:
						s.err = fmt.Errorf("decode response headers: %w", err)
					case st == 0:
						s.err = fmt.Errorf("response headers did not contain :status")
					case st >= 100 && st < 200:
						// Informational response; wait for the final header block.
					case st < 100 || st > 599:
						s.err = fmt.Errorf("invalid response status %d", st)
					default:
						s.status = st
						s.gotHeaders = true
					}
				}
				s.headerAcc = nil
			}
			if f.Flags&flagEndHeaders != 0 && s.headerEndStream && !s.done {
				if !s.gotHeaders && s.err == nil {
					s.err = fmt.Errorf("stream ended before final response headers")
				}
				s.done = true
				s.doneAt = time.Now()
				remaining--
			}
			if f.Flags&flagEndHeaders != 0 {
				s.headerEndStream = false
			}
		case frameData:
			s := streams[f.StreamID]
			if s == nil || s.done {
				continue
			}
			if !s.gotHeaders && s.err == nil {
				s.err = fmt.Errorf("DATA received before final response headers")
			}
			body, err := f.dataBody()
			if err != nil {
				s.err = err
			} else {
				s.bodyLen += len(body)
				if remainingCap := engine.BodyCap - len(s.body); remainingCap > 0 {
					if len(body) > remainingCap {
						body = body[:remainingCap]
					}
					s.body = append(s.body, body...)
				}
			}
			if f.Flags&flagEndStream != 0 {
				s.done = true
				s.doneAt = time.Now()
				remaining--
			}
		}
	}
	return nil
}

func collect(reqs []request.Request, streams map[uint32]*streamState, order []uint32, t0 time.Time) []engine.Response {
	out := make([]engine.Response, len(reqs))
	for _, id := range order {
		s := streams[id]
		r := engine.Response{Index: s.reqIndex, StreamID: id, Status: s.status, Body: s.body, BodyLen: s.bodyLen, Err: s.err}
		if s.done && s.err == nil {
			r.Duration = s.doneAt.Sub(t0)
		}
		if !s.done && s.err == nil {
			r.Err = fmt.Errorf("no response before deadline")
		}
		out[s.reqIndex] = r
	}
	return out
}

func (e *Engine) dial(r request.Request) (net.Conn, error) {
	d := net.Dialer{Timeout: e.DialTimeout}
	raw, err := d.Dial("tcp", r.DialAddress())
	if err != nil {
		return nil, err
	}
	if tc, ok := raw.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	cfg := &tls.Config{
		ServerName:         r.Host(),
		NextProtos:         []string{"h2"},
		InsecureSkipVerify: e.Insecure,
		MinVersion:         tls.VersionTLS12,
	}
	tconn := tls.Client(raw, cfg)
	if e.DialTimeout > 0 {
		_ = tconn.SetDeadline(time.Now().Add(e.DialTimeout))
	}
	if err := tconn.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	if p := tconn.ConnectionState().NegotiatedProtocol; p != "h2" {
		_ = tconn.SetDeadline(time.Time{})
		tconn.Close()
		return nil, fmt.Errorf("server did not negotiate h2 (got %q); the target may not support HTTP/2", p)
	}
	_ = tconn.SetDeadline(time.Time{})
	return tconn, nil
}
