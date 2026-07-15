// Package http2 implements just enough of HTTP/2 (RFC 7540) and HPACK
// (RFC 7541), by hand and with no third-party dependencies, to run the
// "single-packet attack": pre-send the HEADERS (and body) of many streams,
// then release one empty END_STREAM DATA frame per stream in a single TCP
// write so the server receives — and processes — them with almost no jitter.
package http2

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Frame types (RFC 7540 §6).
const (
	frameData         = 0x0
	frameHeaders      = 0x1
	frameRSTStream    = 0x3
	frameSettings     = 0x4
	framePing         = 0x6
	frameGoAway       = 0x7
	frameWindowUpdate = 0x8
	frameContinuation = 0x9
)

// Frame flags.
const (
	flagEndStream  = 0x1  // DATA, HEADERS
	flagAck        = 0x1  // SETTINGS, PING
	flagEndHeaders = 0x4  // HEADERS, CONTINUATION
	flagPadded     = 0x8  // DATA, HEADERS
	flagPriority   = 0x20 // HEADERS
)

// SETTINGS identifiers (RFC 7540 §6.5.2).
const (
	settingHeaderTableSize   = 0x1
	settingEnablePush        = 0x2
	settingMaxConcurrent     = 0x3
	settingInitialWindowSize = 0x4
	settingMaxFrameSize      = 0x5
)

const clientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// frame is a decoded HTTP/2 frame.
type frame struct {
	Type     byte
	Flags    byte
	StreamID uint32
	Payload  []byte
}

// appendFrame appends a serialized frame to dst and returns the extended slice.
// It lets callers coalesce many frames into one buffer for a single Write.
func appendFrame(dst []byte, typ, flags byte, streamID uint32, payload []byte) []byte {
	var hdr [9]byte
	n := len(payload)
	hdr[0] = byte(n >> 16)
	hdr[1] = byte(n >> 8)
	hdr[2] = byte(n)
	hdr[3] = typ
	hdr[4] = flags
	binary.BigEndian.PutUint32(hdr[5:], streamID&0x7fffffff)
	dst = append(dst, hdr[:]...)
	dst = append(dst, payload...)
	return dst
}

// readFrame reads one frame from r. maxPayload guards against absurd lengths.
func readFrame(r io.Reader, maxPayload uint32) (frame, error) {
	var hdr [9]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return frame{}, err
	}
	length := uint32(hdr[0])<<16 | uint32(hdr[1])<<8 | uint32(hdr[2])
	if length > maxPayload {
		return frame{}, fmt.Errorf("frame payload %d exceeds max %d", length, maxPayload)
	}
	f := frame{
		Type:     hdr[3],
		Flags:    hdr[4],
		StreamID: binary.BigEndian.Uint32(hdr[5:]) & 0x7fffffff,
	}
	if length > 0 {
		f.Payload = make([]byte, length)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return frame{}, err
		}
	}
	return f, nil
}

// dataBody returns the application data of a DATA frame, stripping any padding.
func (f frame) dataBody() ([]byte, error) {
	if f.Flags&flagPadded == 0 {
		return f.Payload, nil
	}
	if len(f.Payload) < 1 {
		return nil, fmt.Errorf("padded DATA frame too short")
	}
	padLen := int(f.Payload[0])
	body := f.Payload[1:]
	if padLen > len(body) {
		return nil, fmt.Errorf("DATA pad length %d exceeds payload", padLen)
	}
	return body[:len(body)-padLen], nil
}

// headerBlock returns the header block fragment of a HEADERS frame, stripping
// padding and the optional priority field.
func (f frame) headerBlock() ([]byte, error) {
	p := f.Payload
	padLen := 0
	if f.Flags&flagPadded != 0 {
		if len(p) < 1 {
			return nil, fmt.Errorf("padded HEADERS frame too short")
		}
		padLen = int(p[0])
		p = p[1:]
	}
	if f.Flags&flagPriority != 0 {
		if len(p) < 5 {
			return nil, fmt.Errorf("HEADERS frame with PRIORITY too short")
		}
		p = p[5:]
	}
	if padLen > len(p) {
		return nil, fmt.Errorf("HEADERS pad length %d exceeds fragment", padLen)
	}
	return p[:len(p)-padLen], nil
}

// settingsPayload encodes a list of (id, value) settings.
func settingsPayload(kv ...[2]uint32) []byte {
	out := make([]byte, 0, len(kv)*6)
	for _, s := range kv {
		var b [6]byte
		binary.BigEndian.PutUint16(b[0:], uint16(s[0]))
		binary.BigEndian.PutUint32(b[2:], s[1])
		out = append(out, b[:]...)
	}
	return out
}

// windowUpdatePayload encodes a WINDOW_UPDATE increment.
func windowUpdatePayload(inc uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], inc&0x7fffffff)
	return b[:]
}
