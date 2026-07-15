package http2

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/skaterzeal/syncburst/internal/request"
)

// staticTable is the RFC 7541 Appendix A static table (index 1..61). Index 0 is
// unused. syncburst disables the HPACK dynamic table (HEADER_TABLE_SIZE=0), so
// this static table plus literal fields is sufficient to locate ":status".
var staticTable = []struct{ name, value string }{
	{"", ""}, // 0 (unused)
	{":authority", ""},
	{":method", "GET"},
	{":method", "POST"},
	{":path", "/"},
	{":path", "/index.html"},
	{":scheme", "http"},
	{":scheme", "https"},
	{":status", "200"},
	{":status", "204"},
	{":status", "206"},
	{":status", "304"},
	{":status", "400"},
	{":status", "404"},
	{":status", "500"},
	{"accept-charset", ""},
	{"accept-encoding", "gzip, deflate"},
	{"accept-language", ""},
	{"accept-ranges", ""},
	{"accept", ""},
	{"access-control-allow-origin", ""},
	{"age", ""},
	{"allow", ""},
	{"authorization", ""},
	{"cache-control", ""},
	{"content-disposition", ""},
	{"content-encoding", ""},
	{"content-language", ""},
	{"content-length", ""},
	{"content-location", ""},
	{"content-range", ""},
	{"content-type", ""},
	{"cookie", ""},
	{"date", ""},
	{"etag", ""},
	{"expect", ""},
	{"expires", ""},
	{"from", ""},
	{"host", ""},
	{"if-match", ""},
	{"if-modified-since", ""},
	{"if-none-match", ""},
	{"if-range", ""},
	{"if-unmodified-since", ""},
	{"last-modified", ""},
	{"link", ""},
	{"location", ""},
	{"max-forwards", ""},
	{"proxy-authenticate", ""},
	{"proxy-authorization", ""},
	{"range", ""},
	{"referer", ""},
	{"refresh", ""},
	{"retry-after", ""},
	{"server", ""},
	{"set-cookie", ""},
	{"strict-transport-security", ""},
	{"transfer-encoding", ""},
	{"user-agent", ""},
	{"vary", ""},
	{"via", ""},
	{"www-authenticate", ""},
}

// --- Encoder (requests) ---

// encodeRequestHeaders serializes a request's header block using only "literal
// header field without indexing" entries with literal (non-Huffman) names and
// values. This is always valid, requires no encoder state, and keeps every
// stream's header block independent — ideal for the single-packet attack.
func encodeRequestHeaders(r request.Request) ([]byte, error) {
	var dst []byte
	dst = appendLiteralHeader(dst, ":method", r.Method)
	dst = appendLiteralHeader(dst, ":scheme", r.Scheme)
	dst = appendLiteralHeader(dst, ":authority", r.Authority)
	path := r.Path
	if path == "" {
		path = "/"
	}
	dst = appendLiteralHeader(dst, ":path", path)
	for _, h := range r.Headers {
		name := strings.ToLower(h.Name)
		if strings.ContainsAny(name+h.Value, "\r\n") || !validHeaderName(name) {
			return nil, fmt.Errorf("invalid HTTP/2 header %q", h.Name)
		}
		switch name {
		case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade":
			return nil, fmt.Errorf("header %q is forbidden in HTTP/2", name)
		case "host", "content-length":
			// :authority carries Host; content-length is generated below.
			continue
		case "te":
			if !strings.EqualFold(strings.TrimSpace(h.Value), "trailers") {
				return nil, fmt.Errorf("HTTP/2 TE header may only contain trailers")
			}
		}
		dst = appendLiteralHeader(dst, name, h.Value)
	}
	if len(r.Body) > 0 {
		dst = appendLiteralHeader(dst, "content-length", strconv.Itoa(len(r.Body)))
	}
	return dst, nil
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if r <= 0x20 || r >= 0x7f || strings.ContainsRune(`()<>@,;:\"/[]?={}`, r) {
			return false
		}
	}
	return true
}

func appendLiteralHeader(dst []byte, name, value string) []byte {
	dst = append(dst, 0x00) // literal without indexing, new name
	dst = appendHpackString(dst, name)
	dst = appendHpackString(dst, value)
	return dst
}

func appendHpackString(dst []byte, s string) []byte {
	dst = appendHpackInt(dst, len(s), 7, 0x00) // H bit = 0 (no Huffman)
	return append(dst, s...)
}

func appendHpackInt(dst []byte, value int, prefixBits uint8, highBits byte) []byte {
	max := (1 << prefixBits) - 1
	if value < max {
		return append(dst, highBits|byte(value))
	}
	dst = append(dst, highBits|byte(max))
	value -= max
	for value >= 128 {
		dst = append(dst, byte(value%128+128))
		value /= 128
	}
	return append(dst, byte(value))
}

// --- Decoder (responses) ---

// statusFromBlock parses an HPACK-encoded response header block and returns the
// :status code. It maintains no dynamic table (the server is told the table
// size is 0). Non-status headers are skipped by their explicit length; a
// Huffman-encoded non-status string is never decoded. Returns 0 if the status
// could not be determined.
func statusFromBlock(block []byte) (int, error) {
	i := 0
	status := 0
	for i < len(block) {
		b := block[i]
		switch {
		case b&0x80 != 0: // indexed header field
			idx, n, err := readHpackInt(block[i:], 7)
			if err != nil {
				return status, err
			}
			i += n
			if name, val, ok := staticLookup(idx); ok && name == ":status" {
				if s, err := strconv.Atoi(val); err == nil {
					status = s
				}
			}
		case b&0xc0 == 0x40: // literal with incremental indexing (6-bit index)
			var err error
			if i, status, err = readLiteral(block, i, 6, status); err != nil {
				return status, err
			}
		case b&0xe0 == 0x20: // dynamic table size update (5-bit) — ignored
			_, n, err := readHpackInt(block[i:], 5)
			if err != nil {
				return status, err
			}
			i += n
		default: // literal without indexing / never indexed (4-bit index)
			var err error
			if i, status, err = readLiteral(block, i, 4, status); err != nil {
				return status, err
			}
		}
	}
	return status, nil
}

// readLiteral parses a literal header field whose index uses prefixBits, reads
// its name and value, and updates status if the field is ":status".
func readLiteral(block []byte, i int, prefixBits uint8, status int) (int, int, error) {
	idx, n, err := readHpackInt(block[i:], prefixBits)
	if err != nil {
		return i, status, err
	}
	i += n

	var name string
	if idx == 0 {
		nameBytes, next, _, err := readHpackString(block, i)
		if err != nil {
			return i, status, err
		}
		i = next
		name = string(nameBytes)
	} else if nm, _, ok := staticLookup(idx); ok {
		name = nm
	}

	valBytes, next, ok, err := readHpackString(block, i)
	if err != nil {
		return i, status, err
	}
	i = next
	if name == ":status" && ok {
		if s, err := strconv.Atoi(string(valBytes)); err == nil {
			status = s
		}
	}
	return i, status, nil
}

func staticLookup(idx int) (name, value string, ok bool) {
	if idx >= 1 && idx < len(staticTable) {
		e := staticTable[idx]
		return e.name, e.value, true
	}
	// Dynamic-table indices should not occur (table size 0); report not found.
	return "", "", false
}

// readHpackInt decodes an HPACK integer with the given prefix (RFC 7541 §5.1).
func readHpackInt(buf []byte, prefixBits uint8) (int, int, error) {
	if len(buf) == 0 {
		return 0, 0, fmt.Errorf("hpack int: empty")
	}
	max := (1 << prefixBits) - 1
	val := int(buf[0]) & max
	if val < max {
		return val, 1, nil
	}
	shift := 0
	for n := 1; n < len(buf); n++ {
		b := buf[n]
		val += int(b&0x7f) << shift
		if b&0x80 == 0 {
			return val, n + 1, nil
		}
		shift += 7
		if shift > 28 {
			return 0, 0, fmt.Errorf("hpack int: too large")
		}
	}
	return 0, 0, fmt.Errorf("hpack int: truncated")
}

// readHpackString reads a length-prefixed string. It always advances past the
// string; decodeOK is false when a Huffman string used unsupported (non-digit)
// symbols, in which case the decoded bytes are nil but the position is correct.
func readHpackString(buf []byte, pos int) (decoded []byte, newPos int, decodeOK bool, err error) {
	if pos >= len(buf) {
		return nil, pos, false, fmt.Errorf("hpack string: out of range")
	}
	huff := buf[pos]&0x80 != 0
	length, n, err := readHpackInt(buf[pos:], 7)
	if err != nil {
		return nil, pos, false, err
	}
	start := pos + n
	end := start + length
	if end > len(buf) {
		return nil, pos, false, fmt.Errorf("hpack string: length exceeds block")
	}
	raw := buf[start:end]
	if !huff {
		return raw, end, true, nil
	}
	dec, derr := decodeHuffman(raw)
	if derr != nil {
		return nil, end, false, nil // advance, but mark undecodable
	}
	return dec, end, true, nil
}
