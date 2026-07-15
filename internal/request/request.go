// Package request parses raw HTTP requests (Burp-style) into a protocol-neutral
// form that both the HTTP/1.1 and HTTP/2 engines can serialize and send.
package request

import (
	"bytes"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Header is a single ordered header. Names are stored lowercased so the same
// Request can be serialized to HTTP/1.1 or HTTP/2 (which requires lowercase).
type Header struct {
	Name  string
	Value string
}

// Request is one HTTP request, independent of protocol version. Host is kept in
// Authority (not in Headers) because HTTP/2 carries it as the :authority
// pseudo-header while HTTP/1.1 carries it as the Host header.
type Request struct {
	Method    string
	Scheme    string // "http" or "https"
	Authority string // host[:port]
	Path      string // origin-form target, e.g. "/redeem?x=1"
	Headers   []Header
	Body      []byte
}

const (
	maxMethodBytes    = 64
	maxAuthorityBytes = 1 << 10
	maxPathBytes      = 8 << 10
	maxHeaderCount    = 200
	maxHeaderBytes    = 64 << 10
	maxBodyBytes      = 1 << 20
)

// ParseFile parses one or more raw requests from the bytes of a request file.
// Multiple requests are separated by a line containing only "---". A single
// request (no separator) yields a one-element slice.
func ParseFile(data []byte) ([]Request, error) {
	blocks := splitBlocks(data)
	if len(blocks) == 0 {
		return nil, fmt.Errorf("no request found in input")
	}
	reqs := make([]Request, 0, len(blocks))
	for i, b := range blocks {
		r, err := ParseOne(b)
		if err != nil {
			return nil, fmt.Errorf("request %d: %w", i+1, err)
		}
		reqs = append(reqs, r)
	}
	return reqs, nil
}

// splitBlocks splits on a line that trims to exactly "---".
func splitBlocks(data []byte) [][]byte {
	lines := bytes.Split(normalizeNewlines(data), []byte("\n"))
	var blocks [][]byte
	var cur [][]byte
	flush := func() {
		joined := bytes.Join(cur, []byte("\n"))
		if len(bytes.TrimSpace(joined)) > 0 {
			blocks = append(blocks, joined)
		}
		cur = nil
	}
	for _, ln := range lines {
		if string(bytes.TrimSpace(ln)) == "---" {
			flush()
			continue
		}
		cur = append(cur, ln)
	}
	flush()
	return blocks
}

func normalizeNewlines(data []byte) []byte {
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	return bytes.ReplaceAll(data, []byte("\r"), []byte("\n"))
}

// ParseOne parses a single raw HTTP request block.
func ParseOne(block []byte) (Request, error) {
	block = normalizeNewlines(block)
	// Separate head (request line + headers) from body at the first blank line.
	head := block
	var body []byte
	if idx := bytes.Index(block, []byte("\n\n")); idx >= 0 {
		head = block[:idx]
		body = block[idx+2:]
	}

	lines := strings.Split(string(head), "\n")
	// Skip leading blank lines.
	for len(lines) > 0 && strings.TrimSpace(lines[0]) == "" {
		lines = lines[1:]
	}
	if len(lines) == 0 {
		return Request{}, fmt.Errorf("empty request")
	}

	req, err := parseRequestLine(lines[0])
	if err != nil {
		return Request{}, err
	}

	for _, ln := range lines[1:] {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		colon := strings.IndexByte(ln, ':')
		if colon < 0 {
			return Request{}, fmt.Errorf("malformed header line: %q", ln)
		}
		name := strings.ToLower(strings.TrimSpace(ln[:colon]))
		value := strings.TrimSpace(ln[colon+1:])
		if name == "host" {
			if req.Authority == "" {
				req.Authority = value
			}
			continue
		}
		// content-length is recomputed at serialization time; drop any provided.
		if name == "content-length" {
			continue
		}
		req.Headers = append(req.Headers, Header{Name: name, Value: value})
	}

	if len(body) > 0 {
		req.Body = body
	}
	if req.Authority == "" {
		return Request{}, fmt.Errorf("no Host header and no target override; cannot determine authority")
	}
	if err := req.Validate(); err != nil {
		return Request{}, err
	}
	return req, nil
}

func parseRequestLine(line string) (Request, error) {
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/") {
		return Request{}, fmt.Errorf("malformed request line: %q", line)
	}
	return Request{
		Method: parts[0],
		Path:   parts[1],
		Scheme: "https", // default; overridden by target
	}, nil
}

// ApplyTarget overrides scheme/authority (and, if the parsed target has no Host,
// supplies one) from a target URL like "https://example.com:8443".
func (r *Request) ApplyTarget(target string) error {
	if target == "" {
		return nil
	}
	u, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("invalid target %q: %w", target, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("invalid target %q: scheme must be http or https", target)
	}
	if u.Host == "" || u.User != nil {
		return fmt.Errorf("invalid target %q: an authority without userinfo is required", target)
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("invalid target %q: use -path or the raw request for path/query data", target)
	}
	if _, err := parseAuthority(u.Host); err != nil {
		return fmt.Errorf("invalid target %q: %w", target, err)
	}
	r.Scheme = scheme
	r.Authority = u.Host
	return nil
}

// Validate rejects malformed request metadata before it reaches either wire
// serializer. This prevents request-line and header injection and keeps both
// protocol engines aligned on the accepted input model.
func (r Request) Validate() error {
	if len(r.Method) > maxMethodBytes || !validToken(r.Method) {
		return fmt.Errorf("invalid HTTP method %q", r.Method)
	}
	if r.Scheme != "http" && r.Scheme != "https" {
		return fmt.Errorf("unsupported scheme %q (want http or https)", r.Scheme)
	}
	if len(r.Authority) > maxAuthorityBytes {
		return fmt.Errorf("authority exceeds %d bytes", maxAuthorityBytes)
	}
	if _, err := parseAuthority(r.Authority); err != nil {
		return err
	}
	path := r.Path
	if path == "" {
		path = "/"
	}
	if len(path) > maxPathBytes {
		return fmt.Errorf("path exceeds %d bytes", maxPathBytes)
	}
	if path != "*" && !strings.HasPrefix(path, "/") {
		return fmt.Errorf("invalid origin-form path %q", path)
	}
	if containsInvalidPathByte(path) {
		return fmt.Errorf("path contains whitespace or control bytes")
	}
	if len(r.Headers) > maxHeaderCount {
		return fmt.Errorf("request has %d headers; maximum is %d", len(r.Headers), maxHeaderCount)
	}
	headerBytes := 0
	for _, h := range r.Headers {
		headerBytes += len(h.Name) + len(h.Value)
		if headerBytes > maxHeaderBytes {
			return fmt.Errorf("request headers exceed %d bytes", maxHeaderBytes)
		}
		if !validToken(h.Name) {
			return fmt.Errorf("invalid header name %q", h.Name)
		}
		if strings.ContainsAny(h.Value, "\r\n") {
			return fmt.Errorf("header %q contains a line break", h.Name)
		}
		for i := 0; i < len(h.Value); i++ {
			if h.Value[i] < 0x20 && h.Value[i] != '\t' || h.Value[i] == 0x7f {
				return fmt.Errorf("header %q contains a control byte", h.Name)
			}
		}
	}
	if len(r.Body) > maxBodyBytes {
		return fmt.Errorf("request body exceeds %d bytes", maxBodyBytes)
	}
	return nil
}

func parseAuthority(authority string) (*url.URL, error) {
	if authority == "" {
		return nil, fmt.Errorf("empty authority")
	}
	u, err := url.Parse("//" + authority)
	if err != nil {
		return nil, fmt.Errorf("invalid authority %q: %w", authority, err)
	}
	if u.Host != authority || u.User != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("invalid authority %q", authority)
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid port in authority %q", authority)
		}
	}
	return u, nil
}

func validToken(s string) bool {
	if s == "" {
		return false
	}
	const separators = `()<>@,;:\"/[]?={} `
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f || strings.ContainsRune(separators, rune(s[i])) {
			return false
		}
	}
	return true
}

func containsInvalidPathByte(path string) bool {
	for i := 0; i < len(path); i++ {
		if path[i] <= 0x20 || path[i] == 0x7f {
			return true
		}
	}
	return false
}

// Port returns the effective TCP port for dialing, defaulting by scheme.
func (r Request) Port() string {
	if u, err := parseAuthority(r.Authority); err == nil && u.Port() != "" {
		return u.Port()
	}
	if r.Scheme == "http" {
		return "80"
	}
	return "443"
}

// Host returns the authority without any port.
func (r Request) Host() string {
	if u, err := parseAuthority(r.Authority); err == nil {
		return u.Hostname()
	}
	return r.Authority
}

// DialAddress returns host:port suitable for net.Dial.
func (r Request) DialAddress() string {
	return net.JoinHostPort(r.Host(), r.Port())
}

// RawHTTP1 serializes the request to HTTP/1.1 wire bytes, adding a correct
// Host and Content-Length. It does not add Connection: close so responses are
// framed by Content-Length; the engine closes the socket after reading.
func (r Request) RawHTTP1() []byte {
	var b bytes.Buffer
	path := r.Path
	if path == "" {
		path = "/"
	}
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", r.Method, path)
	fmt.Fprintf(&b, "Host: %s\r\n", r.Authority)
	for _, h := range r.Headers {
		fmt.Fprintf(&b, "%s: %s\r\n", h.Name, h.Value)
	}
	if len(r.Body) > 0 {
		fmt.Fprintf(&b, "Content-Length: %s\r\n", strconv.Itoa(len(r.Body)))
	}
	b.WriteString("\r\n")
	b.Write(r.Body)
	return b.Bytes()
}

// Repeat returns n copies of the request (identical race attempts).
func Repeat(r Request, n int) []Request {
	out := make([]Request, n)
	for i := range out {
		out[i] = r
	}
	return out
}
