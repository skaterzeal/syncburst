package request

import (
	"bytes"
	"testing"
)

func TestParseOne(t *testing.T) {
	raw := "POST /redeem?x=1 HTTP/1.1\r\n" +
		"Host: example.com:8443\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 999\r\n" + // must be dropped and recomputed
		"\r\n" +
		`{"code":"A"}`
	r, err := ParseOne([]byte(raw))
	if err != nil {
		t.Fatalf("ParseOne: %v", err)
	}
	if r.Method != "POST" || r.Path != "/redeem?x=1" {
		t.Errorf("request line: method=%q path=%q", r.Method, r.Path)
	}
	if r.Authority != "example.com:8443" {
		t.Errorf("authority=%q", r.Authority)
	}
	if r.Host() != "example.com" || r.Port() != "8443" {
		t.Errorf("host/port split: %q / %q", r.Host(), r.Port())
	}
	// Host and Content-Length must not appear as ordinary headers.
	for _, h := range r.Headers {
		if h.Name == "host" || h.Name == "content-length" {
			t.Errorf("header %q should have been stripped", h.Name)
		}
	}
	if string(r.Body) != `{"code":"A"}` {
		t.Errorf("body=%q", r.Body)
	}

	wire := r.RawHTTP1()
	if !bytes.Contains(wire, []byte("Content-Length: 12\r\n")) {
		t.Errorf("Content-Length not recomputed to 12:\n%s", wire)
	}
	if !bytes.Contains(wire, []byte("Host: example.com:8443\r\n")) {
		t.Errorf("Host not emitted:\n%s", wire)
	}
	if bytes.Contains(wire, []byte("Content-Length: 999")) {
		t.Errorf("stale Content-Length leaked:\n%s", wire)
	}
}

func TestParseFileMultiple(t *testing.T) {
	raw := "GET /a HTTP/1.1\nHost: h\n\n---\nGET /b HTTP/1.1\nHost: h\n"
	reqs, err := ParseFile([]byte(raw))
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(reqs) != 2 {
		t.Fatalf("want 2 requests, got %d", len(reqs))
	}
	if reqs[0].Path != "/a" || reqs[1].Path != "/b" {
		t.Errorf("paths: %q %q", reqs[0].Path, reqs[1].Path)
	}
}

func TestApplyTarget(t *testing.T) {
	r := Request{Method: "GET", Path: "/", Scheme: "https", Authority: "orig:443"}
	if err := r.ApplyTarget("http://newhost:8080"); err != nil {
		t.Fatal(err)
	}
	if r.Scheme != "http" || r.Authority != "newhost:8080" {
		t.Errorf("apply target: scheme=%q authority=%q", r.Scheme, r.Authority)
	}
	if r.Port() != "8080" {
		t.Errorf("port=%q", r.Port())
	}
}

func TestPortDefaults(t *testing.T) {
	https := Request{Scheme: "https", Authority: "h"}
	if https.Port() != "443" {
		t.Errorf("https default port=%q", https.Port())
	}
	http := Request{Scheme: "http", Authority: "h"}
	if http.Port() != "80" {
		t.Errorf("http default port=%q", http.Port())
	}
}

func TestValidateRejectsUnsafeMetadata(t *testing.T) {
	base := Request{Method: "GET", Scheme: "https", Authority: "example.com", Path: "/"}
	tests := []struct {
		name string
		edit func(*Request)
	}{
		{"method injection", func(r *Request) { r.Method = "GET\r\nX-Test:" }},
		{"path injection", func(r *Request) { r.Path = "/ok\r\nX-Test: injected" }},
		{"absolute path", func(r *Request) { r.Path = "https://other.example/" }},
		{"header name", func(r *Request) { r.Headers = []Header{{Name: "bad name", Value: "x"}} }},
		{"header value", func(r *Request) { r.Headers = []Header{{Name: "x-test", Value: "ok\r\ninjected"}} }},
		{"scheme", func(r *Request) { r.Scheme = "ftp" }},
		{"authority path", func(r *Request) { r.Authority = "example.com/path" }},
		{"bad port", func(r *Request) { r.Authority = "example.com:70000" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := base
			tt.edit(&r)
			if err := r.Validate(); err == nil {
				t.Fatalf("Validate accepted %#v", r)
			}
		})
	}
}

func TestApplyTargetRequiresBaseHTTPURL(t *testing.T) {
	invalid := []string{
		"example.com",
		"ftp://example.com",
		"https://user:pass@example.com",
		"https://example.com/path",
		"https://example.com/?query=1",
		"https://example.com:70000",
	}
	for _, target := range invalid {
		t.Run(target, func(t *testing.T) {
			r := Request{Method: "GET", Scheme: "https", Authority: "original", Path: "/"}
			if err := r.ApplyTarget(target); err == nil {
				t.Fatalf("ApplyTarget accepted %q", target)
			}
		})
	}
}

func TestIPv6Authority(t *testing.T) {
	r := Request{Method: "GET", Scheme: "https", Authority: "[::1]:8443", Path: "/"}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if r.Host() != "::1" || r.Port() != "8443" || r.DialAddress() != "[::1]:8443" {
		t.Fatalf("unexpected IPv6 split: host=%q port=%q dial=%q", r.Host(), r.Port(), r.DialAddress())
	}
}

func TestParseRequestLineRequiresVersion(t *testing.T) {
	for _, raw := range []string{
		"GET /\nHost: example.com\n",
		"GET / HTTP/1.1 extra\nHost: example.com\n",
	} {
		if _, err := ParseOne([]byte(raw)); err == nil {
			t.Fatalf("ParseOne accepted malformed request line %q", raw)
		}
	}
}

func TestValidateEnforcesResourceLimits(t *testing.T) {
	base := Request{Method: "GET", Scheme: "https", Authority: "example.com", Path: "/"}

	tooManyHeaders := base
	tooManyHeaders.Headers = make([]Header, maxHeaderCount+1)
	if err := tooManyHeaders.Validate(); err == nil {
		t.Fatal("accepted excessive header count")
	}

	largeHeader := base
	largeHeader.Headers = []Header{{Name: "x-test", Value: string(bytes.Repeat([]byte("x"), maxHeaderBytes+1))}}
	if err := largeHeader.Validate(); err == nil {
		t.Fatal("accepted excessive header bytes")
	}

	largeBody := base
	largeBody.Body = bytes.Repeat([]byte("x"), maxBodyBytes+1)
	if err := largeBody.Validate(); err == nil {
		t.Fatal("accepted excessive body")
	}

	longPath := base
	longPath.Path = "/" + string(bytes.Repeat([]byte("x"), maxPathBytes))
	if err := longPath.Validate(); err == nil {
		t.Fatal("accepted excessive path")
	}
}
