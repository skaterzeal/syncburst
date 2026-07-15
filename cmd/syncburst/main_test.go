package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skaterzeal/syncburst/internal/request"
)

func TestBuildRequestsEnforcesBurstLimit(t *testing.T) {
	for _, count := range []int{0, maxBurstRequests + 1} {
		if _, err := buildRequests("", "https://example.com", "GET", "/", "", nil, count); err == nil {
			t.Fatalf("buildRequests accepted count %d", count)
		}
	}
	reqs, err := buildRequests("", "https://example.com", "GET", "/", "", nil, maxBurstRequests)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != maxBurstRequests {
		t.Fatalf("got %d requests, want %d", len(reqs), maxBurstRequests)
	}
}

func TestBuildRequestsNormalizesHostAndLength(t *testing.T) {
	headers := headerFlags{
		"Host: ignored.example",
		"Content-Length: 999",
		"X-Test: value",
	}
	reqs, err := buildRequests("", "https://target.example:8443", "POST", "/redeem", "abc", headers, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range reqs {
		if r.Authority != "target.example:8443" || r.Host() != "target.example" {
			t.Fatalf("unexpected authority %q", r.Authority)
		}
		for _, h := range r.Headers {
			if h.Name == "host" || h.Name == "content-length" {
				t.Fatalf("wire-managed header leaked into request: %#v", h)
			}
		}
		if !strings.Contains(string(r.RawHTTP1()), "Content-Length: 3\r\n") {
			t.Fatalf("body length was not recomputed:\n%s", r.RawHTTP1())
		}
	}
}

func TestRunRejectsInvalidSafetyFlagsBeforeNetwork(t *testing.T) {
	for _, args := range [][]string{
		{"-u", "https://example.com", "-timeout", "0"},
		{"-u", "https://example.com", "-settle", "-1ms"},
		{"-u", "https://example.com", "-match-status", "99"},
		{"-u", "https://example.com", "-max-success", "-1"},
	} {
		if _, err := run(args); err == nil {
			t.Fatalf("run accepted flags %v", args)
		}
	}
}

func TestResolveProto(t *testing.T) {
	if got := resolveProto("auto", request.Request{Scheme: "https"}); got != "http2" {
		t.Fatalf("HTTPS auto protocol=%q", got)
	}
	if got := resolveProto("auto", request.Request{Scheme: "http"}); got != "http1" {
		t.Fatalf("HTTP auto protocol=%q", got)
	}
	if got := resolveProto("http1", request.Request{Scheme: "https"}); got != "http1" {
		t.Fatalf("explicit protocol=%q", got)
	}
}

func TestHelpIsSuccessful(t *testing.T) {
	code, err := run([]string{"-h"})
	if err != nil || code != 0 {
		t.Fatalf("help returned code=%d err=%v", code, err)
	}
}

func TestBuildMatcher(t *testing.T) {
	if m, err := buildMatcher(0, ""); err != nil || m != nil {
		t.Fatalf("no matcher: got m=%v err=%v", m, err)
	}
	m, err := buildMatcher(200, "")
	if err != nil || m == nil || m.Status != 200 || m.Body != nil || m.Label != "status=200" {
		t.Fatalf("status-only matcher: got %#v err=%v", m, err)
	}
	m, err = buildMatcher(0, " redeemed ")
	if err != nil || m == nil || m.Status != 0 || m.Body == nil || m.Label != "body~/ redeemed /" {
		t.Fatalf("body-only matcher: got %#v err=%v", m, err)
	}
	m, err = buildMatcher(200, "ok")
	if err != nil || m == nil || m.Status != 200 || m.Body == nil || m.Label != "status=200 & body~/ok/" {
		t.Fatalf("combined matcher: got %#v err=%v", m, err)
	}
	if _, err := buildMatcher(200, "("); err == nil {
		t.Fatalf("expected error for invalid regex")
	}
}

func TestBuildRequestsFromRawFile(t *testing.T) {
	raw := "POST /redeem HTTP/1.1\r\nHost: file.example\r\n\r\n{\"code\":\"X\"}"
	file := writeTempRequest(t, raw)

	// A single request in the file is duplicated -n times.
	reqs, err := buildRequests(file, "https://target.example", "GET", "/", "", nil, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 4 {
		t.Fatalf("single-request file: got %d requests, want 4", len(reqs))
	}
	for _, r := range reqs {
		if r.Method != "POST" || r.Path != "/redeem" || r.Authority != "target.example" {
			t.Fatalf("target override not applied: %#v", r)
		}
	}
}

func TestBuildRequestsMultiRequestFileIgnoresCount(t *testing.T) {
	raw := "GET /a HTTP/1.1\r\nHost: file.example\r\n---\nGET /b HTTP/1.1\r\nHost: file.example\r\n"
	file := writeTempRequest(t, raw)

	reqs, err := buildRequests(file, "https://target.example", "GET", "/", "", nil, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 2 {
		t.Fatalf("multi-request file: got %d requests, want 2 (-n must be ignored)", len(reqs))
	}
	if reqs[0].Path != "/a" || reqs[1].Path != "/b" {
		t.Fatalf("unexpected paths: %q, %q", reqs[0].Path, reqs[1].Path)
	}
}

func TestBuildRequestsErrors(t *testing.T) {
	if _, err := buildRequests(filepath.Join(t.TempDir(), "missing.txt"), "https://example.com", "GET", "/", "", nil, 1); err == nil {
		t.Fatalf("expected error for missing request file")
	}

	badFile := writeTempRequest(t, "this is not a request line")
	if _, err := buildRequests(badFile, "https://example.com", "GET", "/", "", nil, 1); err == nil {
		t.Fatalf("expected parse error for malformed request file")
	}

	if _, err := buildRequests("", "https://example.com", "GET", "/", "", headerFlags{"NoColonHeader"}, 1); err == nil {
		t.Fatalf("expected error for header without a colon")
	}

	if _, err := buildRequests("", "https://example.com/redeem", "GET", "/", "", nil, 1); err == nil {
		t.Fatalf("expected error for target carrying a path")
	}
}

func TestReadRequestFileRejectsOversize(t *testing.T) {
	file := filepath.Join(t.TempDir(), "big.txt")
	if err := os.WriteFile(file, bytes.Repeat([]byte("a"), maxRequestFileSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRequestFile(file); err == nil {
		t.Fatalf("expected error for oversize request file")
	}
}

func writeTempRequest(t *testing.T, content string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "request.txt")
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}
