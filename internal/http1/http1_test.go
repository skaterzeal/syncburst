package http1

import (
	"bytes"
	"testing"

	"github.com/skaterzeal/syncburst/internal/engine"
	"github.com/skaterzeal/syncburst/internal/request"
)

func TestCappedBodyCountsFullResponse(t *testing.T) {
	w := &cappedBody{cap: 4}
	payload := []byte("abcdefghij")
	n, err := w.Write(payload)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(payload) {
		t.Fatalf("Write returned %d, want %d", n, len(payload))
	}
	if w.total != len(payload) || !bytes.Equal(w.body, []byte("abcd")) {
		t.Fatalf("total=%d body=%q", w.total, w.body)
	}
}

func TestCappedBodyUsesEngineLimit(t *testing.T) {
	w := &cappedBody{cap: engine.BodyCap}
	payload := bytes.Repeat([]byte("x"), engine.BodyCap+100)
	if _, err := w.Write(payload); err != nil {
		t.Fatal(err)
	}
	if len(w.body) != engine.BodyCap || w.total != len(payload) {
		t.Fatalf("captured=%d total=%d", len(w.body), w.total)
	}
}

func TestFireRejectsUnsafeRequest(t *testing.T) {
	e := New()
	_, err := e.Fire([]request.Request{{Method: "GET\r\nX:", Scheme: "https", Authority: "example.com", Path: "/"}})
	if err == nil {
		t.Fatal("Fire accepted an injected request method")
	}
}
