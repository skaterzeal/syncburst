// Package http1 implements the HTTP/1.1 "last-byte synchronization" race
// technique: every request is written except its final byte, the engine waits
// until all connections have their prefix buffered at the server, then releases
// the final byte on every connection as simultaneously as possible so the
// server processes the requests within a very small time window.
package http1

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/skaterzeal/syncburst/internal/engine"
	"github.com/skaterzeal/syncburst/internal/request"
)

// Engine sends synchronized HTTP/1.1 bursts.
type Engine struct {
	DialTimeout time.Duration // per-connection dial timeout
	ReadTimeout time.Duration // per-connection response read timeout
	SettleDelay time.Duration // pause after prefixes are sent, before release
	Insecure    bool          // skip TLS certificate verification
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
func (e *Engine) Protocol() string { return "HTTP/1.1" }

// Fire dials one connection per request, sends every request minus its final
// byte, then releases all final bytes together.
func (e *Engine) Fire(reqs []request.Request) ([]engine.Response, error) {
	if len(reqs) == 0 {
		return nil, fmt.Errorf("no requests")
	}
	for i, r := range reqs {
		if err := r.Validate(); err != nil {
			return nil, fmt.Errorf("request %d: %w", i+1, err)
		}
	}
	n := len(reqs)
	results := make([]engine.Response, n)
	for i := range results {
		results[i] = engine.Response{Index: i, StreamID: 0}
	}

	type live struct {
		idx     int
		conn    net.Conn
		payload []byte
	}
	var conns []live
	for i := range reqs {
		payload := reqs[i].RawHTTP1()
		conn, err := e.dial(reqs[i])
		if err != nil {
			results[i].Err = err
			continue
		}
		conns = append(conns, live{idx: i, conn: conn, payload: payload})
	}
	// Ensure all sockets are closed on return.
	defer func() {
		for _, c := range conns {
			c.conn.Close()
		}
	}()

	gate := make(chan struct{})
	var ready, done sync.WaitGroup
	ready.Add(len(conns))
	done.Add(len(conns))

	for _, c := range conns {
		go func(c live) {
			if e.ReadTimeout > 0 {
				_ = c.conn.SetWriteDeadline(time.Now().Add(e.ReadTimeout))
			}
			defer done.Done()
			// Write everything except the final byte.
			if len(c.payload) > 1 {
				if err := writeOnce(c.conn, c.payload[:len(c.payload)-1]); err != nil {
					results[c.idx].Err = err
					ready.Done()
					return
				}
			}
			ready.Done()
			<-gate

			t0 := time.Now()
			if e.ReadTimeout > 0 {
				_ = c.conn.SetWriteDeadline(t0.Add(e.ReadTimeout))
			}
			if err := writeOnce(c.conn, c.payload[len(c.payload)-1:]); err != nil {
				results[c.idx].Err = err
				return
			}
			status, body, bodyLen, err := readResponse(c.conn, reqs[c.idx].Method, e.ReadTimeout)
			results[c.idx].Duration = time.Since(t0)
			results[c.idx].Status = status
			results[c.idx].BodyLen = bodyLen
			results[c.idx].Body = body
			if err != nil {
				results[c.idx].Err = err
				return
			}
		}(c)
	}

	// A goroutine that errored during prefix write still calls ready.Done(),
	// so this returns once every connection has either buffered its prefix or
	// failed.
	ready.Wait()
	if e.SettleDelay > 0 {
		time.Sleep(e.SettleDelay)
	}
	close(gate)
	done.Wait()
	return results, nil
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

func (e *Engine) dial(r request.Request) (net.Conn, error) {
	d := net.Dialer{Timeout: e.DialTimeout}
	raw, err := d.Dial("tcp", r.DialAddress())
	if err != nil {
		return nil, err
	}
	if tc, ok := raw.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	if r.Scheme != "https" {
		return raw, nil
	}
	cfg := &tls.Config{
		ServerName:         r.Host(),
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"http/1.1"},
		InsecureSkipVerify: e.Insecure,
	}
	tconn := tls.Client(raw, cfg)
	if e.DialTimeout > 0 {
		_ = tconn.SetDeadline(time.Now().Add(e.DialTimeout))
	}
	if err := tconn.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	_ = tconn.SetDeadline(time.Time{})
	return tconn, nil
}

// readResponse reads and parses a single HTTP/1.1 response, fully draining the
// body (bounded by the read deadline).
func readResponse(conn net.Conn, method string, timeout time.Duration) (int, []byte, int, error) {
	if timeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: method})
	if err != nil {
		return 0, nil, 0, err
	}
	defer resp.Body.Close()
	capture := &cappedBody{cap: engine.BodyCap}
	_, err = io.Copy(capture, resp.Body)
	if err != nil {
		return resp.StatusCode, capture.body, capture.total, err
	}
	return resp.StatusCode, capture.body, capture.total, nil
}

// cappedBody counts the complete response while retaining only a bounded
// prefix for regex matching and evidence.
type cappedBody struct {
	cap   int
	total int
	body  []byte
}

func (w *cappedBody) Write(p []byte) (int, error) {
	originalLen := len(p)
	w.total += originalLen
	if remaining := w.cap - len(w.body); remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		w.body = append(w.body, p...)
	}
	return originalLen, nil
}
