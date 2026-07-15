// Package engine defines the protocol-neutral result types and the interface
// implemented by the HTTP/1.1 and HTTP/2 firing engines.
package engine

import (
	"time"

	"github.com/skaterzeal/syncburst/internal/request"
)

// Response is the outcome of a single in-burst request.
type Response struct {
	Index    int           // position within the burst (0-based)
	StreamID uint32        // HTTP/2 stream id, 0 for HTTP/1.1
	Status   int           // HTTP status code, 0 if not received
	BodyLen  int           // number of body bytes read
	Body     []byte        // body, truncated to a cap by the engine
	Duration time.Duration // time from final-byte release to response received
	Err      error         // transport/parse error, if any
}

// Firer sends a burst of requests with minimal timing skew between them and
// returns one Response per request, index-aligned to reqs.
type Firer interface {
	// Fire sends all requests as a synchronized burst and collects responses.
	Fire(reqs []request.Request) ([]Response, error)
	// Protocol is a human-readable label, e.g. "HTTP/1.1" or "HTTP/2".
	Protocol() string
}

// BodyCap bounds how many body bytes each engine retains per response for
// matching and evidence. BodyLen still records the full decoded body length.
const BodyCap = 64 * 1024
