// Package report analyzes a burst of responses and renders a human- or
// machine-readable summary. Automated race signals require a caller-defined
// success matcher to exceed the operation's allowed success count; response
// divergence is retained only as supporting context.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"time"

	"github.com/skaterzeal/syncburst/internal/engine"
)

// signature identifies a class of responses that look identical to the client.
type signature struct {
	Status  int `json:"status"`
	BodyLen int `json:"body_len"`
}

// Group is a set of responses sharing a signature.
type Group struct {
	Status  int   `json:"status"`
	BodyLen int   `json:"body_len"`
	Count   int   `json:"count"`
	Indices []int `json:"indices"`
}

// Timing holds duration statistics over successful responses.
type Timing struct {
	Min    time.Duration `json:"min_ns"`
	Max    time.Duration `json:"max_ns"`
	Mean   time.Duration `json:"mean_ns"`
	Median time.Duration `json:"median_ns"`
}

// Summary is the analyzed result of a burst.
type Summary struct {
	Protocol             string          `json:"protocol"`
	Total                int             `json:"total"`
	Valid                int             `json:"valid"`
	Errors               int             `json:"errors"`
	ErrorDetails         []ResponseError `json:"error_details,omitempty"`
	UncertainBodyMatches int             `json:"uncertain_body_matches,omitempty"`
	Groups               []Group         `json:"groups"`
	Timing               Timing          `json:"timing"`
	MatchLabel           string          `json:"match_label,omitempty"`
	MatchCount           int             `json:"match_count"`
	MaxSuccess           int             `json:"max_success"`
	MatcherEnabled       bool            `json:"matcher_enabled"`
	RaceSignal           bool            `json:"race_signal"`
	Verdict              string          `json:"verdict"`
	// Divergent is true when successful responses fall into more than one group.
	Divergent bool `json:"divergent"`
	// Control holds the result of a post-burst control probe, when one was run.
	Control *ControlResult `json:"control,omitempty"`
}

// ResponseError is a machine-readable per-request transport or parse failure.
type ResponseError struct {
	Index    int    `json:"index"`
	StreamID uint32 `json:"stream_id,omitempty"`
	Message  string `json:"message"`
}

// ControlResult records a post-burst control probe: whether a single lone
// follow-up request still counts as a success. If it does, the endpoint accepts
// repeated requests outside of any race, so multiple burst successes are the
// endpoint's normal behavior — not proof of a single-use bypass. This guards
// against a false positive on idempotent / non-single-use endpoints.
type ControlResult struct {
	Ran     bool   `json:"ran"`
	Matched bool   `json:"matched"`
	Error   string `json:"error,omitempty"`
}

const (
	VerdictInvalid      = "invalid"
	VerdictIncomplete   = "incomplete"
	VerdictInconclusive = "inconclusive"
	VerdictConfirmed    = "race_confirmed"
	VerdictLikely       = "race_likely"
	VerdictNoSignal     = "no_race_signal"
	VerdictManual       = "manual_review"
)

// Matcher reports whether a response counts as a "success" for the tested race.
type Matcher struct {
	Status int            // match this status (0 = ignore)
	Body   *regexp.Regexp // match body against this regex (nil = ignore)
	Label  string         // human description
}

// Matches reports whether a response counts as a success for the tested race.
func (m *Matcher) Matches(r engine.Response) bool {
	if m == nil {
		return false
	}
	if m.Status != 0 && r.Status != m.Status {
		return false
	}
	if m.Body != nil && !m.Body.Match(r.Body) {
		return false
	}
	return m.Status != 0 || m.Body != nil
}

// Analyze groups responses by signature and computes statistics.
func Analyze(protocol string, resps []engine.Response, m *Matcher) Summary {
	s := Summary{Protocol: protocol, Total: len(resps)}
	counts := map[signature]*Group{}
	var durations []time.Duration
	for _, r := range resps {
		if r.Err != nil {
			s.Errors++
			s.ErrorDetails = append(s.ErrorDetails, ResponseError{
				Index: r.Index, StreamID: r.StreamID, Message: r.Err.Error(),
			})
			continue
		}
		s.Valid++
		durations = append(durations, r.Duration)
		sig := signature{Status: r.Status, BodyLen: r.BodyLen}
		g := counts[sig]
		if g == nil {
			g = &Group{Status: sig.Status, BodyLen: sig.BodyLen}
			counts[sig] = g
		}
		g.Count++
		g.Indices = append(g.Indices, r.Index)
		matched := m.Matches(r)
		if matched {
			s.MatchCount++
		}
		if m != nil && m.Body != nil && r.BodyLen > len(r.Body) &&
			(m.Status == 0 || r.Status == m.Status) && !m.Body.Match(r.Body) {
			s.UncertainBodyMatches++
		}
	}
	for _, g := range counts {
		s.Groups = append(s.Groups, *g)
	}
	// Most frequent first; ties broken by status for stable output.
	sort.Slice(s.Groups, func(i, j int) bool {
		if s.Groups[i].Count != s.Groups[j].Count {
			return s.Groups[i].Count > s.Groups[j].Count
		}
		return s.Groups[i].Status < s.Groups[j].Status
	})
	s.Divergent = len(s.Groups) > 1
	s.Timing = computeTiming(durations)
	if m != nil {
		s.MatchLabel = m.Label
	}
	return s
}

// Finalize turns response measurements into an explicit verdict. Divergence is
// deliberately informational: a correctly protected single-use endpoint
// normally returns one success and many rejections. A race signal requires a
// configured success matcher and more matches than the caller says are valid.
func Finalize(s *Summary, matcherEnabled bool, maxSuccess int) {
	s.MatcherEnabled = matcherEnabled
	s.MaxSuccess = maxSuccess
	s.RaceSignal = matcherEnabled && s.MatchCount > maxSuccess

	switch {
	case s.Total == 0 || s.Valid == 0:
		s.Verdict = VerdictInvalid
	case s.RaceSignal && s.Control != nil && s.Control.Error != "":
		s.Verdict = VerdictIncomplete
	case s.RaceSignal && s.Control != nil && s.Control.Ran && s.Control.Matched:
		s.Verdict = VerdictInconclusive
	case s.RaceSignal && s.Control != nil && s.Control.Ran:
		s.Verdict = VerdictConfirmed
	case s.RaceSignal:
		s.Verdict = VerdictLikely
	case s.Errors > 0 || s.UncertainBodyMatches > 0:
		s.Verdict = VerdictIncomplete
	case !matcherEnabled:
		s.Verdict = VerdictManual
	default:
		s.Verdict = VerdictNoSignal
	}
}

// ExitCode maps a finalized verdict to CLI semantics: 0 means a complete run
// without a race signal, 1 means a race signal, and 2 means the run was invalid
// or inconclusive and must not be treated as a clean result.
func (s Summary) ExitCode() int {
	switch s.Verdict {
	case VerdictConfirmed, VerdictLikely:
		return 1
	case VerdictInvalid, VerdictIncomplete, VerdictInconclusive:
		return 2
	default:
		return 0
	}
}
func computeTiming(d []time.Duration) Timing {
	if len(d) == 0 {
		return Timing{}
	}
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	var sum time.Duration
	for _, v := range d {
		sum += v
	}
	return Timing{
		Min:    d[0],
		Max:    d[len(d)-1],
		Mean:   sum / time.Duration(len(d)),
		Median: d[len(d)/2],
	}
}

// WriteJSON emits the summary as indented JSON.
func WriteJSON(w io.Writer, s Summary) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}

// WriteText emits a compact human-readable report.
func WriteText(w io.Writer, s Summary) {
	fmt.Fprintf(w, "syncburst — %s burst of %d request(s)\n", s.Protocol, s.Total)
	if s.Errors > 0 {
		fmt.Fprintf(w, "  valid/errors:  %d/%d\n", s.Valid, s.Errors)
	}
	if s.Valid > 0 {
		fmt.Fprintf(w, "  timing:        min %s / median %s / mean %s / max %s\n",
			ms(s.Timing.Min), ms(s.Timing.Median), ms(s.Timing.Mean), ms(s.Timing.Max))
	}

	fmt.Fprintln(w, "  response groups (status, body-bytes):")
	for _, g := range s.Groups {
		fmt.Fprintf(w, "    %3d x  status=%d  body=%dB\n", g.Count, g.Status, g.BodyLen)
	}
	if len(s.Groups) == 0 {
		fmt.Fprintln(w, "      (no valid responses)")
	}

	if s.MatcherEnabled {
		fmt.Fprintf(w, "  matcher [%s]: %d/%d matched (allowed maximum: %d)",
			s.MatchLabel, s.MatchCount, s.Valid, s.MaxSuccess)
		if s.RaceSignal {
			fmt.Fprint(w, "   <-- limit exceeded")
		}
		fmt.Fprintln(w)
	} else {
		fmt.Fprintln(w, "  matcher:       not configured; no automated vulnerability verdict")
	}

	if s.Control != nil && s.Control.Ran {
		switch {
		case s.Control.Error != "":
			fmt.Fprintf(w, "  control:       failed: %s\n", s.Control.Error)
		case s.Control.Matched:
			fmt.Fprintln(w, "  control:       a lone follow-up also matched; verify the configured success limit")
		default:
			fmt.Fprintln(w, "  control:       a lone follow-up did not match")
		}
	}

	if s.Divergent {
		fmt.Fprintln(w, "  note:          responses diverged; this is context, not proof by itself")
	}
	if s.UncertainBodyMatches > 0 {
		fmt.Fprintf(w, "  note:          %d body match(es) were uncertain because responses exceeded the %d-byte capture limit\n", s.UncertainBodyMatches, engine.BodyCap)
	}

	switch s.Verdict {
	case VerdictConfirmed:
		fmt.Fprintln(w, "  VERDICT: RACE CONFIRMED — matched successes exceeded the configured limit and the lone follow-up did not match.")
	case VerdictLikely:
		fmt.Fprintln(w, "  VERDICT: RACE SIGNAL — matched successes exceeded the configured limit; rerun with -control=true for validation.")
	case VerdictInconclusive:
		fmt.Fprintln(w, "  VERDICT: INCONCLUSIVE — the follow-up also matched, so the matcher or allowed limit does not describe a consumed/limited operation.")
	case VerdictIncomplete:
		fmt.Fprintln(w, "  VERDICT: INCOMPLETE — transport, control, or body-capture uncertainty prevents a clean conclusion.")
	case VerdictInvalid:
		fmt.Fprintln(w, "  VERDICT: INVALID — no valid responses were available.")
	case VerdictManual:
		fmt.Fprintln(w, "  VERDICT: MANUAL REVIEW — configure -match-status and/or -match-body for an automated race verdict.")
	default:
		fmt.Fprintln(w, "  VERDICT: NO RACE SIGNAL — matched successes stayed within the configured limit.")
	}

	if len(s.ErrorDetails) > 0 {
		fmt.Fprintln(w, "  per-request errors:")
		for _, e := range s.ErrorDetails {
			fmt.Fprintf(w, "    #%d: %s\n", e.Index, e.Message)
		}
	}
}

func ms(d time.Duration) string {
	return fmt.Sprintf("%.2fms", float64(d)/float64(time.Millisecond))
}
