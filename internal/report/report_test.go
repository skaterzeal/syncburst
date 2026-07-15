package report

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/skaterzeal/syncburst/internal/engine"
)

func TestAnalyzeDivergence(t *testing.T) {
	resps := []engine.Response{
		{Index: 0, Status: 200, BodyLen: 10},
		{Index: 1, Status: 409, BodyLen: 20},
		{Index: 2, Status: 200, BodyLen: 10},
	}
	m := &Matcher{Status: 200, Label: "status=200"}
	s := Analyze("HTTP/2", resps, m)
	if !s.Divergent {
		t.Error("mixed statuses should be divergent")
	}
	if s.MatchCount != 2 {
		t.Errorf("expected 2 matches, got %d", s.MatchCount)
	}
}

func TestVerdictRaceConfirmed(t *testing.T) {
	out := renderVerdict(t, Summary{
		Total: 30, MatchCount: 30, MatchLabel: "status=200",
		Groups:  []Group{{Status: 200, BodyLen: 54, Count: 30}},
		Control: &ControlResult{Ran: true, Matched: false},
	})
	if !strings.Contains(out, "RACE CONFIRMED") {
		t.Errorf("expected RACE CONFIRMED when control was rejected; got:\n%s", out)
	}
}

func TestVerdictInconclusiveOnNonSingleUse(t *testing.T) {
	out := renderVerdict(t, Summary{
		Total: 20, MatchCount: 20, MatchLabel: "status=200",
		Groups:  []Group{{Status: 200, BodyLen: 18, Count: 20}},
		Control: &ControlResult{Ran: true, Matched: true},
	})
	if !strings.Contains(out, "INCONCLUSIVE") {
		t.Errorf("expected INCONCLUSIVE when a lone follow-up also succeeds; got:\n%s", out)
	}
}

func TestVerdictNoControlSuggestsControl(t *testing.T) {
	out := renderVerdict(t, Summary{
		Total: 30, MatchCount: 30, MatchLabel: "status=200",
		Groups: []Group{{Status: 200, BodyLen: 54, Count: 30}},
	})
	if !strings.Contains(out, "-control") {
		t.Errorf("expected a hint to use -control when no control was run; got:\n%s", out)
	}
}

func renderVerdict(t *testing.T, s Summary) string {
	t.Helper()
	if s.Valid == 0 {
		s.Valid = s.Total
	}
	Finalize(&s, true, 1)
	var b bytes.Buffer
	WriteText(&b, s)
	return b.String()
}

func TestSecureDivergenceIsNotARaceSignal(t *testing.T) {
	resps := []engine.Response{
		{Index: 0, Status: 200, BodyLen: 10},
		{Index: 1, Status: 409, BodyLen: 20},
		{Index: 2, Status: 409, BodyLen: 20},
	}
	s := Analyze("HTTP/2", resps, &Matcher{Status: 200, Label: "status=200"})
	Finalize(&s, true, 1)
	if !s.Divergent {
		t.Fatal("expected response divergence")
	}
	if s.RaceSignal || s.Verdict != VerdictNoSignal || s.ExitCode() != 0 {
		t.Fatalf("a single allowed success must be clean: signal=%v verdict=%q exit=%d", s.RaceSignal, s.Verdict, s.ExitCode())
	}
}

func TestRaceSignalControlOutcomes(t *testing.T) {
	resps := []engine.Response{
		{Index: 0, Status: 200},
		{Index: 1, Status: 200},
		{Index: 2, Status: 409},
	}
	s := Analyze("HTTP/2", resps, &Matcher{Status: 200, Label: "status=200"})
	Finalize(&s, true, 1)
	if !s.RaceSignal || s.Verdict != VerdictLikely || s.ExitCode() != 1 {
		t.Fatalf("expected unvalidated race signal, got signal=%v verdict=%q exit=%d", s.RaceSignal, s.Verdict, s.ExitCode())
	}

	s.Control = &ControlResult{Ran: true, Matched: true}
	Finalize(&s, true, 1)
	if s.Verdict != VerdictInconclusive || s.ExitCode() != 2 {
		t.Fatalf("matching control must be inconclusive: verdict=%q exit=%d", s.Verdict, s.ExitCode())
	}

	s.Control = &ControlResult{Ran: true, Matched: false}
	Finalize(&s, true, 1)
	if s.Verdict != VerdictConfirmed || s.ExitCode() != 1 {
		t.Fatalf("rejected control must confirm the signal: verdict=%q exit=%d", s.Verdict, s.ExitCode())
	}
}

func TestFailuresCannotProduceCleanExit(t *testing.T) {
	s := Analyze("HTTP/1.1", []engine.Response{
		{Index: 0, Status: 200},
		{Index: 1, Err: fmt.Errorf("read timeout")},
	}, &Matcher{Status: 200, Label: "status=200"})
	Finalize(&s, true, 1)
	if s.Verdict != VerdictIncomplete || s.ExitCode() != 2 {
		t.Fatalf("partial transport failure must be incomplete: verdict=%q exit=%d", s.Verdict, s.ExitCode())
	}
	if len(s.ErrorDetails) != 1 || s.ErrorDetails[0].Index != 1 {
		t.Fatalf("expected indexed error detail, got %#v", s.ErrorDetails)
	}

	empty := Analyze("HTTP/2", []engine.Response{{Index: 0, Err: fmt.Errorf("connection closed")}}, nil)
	Finalize(&empty, false, 1)
	if empty.Verdict != VerdictInvalid || empty.ExitCode() != 2 {
		t.Fatalf("zero valid responses must be invalid: verdict=%q exit=%d", empty.Verdict, empty.ExitCode())
	}
}

func TestNoMatcherRequiresManualReview(t *testing.T) {
	s := Analyze("HTTP/1.1", []engine.Response{
		{Index: 0, Status: 200},
		{Index: 1, Status: 409},
	}, nil)
	Finalize(&s, false, 1)
	if !s.Divergent || s.RaceSignal || s.Verdict != VerdictManual || s.ExitCode() != 0 {
		t.Fatalf("unexpected no-matcher result: divergent=%v signal=%v verdict=%q exit=%d", s.Divergent, s.RaceSignal, s.Verdict, s.ExitCode())
	}
}

func TestBodyMatcherUsesCapturedBody(t *testing.T) {
	m := &Matcher{Body: regexp.MustCompile(`credited`), Label: "body~=credited"}
	s := Analyze("HTTP/2", []engine.Response{
		{Index: 0, Status: 200, Body: []byte(`credited`), BodyLen: 8},
		{Index: 1, Status: 200, Body: []byte(`rejected`), BodyLen: 8},
	}, m)
	Finalize(&s, true, 0)
	if s.MatchCount != 1 || !s.RaceSignal {
		t.Fatalf("expected one captured-body match, got matches=%d signal=%v", s.MatchCount, s.RaceSignal)
	}
}

func TestTruncatedBodyNonMatchIsIncomplete(t *testing.T) {
	m := &Matcher{Body: regexp.MustCompile(`needle-after-cap`), Label: "body matcher"}
	s := Analyze("HTTP/2", []engine.Response{
		{
			Index:   0,
			Status:  200,
			Body:    []byte("captured-prefix"),
			BodyLen: engine.BodyCap + 1,
		},
	}, m)
	Finalize(&s, true, 0)
	if s.UncertainBodyMatches != 1 {
		t.Fatalf("uncertain body matches=%d", s.UncertainBodyMatches)
	}
	if s.Verdict != VerdictIncomplete || s.ExitCode() != 2 {
		t.Fatalf("truncated non-match must be incomplete: verdict=%q exit=%d", s.Verdict, s.ExitCode())
	}
	var out bytes.Buffer
	WriteText(&out, s)
	if !strings.Contains(out.String(), "capture limit") {
		t.Fatalf("missing capture-limit explanation:\n%s", out.String())
	}
}
