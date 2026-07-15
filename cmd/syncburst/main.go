// Command syncburst fires a synchronized burst of HTTP requests to expose
// race-condition (TOCTOU / limit-overrun) vulnerabilities.
//
// Authorized testing only: you must have explicit permission to test the target.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/skaterzeal/syncburst/internal/engine"
	"github.com/skaterzeal/syncburst/internal/http1"
	"github.com/skaterzeal/syncburst/internal/http2"
	"github.com/skaterzeal/syncburst/internal/report"
	"github.com/skaterzeal/syncburst/internal/request"
)

type headerFlags []string

func (h *headerFlags) String() string { return strings.Join(*h, ", ") }
func (h *headerFlags) Set(v string) error {
	*h = append(*h, v)
	return nil
}

// version is the tool version, overridable at build time with
// -ldflags "-X main.version=vX.Y.Z".
var version = "dev"

func main() {
	code, err := run(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "syncburst: "+err.Error())
		os.Exit(2)
	}
	os.Exit(code)
}

func run(args []string) (int, error) {
	fs := flag.NewFlagSet("syncburst", flag.ContinueOnError)
	var (
		reqFile     = fs.String("r", "", "raw HTTP request file (Burp-style); '---' separates multiple requests")
		target      = fs.String("u", "", "target base URL, e.g. https://host:port (overrides scheme/authority)")
		method      = fs.String("X", "GET", "HTTP method (when not using -r)")
		path        = fs.String("path", "/", "request path (when not using -r)")
		data        = fs.String("d", "", "request body (when not using -r)")
		headers     = headerFlags{}
		count       = fs.Int("n", 20, "number of parallel requests in the burst")
		proto       = fs.String("proto", "auto", "protocol: auto|http1|http2")
		matchStatus = fs.Int("match-status", 0, "count responses with this status as a success")
		matchBody   = fs.String("match-body", "", "regex; responses whose body matches count as a success")
		maxSuccess  = fs.Int("max-success", 1, "maximum matched successes allowed before reporting a race signal")
		jsonOut     = fs.Bool("json", false, "emit JSON instead of text")
		insecure    = fs.Bool("insecure", false, "skip TLS certificate verification (needed for self-signed pentest targets)")
		timeout     = fs.Duration("timeout", 15*time.Second, "per-request read/write timeout")
		settle      = fs.Duration("settle", 30*time.Millisecond, "delay after prefixes are sent, before release")
		control     = fs.Bool("control", true, "after a race signal, send one lone follow-up to validate the configured success limit")
		showVersion = fs.Bool("version", false, "print version and exit")
	)
	fs.Var(&headers, "H", "request header 'Name: Value' (repeatable; when not using -r)")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `syncburst — synchronized HTTP race-condition tester (authorized use only)

  syncburst -r <file> -u <url> -n <count> [-match-status N] [-proto auto|http1|http2]
  syncburst -u <url> -X POST -path /redeem -H "H: V" -d '<body>' -n 30 -match-status 200

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, nil
		}
		return 0, err
	}
	if *showVersion {
		fmt.Println("syncburst " + version)
		return 0, nil
	}
	if *maxSuccess < 0 {
		return 0, fmt.Errorf("-max-success must be >= 0")
	}
	if *timeout <= 0 {
		return 0, fmt.Errorf("-timeout must be greater than zero")
	}
	if *settle < 0 {
		return 0, fmt.Errorf("-settle must be >= 0")
	}
	if *matchStatus != 0 && (*matchStatus < 100 || *matchStatus > 599) {
		return 0, fmt.Errorf("-match-status must be between 100 and 599")
	}

	reqs, err := buildRequests(*reqFile, *target, *method, *path, *data, headers, *count)
	if err != nil {
		return 0, err
	}

	matcher, err := buildMatcher(*matchStatus, *matchBody)
	if err != nil {
		return 0, err
	}

	if *insecure {
		fmt.Fprintln(os.Stderr, "syncburst: warning: -insecure disables TLS certificate verification (connection is not authenticated)")
	}

	var eng engine.Firer
	switch resolveProto(*proto, reqs[0]) {
	case "http1":
		h := http1.New()
		h.ReadTimeout = *timeout
		h.SettleDelay = *settle
		h.DialTimeout = *timeout
		h.Insecure = *insecure
		eng = h
	case "http2":
		h := http2.New()
		h.ReadTimeout = *timeout
		h.SettleDelay = *settle
		h.DialTimeout = *timeout
		h.Insecure = *insecure
		eng = h
	default:
		return 0, fmt.Errorf("unknown protocol %q", *proto)
	}

	resps, err := eng.Fire(reqs)
	if err != nil {
		return 0, err
	}

	summary := report.Analyze(eng.Protocol(), resps, matcher)
	report.Finalize(&summary, matcher != nil, *maxSuccess)

	// A post-burst follow-up validates the user's matcher/limit assumption. It
	// runs for every matcher-based race signal; response divergence alone never
	// triggers it because divergence is not proof of a race.
	if *control && summary.RaceSignal {
		cr := &report.ControlResult{Ran: true}
		ctl, cerr := eng.Fire(reqs[:1])
		switch {
		case cerr != nil:
			cr.Error = cerr.Error()
		case len(ctl) != 1:
			cr.Error = fmt.Sprintf("expected one response, got %d", len(ctl))
		case ctl[0].Err != nil:
			cr.Error = ctl[0].Err.Error()
		default:
			cr.Matched = matcher.Matches(ctl[0])
			statusEligible := matcher.Status == 0 || ctl[0].Status == matcher.Status
			if !cr.Matched && matcher.Body != nil && statusEligible && ctl[0].BodyLen > len(ctl[0].Body) {
				cr.Error = fmt.Sprintf(
					"body matcher was inconclusive: response exceeded the %d-byte capture limit",
					engine.BodyCap,
				)
			}
		}
		summary.Control = cr
		report.Finalize(&summary, true, *maxSuccess)
	}

	if *jsonOut {
		if err := report.WriteJSON(os.Stdout, summary); err != nil {
			return 0, err
		}
	} else {
		report.WriteText(os.Stdout, summary)
	}

	return summary.ExitCode(), nil
}

const (
	maxBurstRequests   = 100
	maxRequestFileSize = 10 << 20
)

func readRequestFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxRequestFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxRequestFileSize {
		return nil, fmt.Errorf("request file exceeds %d bytes", maxRequestFileSize)
	}
	return raw, nil
}

func buildRequests(reqFile, target, method, path, data string, headers headerFlags, count int) ([]request.Request, error) {
	if count < 1 || count > maxBurstRequests {
		return nil, fmt.Errorf("-n must be between 1 and %d", maxBurstRequests)
	}
	var reqs []request.Request
	if reqFile != "" {
		raw, err := readRequestFile(reqFile)
		if err != nil {
			return nil, err
		}
		parsed, err := request.ParseFile(raw)
		if err != nil {
			return nil, err
		}
		if len(parsed) == 1 {
			reqs = request.Repeat(parsed[0], count)
		} else {
			reqs = parsed // an explicit multi-request set; -n is ignored
		}
	} else {
		hs := make([]request.Header, 0, len(headers))
		authority := ""
		for _, h := range headers {
			name, val, ok := strings.Cut(h, ":")
			if !ok {
				return nil, fmt.Errorf("bad header %q (want 'Name: Value')", h)
			}
			name = strings.ToLower(strings.TrimSpace(name))
			val = strings.TrimSpace(val)
			switch name {
			case "host":
				authority = val
			case "content-length":
				// Recomputed from the actual body by both protocol engines.
			default:
				hs = append(hs, request.Header{Name: name, Value: val})
			}
		}
		one := request.Request{Method: method, Path: path, Scheme: "https", Authority: authority, Headers: hs}
		if data != "" {
			one.Body = []byte(data)
		}
		reqs = request.Repeat(one, count)
	}

	if len(reqs) > maxBurstRequests {
		return nil, fmt.Errorf("burst contains %d requests; maximum is %d", len(reqs), maxBurstRequests)
	}
	for i := range reqs {
		if err := reqs[i].ApplyTarget(target); err != nil {
			return nil, err
		}
		if err := reqs[i].Validate(); err != nil {
			return nil, fmt.Errorf("request %d: %w", i+1, err)
		}
	}
	return reqs, nil
}

func buildMatcher(status int, body string) (*report.Matcher, error) {
	if status == 0 && body == "" {
		return nil, nil
	}
	m := &report.Matcher{Status: status}
	var parts []string
	if status != 0 {
		parts = append(parts, fmt.Sprintf("status=%d", status))
	}
	if body != "" {
		re, err := regexp.Compile(body)
		if err != nil {
			return nil, fmt.Errorf("bad -match-body regex: %w", err)
		}
		m.Body = re
		parts = append(parts, "body~/"+body+"/")
	}
	m.Label = strings.Join(parts, " & ")
	return m, nil
}

func resolveProto(proto string, first request.Request) string {
	if proto != "auto" {
		return proto
	}
	// The single-packet attack is the headline capability, so auto prefers
	// HTTP/2 on TLS targets. Use -proto http1 for HTTP/2-less HTTPS servers.
	if first.Scheme == "https" {
		return "http2"
	}
	return "http1"
}
