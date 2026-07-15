# syncburst

[![CI](https://github.com/skaterzeal/syncburst/actions/workflows/ci.yml/badge.svg)](https://github.com/skaterzeal/syncburst/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`syncburst` is a focused, zero-dependency tester for HTTP race conditions. It
coordinates a bounded burst of requests so an authorized tester can investigate
TOCTOU and limit-overrun flaws such as coupon reuse, double spending, duplicate
redemption, vote/invite limits, or retry-counter bypasses.

> Project status: **beta**. The core techniques are covered by unit, fuzz, and
> in-process integration tests, but real targets vary by proxy, CDN, protocol
> implementation, and application behavior. Treat every result as evidence to
> validate, not as an automatic vulnerability claim.

> **Authorized testing only.** Run this tool only against systems you own or
> have explicit permission to test. A burst can change application state.

## Contents

- [Why syncburst](#why-syncburst)
- [Install](#install)
- [Quick start](#quick-start)
- [Verdict model](#verdict-model)
- [Important flags](#important-flags)
- [Bundled test target](#bundled-test-target)
- [Scope and limitations](#scope-and-limitations)
- [Development](#development)
- [License](#license)

## Why syncburst

- HTTP/1.1 last-byte synchronization: one connection per request is primed,
  then each final byte is released together.
- HTTP/2 synchronized release: request streams are pre-sent on one TLS
  connection, then their terminating `END_STREAM` frames are emitted in one
  coalesced write.
- Explicit success budget: you define what success looks like and how many
  successes are legitimate.
- Conservative verdicts: response divergence alone is never called a race;
  partial transport failures and ambiguous body matches cannot produce a clean
  result.
- One static Go binary with no runtime or third-party Go dependencies.

The HTTP/2 implementation minimizes client-side release skew. It does not claim
that TLS, the operating system, or the network will preserve the write as one
physical TCP segment.

The synchronized-release approach builds on James Kettle's PortSwigger research,
[Smashing the state machine](https://portswigger.net/research/smashing-the-state-machine)
and [The single-packet attack](https://portswigger.net/research/the-single-packet-attack-making-remote-race-conditions-local),
which introduced the single-packet attack for HTTP/2. `syncburst` is an
independent, focused implementation of those ideas, not affiliated with
PortSwigger.

## Install

### Prebuilt binaries

Download a static binary for your platform from the
[Releases](https://github.com/skaterzeal/syncburst/releases) page. Archives are
published for Linux, macOS, and Windows on `amd64` and `arm64`. Each release
includes a `checksums.txt`; verify your download against it, for example:

```sh
sha256sum -c checksums.txt --ignore-missing
```

### go install

With Go 1.22 or newer:

```sh
go install github.com/skaterzeal/syncburst/cmd/syncburst@latest
```

### Build from source

```sh
git clone https://github.com/skaterzeal/syncburst.git
cd syncburst
CGO_ENABLED=0 go build -trimpath -o syncburst ./cmd/syncburst
```

On Windows, use `-o syncburst.exe`.

## Quick start

A raw Burp-style request is the recommended input. This example is included in
the repository as [`request.txt`](request.txt):

```http
POST /redeem HTTP/1.1
Host: target.example
Content-Type: application/json

{"code":"GIFT100"}
```

```sh
syncburst \
  -r request.txt \
  -u https://target.example \
  -n 30 \
  -match-status 200 \
  -max-success 1
```

The same request can be built from flags:

```sh
syncburst \
  -u https://target.example \
  -X POST \
  -path /redeem \
  -H "Content-Type: application/json" \
  -d '{"code":"GIFT100"}' \
  -n 30 \
  -match-status 200 \
  -max-success 1
```

`-u` must be an HTTP(S) base URL containing only scheme and authority. Put path
and query data in `-path` or the raw request.

## Verdict model

A meaningful automated test needs two inputs:

1. A success matcher: `-match-status`, `-match-body`, or both.
2. The legitimate success budget: `-max-success` (default `1`).

For a single-use redemption, status `200` with `-max-success 1` means one
successful response is expected. Two or more matching responses produce a race
signal. A normal protected result such as one `200` and nineteen `409`
responses is divergent, but it is **not** a race signal.

When a race signal occurs, the default control probe sends one additional lone
request:

- If it does not match, the signal is reported as `RACE CONFIRMED`.
- If it also matches, the result is `INCONCLUSIVE`; the endpoint may normally
  allow repeated success, or the configured budget may be wrong.
- If the control fails, the run is `INCOMPLETE`.

The control is supporting evidence, not a substitute for understanding the
endpoint. It is another potentially state-changing request. Disable it with
`-control=false` when an additional request is undesirable.

Example:

```text
syncburst — HTTP/2 burst of 30 request(s)
  timing:        min 18.42ms / median 20.11ms / mean 20.03ms / max 21.37ms
  response groups (status, body-bytes):
     28 x  status=409  body=29B
      2 x  status=200  body=21B
  matcher [status=200]: 2/30 matched (allowed maximum: 1)   <-- limit exceeded
  control:       a lone follow-up did not match
  note:          responses diverged; this is context, not proof by itself
  VERDICT: RACE CONFIRMED — matched successes exceeded the configured limit and the lone follow-up did not match.
```

### Exit codes

| Code | Meaning |
|---:|---|
| `0` | No race signal, or manual-review output when no matcher was configured |
| `1` | Confirmed or unvalidated race signal |
| `2` | Invalid, incomplete, or inconclusive run |

JSON output contains the explicit `verdict`, `race_signal`, error details, and
control result for automation.

## Important flags

| Flag | Purpose |
|---|---|
| `-r` | Raw request file; a line containing only `---` separates explicit requests |
| `-u` | Base target URL; overrides scheme and authority |
| `-n` | Burst size, from 1 to 100 (default 20) |
| `-proto` | `auto`, `http1`, or `http2`; auto prefers HTTP/2 for HTTPS |
| `-match-status` | HTTP status that counts as success |
| `-match-body` | Go regular expression that must match the captured response body |
| `-max-success` | Legitimate number of matching successes (default 1) |
| `-control` | Run the post-signal lone control probe (default true) |
| `-timeout` | Positive dial/read/write timeout (default 15s) |
| `-settle` | Priming delay before synchronized release (default 30ms) |
| `-insecure` | Disable TLS certificate verification; emits a warning |
| `-json` | Emit machine-readable JSON |
| `-version` | Print the build version |

If a raw file contains one request, `-n` duplicates it. If it contains multiple
`---`-separated requests, those requests form the burst and `-n` is ignored.
The total remains capped at 100.

## Bundled test target

The repository includes a deliberately vulnerable local HTTPS server:

```sh
go run ./testserver
```

In another terminal:

```sh
syncburst \
  -r request.txt \
  -u https://127.0.0.1:8443 \
  -n 30 \
  -match-status 200 \
  -max-success 1 \
  -insecure
```

The server is for local demonstration only. The automated integration tests
start isolated in-process servers on random loopback ports.

## Scope and limitations

- HTTP/2 currently supports TLS with ALPN (`h2`) only; h2c is not implemented.
- The hand-written HPACK reader extracts response status and does not expose all
  response headers.
- Up to 64 KiB of each response body is retained for `-match-body`; full body
  length is still counted. A non-match beyond that capture window makes the run
  incomplete rather than silently clean.
- HTTP/2 request bodies must fit the peer's initial per-stream flow-control
  window, and all pre-sent bodies together must fit the initial 65,535-byte
  connection window. The tool returns an explicit error instead of violating
  flow control.
- Individual request bodies are capped at 1 MiB, request headers at 64 KiB,
  and raw request files at 10 MiB to keep burst memory use bounded.
- Synchronization is usually strongest when the server reads the request body
  before committing the state change.
- Proxies, CDNs, rate limits, connection coalescing, and upstream protocol
  translation can materially change timing and results.
- The tool performs one bounded burst per invocation. It is not a scanner,
  crawler, or load generator.
- On Git Bash/MSYS, `/path` arguments may be rewritten as Windows paths. Prefer
  raw request files or set `MSYS_NO_PATHCONV=1`.

## Development

```sh
gofmt -w .
go test ./...
go vet ./...
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution expectations and
[SECURITY.md](SECURITY.md) for private vulnerability reporting.

## License

MIT — see [LICENSE](LICENSE).
