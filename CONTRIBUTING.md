# Contributing

Contributions that improve syncburst's correctness, interoperability, safety,
documentation, or tests are welcome.

## Before opening a change

- Discuss substantial protocol or CLI changes in an issue first.
- Keep the runtime dependency-free unless there is a compelling, documented
  reason to change that policy.
- Do not add broad scanning, evasion, persistence, credential theft, or
  unauthorized-targeting features.
- Use only local fixtures or systems you have explicit permission to test.

## Development checks

Go 1.22 or newer is required.

```sh
gofmt -w .
go test ./...
go vet ./...
CGO_ENABLED=0 go build -trimpath ./cmd/syncburst
```

Changes to HTTP framing, HPACK, request parsing, matchers, verdicts, or exit
codes should include a regression test. Network tests must bind loopback on a
random port and clean up their server.

Fuzz targets can be exercised with:

```sh
go test ./internal/request -run '^$' -fuzz FuzzParseFile -fuzztime 10s
go test ./internal/http2 -run '^$' -fuzz FuzzStatusFromBlock -fuzztime 10s
```

## Pull requests

Keep changes focused. Explain:

- the problem and security/correctness impact;
- the behavior before and after;
- how the change was tested; and
- any compatibility or protocol trade-offs.

By contributing, you agree that your contribution is licensed under the MIT
License included in this repository.

Security-sensitive reports belong in the private channel described in
[SECURITY.md](SECURITY.md), not in a public issue.
