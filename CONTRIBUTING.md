# Contributing to socks5scan

Thanks for your interest in contributing! This document covers the workflow and quality bar.

## Development setup

- Go 1.21+ (`go version` to check).
- Clone the repo and build:

```sh
make build        # native binary -> bin/socks5scan
make all          # cross-compile linux/darwin/windows -> bin/
```

## Before submitting

Run the full local check — CI runs the same steps and will fail otherwise:

```sh
gofmt -l .        # must print nothing
make vet
make test
```

## Pull requests

- Keep PRs focused: one feature or fix per PR.
- Update docs when behavior changes: `README.md`, `README.zh-CN.md`, and `./bin/socks5scan -h` text.
- Add or update tests for `internal/...` packages when touching parsing, output, or protocol logic.
  Tests must be hermetic — no live network access (see `internal/probe/probe_test.go` for the
  loopback-fake-server pattern).
- Write a `CHANGELOG.md` entry under `Unreleased` when the change is user-visible.

## Reporting bugs

Use the bug-report issue template and include:

- `socks5scan` version (`git describe --tags` or release tag),
- OS / architecture and Go version,
- full command line (redact sensitive targets if needed),
- relevant `[progress]` / `[done]` log lines from stderr.

## Security issues

Do **not** open a public issue for vulnerabilities — see [SECURITY.md](SECURITY.md).
