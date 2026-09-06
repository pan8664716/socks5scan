# socks5scan

[中文文档](README.zh-CN.md) · [Changelog](CHANGELOG.md) · [Contributing](CONTRIBUTING.md) · [Releases](https://github.com/pan8664716/socks5scan/releases)

A fast, two-stage SOCKS5 proxy scanner written in Go.

**How it works:**

1. **probe** — cheap pre-screen: TCP connect + SOCKS5 handshake (6 bytes total) classifies
   each target as `closed` / `not-socks5` / `auth-required` / `no-auth`;
2. **verify** — full `CONNECT` tunnel validation for candidates, optionally followed by
   HTTP checks that record egress IP and end-to-end latency. Targets requiring auth are
   tried against a built-in weak-credential dictionary (RFC 1929).

> ⚠️ **Authorized use only.** Scan only networks and systems you own or are explicitly
> authorized to test. See [SECURITY.md](SECURITY.md).

## Features

- 🎯 Flexible targets: single IP, CIDR, IP ranges, comma-separated lists, `@file`,
  ASN (`AS13335`), ASN ranges — freely mixed
- 🔌 Flexible ports: lists and ranges (e.g. `1080,8080` or `1024-2048`)
- ⚡ High-throughput engine: pipelined generator → probe pool → verify pool with backpressure
- ✅ End-to-end validation with dual HTTP cross-checks (filters fake echo responders)
- 🔑 Built-in weak-credential dictionary, overridable with `-w`
- 📄 Three output formats: `text` (`socks5://…`), `json` (JSON lines), `uri` (`[user:pass@]ip:port`)
- 🖥️ Cross-platform binaries: Linux / macOS / Windows (amd64 + arm64)

## Install

Download a prebuilt binary from
[Releases](https://github.com/pan8664716/socks5scan/releases), or build from source
(requires Go 1.21+):

```sh
git clone https://github.com/pan8664716/socks5scan.git
cd socks5scan
make build   # native binary -> bin/socks5scan
make all     # all platforms  -> bin/
```

## Quick start

```sh
# Scan a /24 on common proxy ports, show only verified proxies
./bin/socks5scan -t 1.2.3.0/24 --only-verified -v

# Multiple targets and custom ports
./bin/socks5scan -t 10.0.0.0/8 -p 1024-2048 -c 5000 --only-verified -v

# Targets from file, JSON output to results/
./bin/socks5scan -t @./cidrs.txt -p 1080 -f json -o found.jsonl

# Scan an ASN (prefixes are fetched automatically)
./bin/socks5scan -t AS13335 -p 1080 --only-verified

# Skip end-to-end validation (tunnel check only)
./bin/socks5scan -t 203.0.113.0/24 --no-egress --verify-host 1.1.1.1 --verify-port 80
```

See `./bin/socks5scan -h` for the full flag reference.

## How validation works

A candidate counts as **verified** only if it survives the full chain:

1. SOCKS5 handshake (plus RFC 1929 auth when the server demands it);
2. `CONNECT` tunnel to the primary echo service (`httpbin.org/ip` by default);
3. a second, independent check against `info.cern.ch` requiring HTTP 200 and a keyword
   match — this filters proxies that return canned responses.

Use `--no-egress` to skip the HTTP checks and only verify that the tunnel opens,
or `--verify-host/--verify-port/--verify-path` to point validation at your own service
(recommended for large scans, to avoid hammering public endpoints).

## Performance tuning

Real-world throughput is usually bounded by bandwidth, NAT table size, and the 4s
default connect timeout — not by CPU. Practical guidance:

| Scenario | Flags |
| -------- | ----- |
| Home broadband | `-c 3000` (default), or lower if the router struggles |
| Cloud VM, 1 Gbps+ | `-c 5000`–`10000` |
| Polite / rate-limited | `--rate 1000` |
| Estimate scale first | `--dry-run` (no packets sent) |

Before raising concurrency, raise the file-descriptor limit:

```sh
ulimit -n 100000
```

The scanner warns on stderr when concurrency approaches the fd limit.

## Output

- Results go to **stdout** by default (pipe-friendly); logs and `[progress]` lines go to **stderr**.
- `-o FILE`: write results to a file. A bare filename lands in `results/`
  (e.g. `-o found.jsonl` → `results/found.jsonl`); a path is used as-is.
- `-f text|json|uri`, `-v` (auth/verification/egress/latency details),
  `--only-verified` (verified proxies only).
- `results/aliyun.log.example` shows what `--progress 10s` stderr output looks like.

## Project layout

```text
.
├── main.go                  # CLI: flags, target expansion, output wiring
├── internal/
│   ├── addr/                # target/port expression parsing, reserved ranges
│   ├── asn/                 # ASN -> IPv4 prefix expansion (bgpview/hackertarget/RIPE)
│   ├── dic/                 # weak-credential dictionary (built-in + -w file)
│   ├── probe/               # stage 1: 6-byte handshake pre-screen
│   ├── verify/              # stage 2: CONNECT tunnel + dual HTTP checks
│   ├── scan/                # pipelined engine (generator/probe/verify pools)
│   ├── output/              # text/json/uri serializers
│   └── netutil/             # socket tuning (SO_LINGER, fd limits)
├── bin/                     # build output (see Makefile BINDIR)
└── results/                 # scan result output (see -o flag)
```

## Development

```sh
gofmt -l .     # must be clean
make vet
make test
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the PR workflow. User-visible changes go in
[CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE)
