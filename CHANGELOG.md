# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `ParsePorts` now accepts full-width (Chinese) commas anywhere in the expression.
- `resolveOutPath` treats both `/` and `\` as path separators (Windows-safe).
- `--no-verify` / `--no-egress` / `--no-weak` are explicit flags with default `false`
  (previously registered with default `true`, relying on presence detection).
- `make clean` no longer deletes the `bin/` directory itself.

### Added

- Unit tests for `addr`, `asn`, `dic`, `output` and `probe` (loopback-only, no live network).
- CI now runs `gofmt` check and `make test`.
- `LICENSE` (MIT), `CONTRIBUTING.md`, `SECURITY.md`, issue/PR templates.

## [0.1] - 2026-09-06

- First usable release: two-stage probe+verify pipeline, ASN scanning,
  weak-credential probing (RFC 1929), text/json/uri output, unified `bin/` and `results/` dirs.
