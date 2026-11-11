# Changelog

All notable changes to this project are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `transporter receive` and `transporter send`: encrypted, resumable
  transfer of files and directory trees with a one-time 9-word code.
- Noise NNpsk0 secure channel keyed from the code with HKDF-SHA-256.
- Whole-file BLAKE3 verification, `.part` files with automatic resume, an
  overwrite policy with conflicts, and `--verify` content comparison.
- Automatic reconnect with exponential backoff and full jitter, heartbeats
  and dead-connection detection, session supersession and BUSY handling.
- mDNS discovery (`_transporter._tcp`) with `--to` as an always-available
  alternative.
- Progress on stderr, final summaries, and documented exit codes.
- Documentation: README, architecture, protocol, security, testing, and the
  decisions log.
