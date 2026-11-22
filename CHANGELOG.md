# Changelog

All notable changes to this project are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.1] - 2026-11-21

### Added

- README section "Finding the receiver": how mDNS, the UDP sweep and
  `--to` are tried, with example output, recipes for the discovery flags,
  the firewall ports to open, and the limits.

## [0.2.0] - 2026-11-21

### Added

- `scripts/install.sh` (also `make install`) builds Transporter for this
  machine's OS and architecture, in Docker by default or with the local Go
  toolchain (`--local`), and installs it as `/usr/local/bin/transporter`.
  It checks for root (sudo or doas) before building and uses it only for
  the copy.

## [0.1.1] - 2026-11-20

### Fixed

- The receiver's progress counts files that are already complete, as the
  sender's does: a rerun shows `5/5 files` instead of `0/0 files`.
- Progress no longer counts files twice after a reconnect, on either side
  (it could show several times the transfer size), and bytes already in
  place (complete files, resumed prefixes) no longer inflate the rate and
  ETA.

## [0.1.0] - 2026-11-20

### Added

- `transporter receive` and `transporter send`: encrypted, resumable
  transfer of files and directory trees with a one-time 9-word code.
- Noise NNpsk0 secure channel keyed from the code with HKDF-SHA-256.
- Whole-file BLAKE3 verification, `.part` files with automatic resume, an
  overwrite policy with conflicts, and `--verify` content comparison.
- Automatic reconnect with exponential backoff and full jitter, heartbeats
  and dead-connection detection, session supersession and BUSY handling.
- mDNS discovery (`_transporter._tcp`) on every network interface, with
  `--to` as an always-available alternative.
- A UDP unicast sweep of the local IPv4 subnets (UDP port 29873) that finds
  the receiver when mDNS does not. It is on by default; `--no-sweep` and
  `--sweep-port`, on both send and receive and in the config file, turn it
  off or change its port.
- Progress on stderr, final summaries, and documented exit codes.
- Command-line parsing with cobra, and an optional YAML config file for
  your own flag defaults: by default `transporter/config.yaml` in the user
  config directory, or `--config PATH`.
- Documentation: README, architecture, protocol, security, testing, and the
  decisions log.

[Unreleased]: https://github.com/nedmchugh/transporter/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/nedmchugh/transporter/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/nedmchugh/transporter/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/nedmchugh/transporter/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/nedmchugh/transporter/releases/tag/v0.1.0
