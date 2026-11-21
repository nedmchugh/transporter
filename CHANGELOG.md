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

### Fixed

- Discovery on machines with more than one network: mDNS advertised and
  queried on only one interface, the sender could pick an unreachable
  receiver address (for example a Docker bridge), and large container or
  VPN subnets could use up the sweep's address cap before the LAN.
- The last progress line no longer stays on screen in front of the
  summary (`... 0/5 filesSummary: ...`).
- The receiver's list of stray `.part` files looks only in the
  destination's top level and under the paths being transferred, so
  receiving into a home directory no longer walks all of it or lists a
  browser's partial downloads.
