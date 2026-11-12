# Contributing to Transporter

Thank you for helping. This document covers setup, the `make` targets, how
CI gates changes, and the license terms for contributions.

## Setup

- Go 1.26 or newer (the `toolchain` line in `go.mod` selects the latest
  tested release automatically).
- For `make lint`: [golangci-lint](https://golangci-lint.run/) v2.15.0 in
  `$(go env GOPATH)/bin` or on `PATH`.
- Optional for `make docs-check`: Docker (Markdown lint runs from the pinned
  `davidanson/markdownlint-cli2` image, so Node is not needed) and `lychee`.
  Each is skipped locally if missing and required in CI.

Other tools (`go-licenses`, `govulncheck`) run at pinned versions through
`go run`, so nothing else needs installing.

## Make targets

| Target | What it does |
| --- | --- |
| `build` | Build `bin/transporter`. |
| `build-cross` | Cross-compile and vet for linux, darwin and windows on amd64 and arm64. |
| `test` / `test-short` | Unit and integration tests with `-race -shuffle=on`. |
| `cover` | Tests with coverage; fails below 85% of `internal/...`. |
| `e2e` | End-to-end tests against the built binary. |
| `fuzz` | Each fuzz target for `FUZZTIME` (default 30 s). |
| `lint` | `gofmt`, `go vet`, `golangci-lint`. |
| `tidy` / `tidy-check` | `go mod tidy`; check that `go.mod`/`go.sum` are tidy and verified. |
| `vuln` | `govulncheck`. |
| `license-check` | SPDX headers, the dependency license allowlist, and that `THIRD_PARTY_LICENSES` is current. |
| `third-party` | Regenerate `THIRD_PARTY_LICENSES` from the module cache. |
| `docs-check` | Requirements-to-tests table, Markdown lint, link check. |
| `ci` | All of the above, as CI runs them. |

## Expectations for changes

- Every `.go` file starts with the MPL-2.0 SPDX header followed by the
  project's copyright line (copy them from any existing file);
  `make license-check` enforces both. Do not add the MPL "Incompatible
  With Secondary Licenses" notice.
- Tests reference the requirement IDs they cover (for example
  `// TestX covers SEC-7`), and `docs/testing.md` maps every MUST
  requirement to tests.
- Exported identifiers have doc comments. Comments explain **why** for
  security checks, protocol invariants, concurrency and shutdown logic, and
  platform workarounds.
- Errors are wrapped with `%w` and context. Expected failures never panic.
- The pairing code must never be logged, printed (except the receiver
  banner), or included in errors. Use the `code.Code` type, which redacts
  itself.
- Do not add cryptography beyond the constructions in
  `docs/requirements.md`. Discuss any protocol change in an issue first,
  and update `docs/protocol.md` in the same change.
- New dependencies need a justification in `docs/DECISIONS.md`
  (maintenance status, license, why the standard library is not enough), a
  license on the LIC-3 allowlist, and `make third-party`.
- Keep `README.md` and `docs/` in sync with behavior, and record decisions
  in `docs/DECISIONS.md`.

## Commits and pull requests

- Small, focused commits with a clear subject line in the imperative mood
  ("Add resume offset test"), and a body explaining why when it isn't
  obvious.
- Open a pull request against `main` and fill in the template. CI must be
  green: the required checks are listed in `docs/branch-protection.md`.
  Pull requests need a review from a code owner.
- Add an entry under "Unreleased" in `CHANGELOG.md` for user-visible
  changes.

## License of contributions

Transporter is licensed under the Mozilla Public License 2.0. MPL-2.0 is a
**file-level** copyleft:

- Modifications to files covered by the MPL remain under MPL-2.0, and when
  you distribute them, their source must be available under the MPL.
- New files you add to this project are expected to be MPL-2.0 too, with the
  standard header.
- The MPL allows combining these files with code under other licenses in a
  larger work, provided the MPL files themselves stay under the MPL.

By submitting a contribution you agree that it is licensed under MPL-2.0,
the same license as the project ("inbound = outbound"). There is no
contributor license agreement. Make sure you have the right to contribute
the code (for example, that your employer allows it).
