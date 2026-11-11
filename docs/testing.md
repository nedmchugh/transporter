# Testing

How to run the tests, what each category covers, how fault injection works,
the coverage policy, and the requirements-to-tests table (DOC-5, TEST-1).

## Running tests

| Command | What it runs |
| --- | --- |
| `make test` | All unit and integration tests with `-race -shuffle=on`. |
| `make test-short` | The same with `-short` (skips the slow statistical and large-file variants). |
| `make cover` | `make test` with coverage; fails below 85% statement coverage of `internal/...` (excluding `internal/testutil`). Writes `coverage.out`. |
| `make e2e` | End-to-end tests (`-tags e2e`): build the real binary (with `-race`) and run it as subprocesses over loopback. |
| `make fuzz` | Every fuzz target for `FUZZTIME` (default 30 s each; CI's fuzz-smoke job uses 30 s). |
| `make ci` | Everything CI checks: lint, license, tidy, coverage, e2e, cross-build, vuln, docs, fuzz. Use `make ci FUZZTIME=5s` for a quicker local run. |

Single packages or tests: `go test -race -run TestFaultInjection ./internal/send/`,
`go test -tags e2e -race -run TestE2ETree ./test/e2e/`.

All tests are hermetic: temporary directories (`t.TempDir`), loopback
addresses with port 0, no fixed ports, no network access beyond loopback
(and multicast for the mDNS tests, which skip without it). They are safe to
run in parallel.

## Test categories

- **Unit tests** (table-driven): code generation, parsing, leniency, error
  messages, redaction and golden KDF vectors (`internal/code`); frame
  encoding and decoding (`internal/secure`); every message round trip and
  malformed-input table (`internal/proto`); backoff schedule with injected
  jitter and sleeper (`internal/send`); path validation, Windows rules and
  collisions (`internal/manifest`); quick check, resume rounding and error
  classification (`internal/recv`, `internal/fail`); CLI parsing including
  CLI-6 (`cmd/transporter`).
- **Secure channel tests** (`internal/secure`): right and wrong code,
  prologue mismatch, tampered, replayed, reordered, truncated, oversized and
  zero-length frames, deadlines, cancellation, concurrent read/write.
- **Fuzz tests** with committed seed corpora under `testdata/fuzz`:
  `FuzzDecode` (every message decoder; also checks canonical re-encoding),
  `FuzzReadFrame` (frame reader), `FuzzValidatePath` (path validator),
  `FuzzParse` (code parser). Decoders bound allocations by the input
  present, which the fuzzers exercise with lying length fields.
- **Hostile-input tests** (`internal/recv/hostile_test.go`): a test-only
  client that knows the code sends crafted messages: hostile paths,
  collisions, limit violations, out-of-state messages, offsets outside the
  declared size, and symlinks planted in the destination. Each test checks
  that nothing was written outside the destination.
- **Integration tests** (`internal/send/*_test.go`): a real sender and
  receiver in one process over loopback, covering trees, resume, the
  overwrite and verify policies, pipelining bounds, hash mismatches, and
  fault injection.
- **End-to-end tests** (`test/e2e`, TEST-8): the built binary as
  subprocesses. Scenarios 1 to 14 are covered by `TestE2ESingleFile`,
  `TestE2ELargeFile`, `TestE2ETree`, `TestE2EKillSenderAndRerun`,
  `TestE2EKillReceiverAndRestart`, `TestE2EFlakyProxy`, `TestE2EWrongCode`,
  `TestE2EHostileManifest`, `TestE2EOverwriteAndVerify`, `TestE2ETimeouts`,
  `TestE2ECodeInputMethods`, `TestE2EDiscovery`, `TestE2EModifiedDuringTransfer`,
  `TestE2EBusy` and `TestE2EExitPrecedence`. `TestE2ECodeNeverLogged`
  covers TEST-9 and `TestE2ESignals` covers REL-7.

## Fault injection

`internal/testutil.FaultConn` wraps a `net.Conn` and, by cumulative byte
counts, can drop the connection (as a reset, not a clean close), stall reads
or writes without closing (until the deadline), corrupt a chosen byte, or
delay every operation. `internal/send/fault_test.go` injects these through
the sender's `Dial` hook to cover drops during the handshake, the manifest,
chunks and ACKs; a flaky link with many drops; stalled connections
(exercising the heartbeat and deadline logic, REL-3); corrupted ciphertext;
and a receiver replaced between attempts.

`internal/testutil.Proxy` is a TCP proxy that cuts the n-th connection after
a number of bytes, either resetting both sides or leaving the receiver's
side **half-open** (silent). The half-open mode forces the receiver to
supersede a connection it still believes is alive (RCV-5). The e2e flaky
link test uses the proxy with the real binary.

Two unexported test hooks exist in `internal/send` (DECISIONS.md section
8): one corrupts chunk data after hashing (XFER-4 mismatch paths), one
observes in-flight counts (XFER-6). Both are nil in production.

## Leaks, races, timing

- Every test runs with `-race -shuffle=on`.
- `testutil.CheckLeaks` (an in-repo helper; DECISIONS.md section 6)
  snapshots goroutines at the start of a test and fails if goroutines
  created by project code are still running five seconds after the test
  ends. It is used in all session, channel and fault tests (TEST-6).
- Fault tests use short heartbeat and dead-connection timings
  (100 ms / 1-2 s) through the `Link` options, so they exercise the
  production code paths quickly.

## Platform notes

- **Windows**: process-kill tests use `Process.Kill`, which is
  `TerminateProcess` on Windows and `SIGKILL` elsewhere; the behavior is
  the same for these tests (TEST-11). `os.Interrupt` cannot be delivered to
  another process on Windows, so `TestE2ESignals` is skipped there; Ctrl-C
  handling uses the same code path on all platforms. Tests that need POSIX
  permissions, FIFOs, sockets or unprivileged symlinks skip on Windows.
- **mDNS**: `TestAdvertiseAndFind` and `TestE2EDiscovery` skip with a clear
  message when multicast does not work (common in CI containers and behind
  host firewalls). Record construction and answer matching are unit-tested
  without the network.
- **Memory**: that memory does not grow with file size (SND-4, NFR-4) is
  verified by design and inspection: one chunk buffer and fixed frame
  buffers per connection, with no per-chunk frame allocation. There is no
  test that measures it, because heap measurements are too noisy for CI.

## Coverage policy

Statement coverage over `internal/...` (excluding `internal/testutil`) is
measured with `-coverpkg`, so the integration tests count for the packages
they exercise. `make cover` fails below **85%**. The threshold was raised in
steps during development (DECISIONS.md D-7.1). New code should come with
tests that assert behavior; coverage padding is not wanted.

## Requirements to tests

Each MUST requirement and where it is verified (TEST-1). Test names are
`package` plus function. Requirements about documentation, CI or
repository contents are verified by inspection of the named files.
`tools/reqcheck` fails CI if a MUST requirement is missing from this table.

| Requirement | Verified by |
| --- | --- |
| CODE-1 | `internal/code` TestWordListProperties; `internal/code` TestGenerate; `internal/code` TestGenerateUniform |
| CODE-2 | `internal/code` TestWordListProperties |
| CODE-3 | `internal/code` TestParseLenient |
| CODE-4 | `internal/code` TestParseErrors |
| CODE-5 | `internal/code` TestParseLenient |
| CODE-6 | `internal/code` TestRedaction |
| CODE-7 | `internal/code` TestParseErrors; `internal/discover` TestServiceRecords; `test/e2e` TestE2ECodeNeverLogged |
| CODE-8 | `cmd/transporter` TestReadCodePrecedence; `test/e2e` TestE2ECodeInputMethods |
| CODE-9 | Inspection: `docs/security.md` section 6 and `transporter send --help` explain process-listing and history visibility. |
| RCV-1 | `cmd/transporter` TestParseReceiveFlags; `internal/recv` TestNewCreatesDestination |
| RCV-2 | `test/e2e` TestE2ESingleFile |
| RCV-3 | `cmd/transporter` TestParseReceiveFlags |
| RCV-4 | `cmd/transporter` TestListenAddrs |
| RCV-5 | `internal/recv` TestBusy; `internal/send` TestSupersession; `test/e2e` TestE2EBusy; `test/e2e` TestE2EFlakyProxy; `test/e2e` TestE2EKillSenderAndRerun |
| RCV-6 | `test/e2e` TestE2ESingleFile |
| RCV-7 | `internal/recv` TestIdleTimeout; `test/e2e` TestE2ETimeouts |
| RCV-8 | `internal/recv` TestFailedHandshakesHarmless; `internal/recv` TestUnauthenticatedLimit |
| SND-1 | `internal/send` TestMultipleSources |
| SND-2 | `internal/manifest` TestWalk; `internal/manifest` TestWalkErrors; `internal/send` TestMultipleSources |
| SND-3 | `cmd/transporter` TestParseSendFlags |
| SND-4 | `internal/manifest` TestWalk; `test/e2e` TestE2ELargeFile |
| SND-5 | `internal/manifest` TestWalkUnreadable |
| SND-6 | `test/e2e` TestE2EModifiedDuringTransfer |
| SND-7 | `test/e2e` TestE2EDiscovery |
| TREE-1 | `internal/manifest` TestWalk |
| TREE-2 | `internal/manifest` TestValidatePathHostile; `internal/recv` TestHostileManifest |
| TREE-3 | `internal/manifest` TestWalkUnrepresentable |
| TREE-4 | `internal/manifest` TestWalk; `internal/recv` TestExistingDirectories; `internal/send` TestEmptyFileAndDirs; `test/e2e` TestE2ETree |
| TREE-5 | `internal/recv` TestResumeOffset |
| TREE-6 | `internal/manifest` TestCheckerStructure; `internal/manifest` TestWalk; `internal/proto` TestDecodeInvalid |
| TREE-7 | `internal/manifest` TestWalk; `internal/recv` TestExistingDirectories; `internal/send` TestSingleFile |
| TREE-8 | Inspection: directory mtimes are not applied (`internal/recv/conn.go` creates directories only); documented in the README platform notes. Tree comparisons check file mtimes only. |
| TREE-9 | `internal/manifest` TestCheckerCollisions; `internal/recv` TestHostileManifest |
| TREE-10 | `internal/manifest` TestValidateWindowsPath; `internal/recv` TestWindowsInvalidNames |
| TREE-11 | `internal/manifest` TestValidatePathHostile; `internal/manifest` TestCheckerStructure; `internal/recv` TestHostileManifest |
| TREE-12 | `internal/manifest` TestCheckerStructure |
| XFER-1 | `internal/send` TestSingleFile; `internal/send` TestResumeFromPart |
| XFER-2 | `internal/send` TestResumeFromPart; `test/e2e` TestE2EKillReceiverAndRestart |
| XFER-3 | `internal/send` TestSingleFile; `internal/send` TestHashMismatchTwiceIsIntegrityFailure |
| XFER-4 | `internal/send` TestHashMismatchRetransmitsOnce; `internal/send` TestHashMismatchTwiceIsIntegrityFailure; `internal/send` TestResumeBadPrefix |
| XFER-5 | `internal/send` TestSingleFile |
| XFER-6 | `internal/send` TestPipelining; `test/e2e` TestE2ETree |
| XFER-7 | `internal/send` TestOverwritePolicy; `test/e2e` TestE2EOverwriteAndVerify |
| RES-1 | `internal/send` TestRerunSkipsEverything; `internal/send` TestResumeFromPart; `test/e2e` TestE2EKillSenderAndRerun |
| RES-2 | `internal/recv` TestQuickCheck; `internal/send` TestOverwritePolicy; `internal/send` TestRerunSkipsEverything; `test/e2e` TestE2EOverwriteAndVerify |
| RES-3 | `internal/recv` TestResumeOffset; `internal/send` TestResumeFromPart; `internal/send` TestResumeOversizedPart; `test/e2e` TestE2EKillSenderAndRerun; `test/e2e` TestE2EKillReceiverAndRestart |
| RES-4 | `internal/send` TestStrayPartsUntouched |
| RES-5 | `internal/recv` TestTypeConflicts |
| REL-1 | `internal/send` TestBackoffSchedule; `internal/send` TestRetryBudget; `internal/send` TestFaultInjection; `test/e2e` TestE2ETimeouts; `test/e2e` TestE2EFlakyProxy |
| REL-2 | `internal/send` TestFaultInjection; `internal/send` TestReceiverRestartBetweenAttempts; `internal/send` TestSupersession; `test/e2e` TestE2EFlakyProxy |
| REL-3 | `internal/proto` TestLinkSendRecv; `internal/proto` TestLinkDeadPeer; `internal/secure` TestHandshakeDeadline; `internal/secure` TestFrameDeadlines; `internal/send` TestFaultInjection |
| REL-4 | `internal/fail` TestClassification; `internal/send` TestRetryBudget |
| REL-5 | `internal/secure` TestHandshakeWrongCode; `internal/send` TestWrongCode; `test/e2e` TestE2EWrongCode |
| REL-6 | `internal/send` TestFaultInjection |
| REL-7 | `internal/send` TestRetryInterrupted; `test/e2e` TestE2ESignals; `test/e2e` TestE2EKillSenderAndRerun |
| DISC-1 | `internal/discover` TestAdvertiseAndFind; `internal/discover` TestServiceRecords; `test/e2e` TestE2EDiscovery |
| DISC-2 | `internal/discover` TestAdvertiseAndFind; `internal/discover` TestMatch; `test/e2e` TestE2EDiscovery |
| DISC-3 | `internal/discover` TestFindTimeout; `test/e2e` TestE2EDiscoveryFails |
| DISC-4 | `test/e2e` TestE2EDiscoveryFails |
| DISC-5 | `internal/discover` TestAdvertiseAndFind; `test/e2e` TestE2EDiscovery |
| SEC-1 | `internal/secure` TestHandshakeSuccess |
| SEC-2 | `internal/code` TestKDFGolden; `internal/pairing` TestCodePairer |
| SEC-3 | `internal/secure` TestHandshakePrologueMismatch |
| SEC-4 | `internal/secure` TestHandshakeWrongCode; `internal/secure` TestHandshakeDeadline |
| SEC-5 | `internal/secure` TestFreshKeysPerConnection |
| SEC-6 | `internal/secure` TestFrameTampering |
| SEC-7 | `internal/secure` TestHandshakeOversizedMessage; `internal/secure` TestFrameTampering; `internal/secure` TestFrameLengthLimits; `internal/secure` TestPlaintextSize |
| SEC-8 | `internal/proto` TestLinkSendRecv |
| SEC-9 | `internal/recv` TestHostileManifest; `internal/recv` TestSymlinkEscape; `internal/recv` TestOnlyRootFilesystemAccess |
| SEC-10 | `internal/proto` TestDecodeInvalid; `internal/recv` TestOutOfStateMessages |
| SEC-11 | `internal/recv` TestSymlinkEscape |
| SEC-12 | `internal/recv` TestHostileManifest |
| SEC-13 | `internal/recv` TestOutOfStateMessages; `internal/recv` TestVersionMismatch |
| SEC-14 | `internal/pairing` TestCodePairer |
| SEC-15 | `test/e2e` TestE2ECodeNeverLogged |
| SEC-16 | Inspection: `docs/security.md` (top note, section 7) and the README security section. |
| PROTO-1 | `internal/proto` TestRoundTrip; `internal/proto` TestTruncation; `internal/proto` TestDecodeInvalid |
| PROTO-2 | `internal/proto` TestRoundTrip |
| PROTO-3 | `internal/recv` TestVersionMismatch |
| PROTO-4 | `internal/recv` TestOutOfStateMessages |
| PROTO-5 | `internal/send` TestSupersession |
| PROTO-6 | `internal/send` TestPipelining |
| PROTO-7 | `internal/send` TestSingleFile; `test/e2e` TestE2ESingleFile |
| CLI-1 | `cmd/transporter` TestRunUsage; `test/e2e` TestVersion |
| CLI-2 | `internal/progress` TestPlainOutput; `internal/progress` TestTTYOutput |
| CLI-3 | `test/e2e` TestE2EExitPrecedence |
| CLI-4 | `test/e2e` TestE2EWrongCode; `test/e2e` TestE2ETimeouts |
| CLI-5 | `cmd/transporter` TestRunUsage; `cmd/transporter` TestHelpDocumentsEveryFlag |
| CLI-6 | `cmd/transporter` TestSplitCodeAndPaths; `test/e2e` TestE2ECodeInputMethods |
| CLI-7 | `cmd/transporter` TestRunUsage; `internal/fail` TestExitCodes; `internal/recv` TestNoSpace; `internal/recv` TestDestinationNotWritable; `internal/recv` TestIdleTimeout; `internal/send` TestHashMismatchTwiceIsIntegrityFailure (+3 more) |
| CLI-8 | `internal/send` TestOverwritePolicy; `test/e2e` TestE2EExitPrecedence |
| CLI-9 | `internal/fail` TestWorst; `test/e2e` TestE2EExitPrecedence |
| NFR-1 | CI: `test` and `e2e` jobs on ubuntu, macOS and Windows; `build` job cross-compiles linux/darwin/windows x amd64/arm64 (`make build-cross`). |
| NFR-2 | Inspection and CI: `go.mod` (`go 1.25.0`), DECISIONS.md D-1.1 (verification against the Go 1.24/1.25 release notes); CI tests Go 1.25.x and 1.27.x with `GOTOOLCHAIN=local`. |
| NFR-4 | `test/e2e` TestE2ELargeFile |
| NFR-5 | Inspection: DECISIONS.md sections 1 and 6 justify each dependency. |
| NFR-6 | Lint (`revive` exported-comment rule, `errorlint`, `errcheck`) and review. |
| NFR-7 | Inspection: `internal/meta.Name` is the only use of the name as a name; module path `github.com/OWNER/transporter` (DECISIONS.md D-2.2). |
| NFR-8 | Inspection: README "Not affiliated" section; no franchise material in the repository. |
| TEST-1 | This table; `tools/reqcheck` fails if a MUST requirement is missing from it. |
| TEST-2 | `internal/proto` TestRoundTrip; `internal/send` TestBackoffSchedule |
| TEST-3 | `internal/secure` TestHandshakeSuccess; `internal/secure` TestHandshakeWrongCode; `internal/secure` TestFrameTampering; `internal/secure` TestFrameLengthLimits; `internal/secure` TestFrameDeadlines; `internal/secure` TestConcurrentReadWrite |
| TEST-4 | `internal/proto` FuzzDecode; `internal/secure` FuzzReadFrame |
| TEST-5 | `internal/manifest` TestValidatePathHostile; `internal/recv` TestHostileManifest; `internal/recv` TestOutOfStateMessages; `internal/recv` TestSymlinkEscape |
| TEST-6 | `internal/send` TestFaultInjection |
| TEST-7 | `internal/proto` TestLinkDeadPeer; `internal/secure` TestHandshakeFaults; `internal/send` TestFaultInjection; `internal/send` TestReceiverRestartBetweenAttempts |
| TEST-8 | `internal/send` TestProxyFlakyLink; `internal/send` TestWrongCode; `test/e2e` TestE2EDiscovery; `test/e2e` TestE2EWrongCode; `test/e2e` TestE2ETimeouts; `test/e2e` TestE2ECodeInputMethods (+11 more) |
| TEST-9 | `test/e2e` TestE2ECodeNeverLogged |
| TEST-10 | `test/e2e` TestE2ETree |
| CI-1 | Inspection: `.github/workflows/ci.yml` jobs lint, test, e2e, fuzz-smoke, vuln, license, build, mod-tidy, docs. |
| CI-2 | Inspection: `.github/workflows/codeql.yml`, `.github/workflows/dependency-review.yml`. |
| CI-4 | Inspection: every `uses:` is pinned to a SHA resolved from the action repository (DECISIONS.md section 1.7). |
| CI-5 | Inspection: top-level `permissions: contents: read`, per-job grants, `concurrency`, `timeout-minutes`, no `pull_request_target`. |
| CI-6 | Inspection: `.github/dependabot.yml`. |
| CI-7 | Inspection: `Makefile` targets; the workflows call the same targets. |
| CI-8 | Inspection: `docs/branch-protection.md`. |
| CI-9 | Inspection: `.github/PULL_REQUEST_TEMPLATE.md`, `.github/ISSUE_TEMPLATE/`, `.github/CODEOWNERS`. |
| DOC-1 | Inspection: `README.md`. |
| DOC-2 | Inspection: `docs/architecture.md`. |
| DOC-3 | Inspection: `docs/protocol.md`, re-verified against `internal/proto` and `internal/secure`. |
| DOC-4 | Inspection: `docs/security.md`. |
| DOC-5 | Inspection: this document. |
| DOC-6 | Inspection: `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`, `CODE_OF_CONDUCT.md`. |
| DOC-7 | Lint (`revive` exported rule); `Example` tests in `internal/code`, `internal/proto`, `internal/manifest`. |
| DOC-8 | Inspection: `docs/DECISIONS.md`. |
| LIC-1 | Inspection: `LICENSE` matches mozilla.org (SHA-256 recorded in DECISIONS.md section 1.8). |
| LIC-2 | `tools/spdxcheck` TestCheck |
| LIC-3 | CI: `make license-check` runs go-licenses with the allowlist; dependency-review enforces it on PRs. |
| LIC-4 | `tools/spdxcheck` TestCheck |
| LIC-5 | Inspection: DECISIONS.md section 6 (no dependency outside the allowlist). |
| LIC-6 | CI: `make license-check` regenerates `THIRD_PARTY_LICENSES` and fails on a difference; `.goreleaser.yaml` ships it in archives. |
| LIC-7 | Inspection: `CONTRIBUTING.md` and README license section. |
| LIC-8 | Inspection: README and `docs/security.md` export notices. |
| DEL-1 | Inspection: repository contents. |
| DEL-2 | Inspection: package layout (additions in DECISIONS.md D-2.1). |
| DEL-3 | Design: transfer code uses `net.Conn` and `proto.FrameConn`; tests run it over `net.Pipe`, `testutil.FaultConn` and loopback. |
| DEL-4 | The final report. |
