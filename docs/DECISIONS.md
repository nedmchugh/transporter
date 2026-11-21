# Decisions log

This is a running log of design decisions, verification results, and
interpretations of [requirements.md](requirements.md). Each entry is short:
the decision, then the reason. Entries are grouped by topic, and later entries
override earlier ones where they conflict.

## 0. Process

- **D-0.1 Requirements location.** The requirements arrived as
  `transporter-requirements.md` in the repository root. The task referred to
  `docs/requirements.md`, so the file was moved there unchanged.
- **D-0.2 `obsolete/` directory.** The untracked `obsolete/` directory (an
  older prompt) is not part of the project. It is listed in `.gitignore` so it
  is never committed by accident. It was not modified.
- **D-0.3 Phases.** Work follows the eight phases in the task. Each phase ends
  with `make ci` passing and a commit.

## 1. Verification results (done before writing code)

### 1.1 Go version (NFR-2)

- **Verified source:** the Go 1.25 release notes (<https://go.dev/doc/go1.25>)
  say: "The Root type supports the following additional methods: Root.Chmod,
  Root.Chown, Root.Chtimes, Root.Lchown, Root.Link, Root.MkdirAll,
  Root.ReadFile, Root.Readlink, Root.RemoveAll, Root.Rename, Root.Symlink,
  Root.WriteFile". The Go 1.24 release notes (<https://go.dev/doc/go1.24>)
  introduce `os.Root` with Open, Create, OpenFile, Mkdir, Remove, Stat and
  Lstat only.
- The receiver needs open, create, mkdir (nested), rename, chmod, chtimes,
  remove, stat and lstat. `Rename`, `MkdirAll` and `Chtimes` first appear in Go
  1.25, so **the minimum is Go 1.25**, which matches the belief stated in
  NFR-2.
- *(Superseded by D-1.3: the minimum is now Go 1.26.)* `go.mod` used
  `go 1.25.0` and `toolchain go1.27.4` (the latest stable
  release on 2026-11-10, from <https://go.dev/dl/?mode=json>). CI tests Go
  1.25.x with `GOTOOLCHAIN=local` (otherwise the `toolchain` line would
  silently switch to 1.27.4) and the latest stable release.
- **Caveat recorded for the maintainer:** Go 1.25 is past the upstream support
  window (only the two latest releases, 1.26 and 1.27, get security fixes).
  NFR-2 is a MUST that fixes the minimum at 1.25, so this is kept, but the
  `toolchain` line makes default builds use the supported 1.27.4. Release
  binaries are built with the latest stable Go. Raising the minimum to 1.26 is
  a one-line change, listed as a recommendation in the final report.
- **Consequence for `golang.org/x` modules:** their newest versions require Go
  1.26 (`go 1.26.0` in their `go.mod`). The last versions that still declare
  Go 1.25 were found from the module proxy and are used: `x/text v0.41.0`,
  `x/term v0.45.0`, `x/sys v0.47.0`, `x/net v0.58.0`, `x/crypto v0.55.0`.
  Dependabot updates that raise the `go` line fail the Go 1.25 CI job; this
  is intended.
- **Observed cost (phase 2):** govulncheck reports GO-2026-6354 and
  GO-2026-6355 (`x/crypto/ssh` DoS) and GO-2026-5932 (`x/crypto/openpgp`
  deprecated) in `x/crypto v0.55.0`. The fixes are only in versions that
  require Go 1.26. Transporter imports neither package, and govulncheck
  confirms the code does not reach them ("Your code is affected by 0
  vulnerabilities"), so the `vuln` job passes. This is the main reason the
  final report recommends raising the minimum to Go 1.26.

### 1.1b D-1.3: minimum raised to Go 1.26 (maintainer decision)

- On 2026-11-10 the maintainer decided to raise the minimum Go version to
  **1.26**. This was the recommendation in the final report and open item 8.
  It knowingly departs from the letter of NFR-2, which defines the minimum
  as the oldest release with the needed `os.Root` operations (Go 1.25,
  still true as verified above). Reason: Go 1.25 is out of upstream
  security support, and current `golang.org/x` modules, including the
  `x/crypto` fixes for GO-2026-6354 and GO-2026-6355, require Go 1.26.
- `go.mod`: `go 1.26.0`, `toolchain go1.27.4`. CI tests 1.26.x and 1.27.x
  with `GOTOOLCHAIN=local`.
- Dependencies refreshed to current releases: `x/crypto v0.58.0`,
  `x/net v0.62.0`, `x/sys v0.50.0`, `x/term v0.48.0`, `x/text v0.44.0`,
  `miekg/dns v1.1.73`, `klauspost/cpuid/v2 v2.4.2`. The pinned-old-version
  notes in D-1.1 no longer apply.

### 1.2 `github.com/flynn/noise` (SEC-1)

- **Version:** v1.1.0 (2024-02-02, from `proxy.golang.org`). Repository not
  archived; last push 2024-02-18; 3 open issues, none security-relevant
  (Kyber feature request, nonce allocation performance, a payload-size
  calculation note).
- **Advisories:** GHSA-6cr6-fmvc-vw2p (DoS) and GHSA-g9mp-8g3h-3c5c (improper
  nonce handling), both fixed in v1.0.0. v1.1.0 is not affected.
- **API (read from the module source with `go doc`):** `noise.Config` has
  `CipherSuite`, `Pattern`, `Initiator`, `Prologue`, `PresharedKey`,
  `PresharedKeyPlacement`. `NewHandshakeState`, `WriteMessage` and
  `ReadMessage` return two `*CipherState` values when the handshake completes.
  `CipherState.Encrypt` and `Decrypt` increment the nonce automatically and
  return `ErrMaxNonce` at 2^64-2. The library builds the protocol name
  `Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s` from `HandshakeNN` and
  `PresharedKeyPlacement: 0`.
- **License:** BSD-3-Clause (copyright Prime Directive, Inc.; read from the
  LICENSE file in the module zip; GitHub reports `NOASSERTION` because of the
  extra trademark line). On the allowlist.
- **Verdict:** suitable. It is stable and lightly maintained rather than
  abandoned, it implements exactly the needed pattern, and no other Go Noise
  library is better maintained. Its old `golang.org/x/crypto` requirement is
  raised to a current Go-1.25-compatible release in our `go.mod`.
- The copyright holder's name ("Prime Directive, Inc.") appears in
  `THIRD_PARTY_LICENSES` because the BSD license requires reproducing the
  notice verbatim. This is a legal attribution, not franchise material, so it
  does not conflict with NFR-8.

### 1.3 Wordlist (CODE-1, CODE-2)

- **Candidates checked** (each downloaded and analyzed by script):
  - BIP-39 English (`bitcoin/bips`, `bip-0039/english.txt`, SHA-256
    `2f5eed53…dbda`): 2048 words. **License: MIT** ("This BIP falls under the
    MIT License", read from `bip-0039.mediawiki`). Unique first four letters:
    yes. **Prefix-free: no.** 49 three-letter words are prefixes of other
    words (`act`/`action`, `add`/`address`, …).
  - Mnemonicode (Oren Tirosh, MIT): 1633 words, prefix-free, but 123 groups
    share their first four letters. Fails CODE-2.
  - Monero English (BSD-3-Clause): 1626 words. Usable, but smaller and less
    familiar.
  - EFF lists: CC-BY-3.0, not on the LIC-3 allowlist.
- **Decision:** BIP-39 English **with the 49 prefix words removed**, giving
  **1999 words**. The result has no duplicates, is prefix-free and has unique
  first four letters. A unit test checks all three properties on the embedded
  file.
- **Word count:** 8 words from 1999 give 87.7 bits, below the 88-bit floor, so
  the code has **9 words (98.7 bits)**. CODE-1 explicitly allows another
  size and count if entropy is at least 88 bits. This only increases entropy;
  it does not change the security model.
- The derivation (filtering the upstream list) is recorded in
  `THIRD_PARTY_LICENSES` with the MIT notice.

### 1.4 BLAKE3 (XFER-1)

- `lukechampine.com/blake3` v1.4.1 (2025-05-08), MIT, repository active (last
  push 2025-08), v1 API. Depends on `github.com/klauspost/cpuid/v2` (MIT) for
  SIMD dispatch. v1.4.0 is retracted upstream; v1.4.1 is current.
- `github.com/zeebo/blake3` v0.2.4 (2024-08), CC0, still pre-1.0.
- **Decision:** `lukechampine.com/blake3` (stable v1 API, permissive license,
  maintained). The standard library has no BLAKE3.

### 1.5 mDNS (DISC-5)

- `github.com/hashicorp/mdns` v1.0.7 (2026-06-11), **MIT** (the LICENSE file
  in the v1.0.7 zip is MIT, "Copyright IBM Corp. 2014, 2026"; older releases
  were MPL-2.0). Actively maintained (last push 2026-11). It has
  `QueryContext` and a `Logger` option, so its log output can be routed away
  from the terminal. Depends on `github.com/miekg/dns` (BSD-3-Clause,
  maintained, v1.1.73 on 2026-08) and `golang.org/x/net`.
- `github.com/grandcat/zeroconf` (last release 2020) and
  `github.com/libp2p/zeroconf/v2` (2022) are unmaintained.
  `github.com/brutella/dnssd` (2024) pulls in `vishvananda/netlink`.
- **Decision:** `hashicorp/mdns`, behind the `internal/discover` interface.

### 1.5b UDP unicast sweep (DISC-6 to DISC-9)

Searched on 2026-11-14 for an existing Go library that finds a peer by
unicast when multicast is blocked:

- `github.com/schollz/peerdiscovery` (written for croc), the most widely
  used Go LAN-discovery library, uses UDP multicast only, so it fails on
  the same networks as mDNS. `a1phat0ny/discover` is multicast too, and
  `solcates/broadcast` uses IPv4 broadcast, which the same networks
  usually drop as well.
- No maintained Go library implements a unicast subnet sweep. The pattern
  is established in applications: LocalSend falls back to sending its
  register request to every address of the local /24 when multicast does
  not work, and its third-party Go implementation does the same. Each
  implements it itself.
- **Decision:** implement it in `internal/discover` with the standard
  library only (`net`, `net/netip`), about 300 lines, behind the same
  `Advertiser` and `Browser` interfaces. No dependency is added.

### 1.6 License scanning (LIC-4)

- `github.com/google/go-licenses/v2` v2.0.1 (2025-09-08), Apache-2.0,
  repository active (last push 2026-07). It is a development tool run with
  `go run …@v2.0.1`, so it is not a dependency of the binary.
- `golangci-lint` is GPL-3.0. It is only a development tool, run as a separate
  binary, and is never linked into or distributed with Transporter, so LIC-3
  (which governs dependencies) does not apply.

### 1.7 GitHub Action SHAs (CI-4)

Resolved on 2026-11-10 with the GitHub REST API
(`/repos/{owner}/{repo}/releases/latest`, then `/commits/{tag}` with the
`application/vnd.github.sha` media type, which resolves annotated tags to the
commit). The `codeql-action` "latest release" is a CodeQL bundle, so its
version tag was taken from `/tags`.

| Action | Version | Commit SHA |
| --- | --- | --- |
| actions/checkout | v7.0.1 | 3d3c42e5aac5ba805825da76410c181273ba90b1 |
| actions/setup-go | v7.0.0 | b7ad1dad31e06c5925ef5d2fc7ad053ef454303e |
| actions/upload-artifact | v7.0.2 | cf430e030ddbb5b0abf93d22962f4752f3646cd9 |
| golangci/golangci-lint-action | v9.3.0 | ba0d7d2ec06a0ea1cb5fa41b2e4a3ab91d21278a |
| github/codeql-action | v4.39.3 | 33d7b85da1a04171e211befe2c739303b9a4c066 |
| actions/dependency-review-action | v5.0.0 | a1d282b36b6f3519aa1f3fc636f609c47dddb294 |
| goreleaser/goreleaser-action | v7.3.0 | a4f02ab5355a589de60d917a659ce617ed19b3de |
| actions/attest-build-provenance | v4.2.2 | 4d101475d8b20a2381f78447822ac1eab6504dd8 |
| DavidAnson/markdownlint-cli2-action | v25.0.0 | 696eb3f2509270d7b882d2aa68347bc676e7af34 |
| lycheeverse/lychee-action | v2.9.0 | e7477775783ea5526144ba13e8db5eec57747ce8 |

Tool versions: golangci-lint v2.15.0, govulncheck (`golang.org/x/vuln`)
v1.9.0, go-licenses v2.0.1, markdownlint-cli2 0.24.0, lychee 0.24.2,
GoReleaser `~> v2`.

Locally, `make docs-check` runs markdownlint-cli2 from the container image
`docker.io/davidanson/markdownlint-cli2:v0.24.0`, pinned by digest
`sha256:70ead7c0352d22d04bbe612cd96b54ec591538d8f4626cafe391bb2ecf3639ca`
(pulled on 2026-11-11), so contributors need Docker rather than Node. The
container gets the checkout read-only, no network, and SELinux labelling
disabled (relabelling with `:Z` would change the labels on the user's
files). CI keeps the markdownlint-cli2 action above, which runs the same
version.

### 1.8 MPL-2.0 text (LIC-1)

`LICENSE` was downloaded from <https://www.mozilla.org/media/MPL/2.0/index.txt>
(SHA-256 `3f3d9e0024b1921b067d6f7f88deb4a60cbe7a78e76c64e3f1d7fc3b779b9d04`)
and compared word for word with the SPDX copy (`spdx/license-list-data`,
`text/MPL-2.0.txt`). There were no differences.

## 2. Architecture and package layout

- **D-2.1 Layout** follows DEL-2. Additions:
  - `internal/fail`: error kinds, exit codes and their precedence (REL-4,
    CLI-7, CLI-9), shared by sender, receiver and CLI.
  - `internal/proto/link.go`: the shared heartbeat and deadline wrapper around
    a secure connection. Sender and receiver both need it, and it belongs next
    to the message codec.
  - `internal/meta`: the single project-name constant (NFR-7) and build
    version.
  - `tools/spdxcheck`: the SPDX header checker used by CI and `make`.
  - `tools/reqcheck`: checks that every MUST requirement has a row in the
    requirements-to-tests table and that the tests it names exist (TEST-1).
  - `internal/hashpipe`: overlaps hashing with I/O (D-7b.2).
- **D-2.2 Project name vs. protocol labels (NFR-7).** The project name exists
  once, as `meta.Name`. The protocol constants that happen to contain the word
  (`transporter/1` prologue, the HKDF `info` labels, the mDNS service type
  `_transporter._tcp`) are **wire constants** defined in the spec. They are
  kept as literal constants with golden tests, because renaming the project
  must not silently change the protocol.
- **D-2.3 Code type redaction.** `code.Code` keeps the canonical string in a
  closure (`func() string`), not in a string or pointer field. `fmt` can't
  call methods on unexported fields of an enclosing struct and falls back to
  reflection. That prints strings, and (found by the redaction test) even
  dereferences pointers under `%s` through its bad-verb path. A func value is
  only ever printed as an address. Tests cover nested, pointer, slice, JSON,
  gob and slog cases.
- **D-2.4 Owner filled in (NFR-7, maintainer decision, 2026-11-11).** The
  maintainer asked for the `OWNER` placeholder to be replaced with their
  GitHub account, `nedmchugh` (matching the `origin` remote). The module
  path is now `github.com/nedmchugh/transporter`, and `CODEOWNERS`, the
  workflows and the docs use it too. Renaming is still one `sed` over
  `github.com/nedmchugh/`. `docs/requirements.md` keeps `OWNER` because it
  is the unchanged source specification.

## 3. Pairing code

- **D-3.1** Code: 9 words from 1999 (see D-1.3). `Parse` splits on runs of
  `-`, space, `_`, `.` and `,` (and other Unicode whitespace) and lowercases
  ASCII. A word of 4 or more letters that is a prefix of exactly one list word
  expands to that word. Because the list is prefix-free with unique 4-letter
  prefixes, a prefix of 4 or more letters can never be ambiguous. Three-letter
  words must be typed in full.
- **D-3.2** Suggestions use Levenshtein distance, offered only when the
  distance is at most 2, so random input is not "corrected".
- **D-3.3** HKDF salt: the spec does not name one, so the salt is empty (HKDF
  then uses a block of zeros, per RFC 5869). The input is high-entropy, so a
  salt adds nothing. Golden vectors were generated with Python's `hmac`
  module, an implementation independent of Go's `crypto/hkdf`.
- **D-3.4 CLI-6 and typos.** When the first positional argument looks like a
  code (several separator-joined words, most of them in the list) but does not
  parse, the sender must not print it as a "missing path", because it is
  almost the secret. It prints the parse error instead, which names only the
  single bad word (CODE-4).

## 4. Security and channel

- **D-4.1 Handshake rejection signal.** With NNpsk0, a receiver holding a
  different code fails to decrypt message 1 and closes the connection
  (SEC-4). So the sender sees a clean EOF where message 2 should be. The
  sender treats **a clean EOF at a frame boundary after sending message 1** as
  an authentication failure (fatal, exit 3, REL-5). Timeouts, resets and
  partial frames during the handshake are transient and retried. Residual
  ambiguity: a receiver killed at exactly that moment is reported as an
  authentication failure. This is documented in `security.md`.
- **D-4.2 Unauthenticated-connection limit (RCV-8).** The receiver takes a
  semaphore slot *before* `Accept`, so excess connections wait in the kernel
  backlog instead of being closed. Closing them would look like an
  authentication rejection to the sender (D-4.1).
- **D-4.3 Frame authentication failures (SEC-7).** Any frame that fails AEAD
  authentication terminates the connection immediately. At the session level
  this counts as a transient network error: the sender reconnects with a fresh
  handshake. An on-path attacker can always force disconnects anyway, and
  corruption must not be mistaken for a wrong code.
- **D-4.4 Handshake message size.** Handshake frames are limited to 256 bytes
  (actual NNpsk0 messages are 48 bytes, with empty payloads), stricter than
  the transport frame limit.
- **D-4.5 Nonces (SEC-6).** There is no custom nonce handling. At most 2^64-2
  frames per direction per connection; at 48 KiB per frame that is about
  10^24 bytes, far beyond any transfer. On `ErrMaxNonce` the connection
  closes, and a reconnect performs a fresh handshake. No rekeying is
  implemented.
- **D-4.6 Symlinks inside the destination (SEC-11).** `os.Root` blocks
  escapes, but it still follows symlinks that stay inside the root. To meet
  "never follows symlinks within the destination", the receiver `Lstat`s every
  directory entry it creates or reuses, plus each final and `.part` name. Any
  symlink makes that entry a per-file error. Residual TOCTOU risk (a local
  process swapping in a symlink between the check and the use) is still
  confined by `os.Root`. This is documented.

- **D-4.7 os.Root coverage (SEC-9).** Every destination operation goes
  through `*os.Root`, with two exceptions. `os.MkdirAll(DEST)` creates the
  root itself, which cannot be opened before it exists. The free-space query
  (`statfs` / `GetDiskFreeSpaceEx`) only reads filesystem totals. The test
  `TestOnlyRootFilesystemAccess` scans the package source, so any new
  path-based `os` call fails CI.
- **D-4.8 Writability probe.** At startup the receiver creates and deletes
  a uniquely named empty file
  (`.transporter-write-test-<random>`) in DEST, so an unwritable destination
  fails with exit 5 before the user starts the sender. The file is created
  and removed in the same run, which is consistent with RES-1 and RES-4.

## 5. Protocol

- **D-5.1** One application message per frame. The message type is the first
  plaintext byte. Big-endian integers. The full layout is in `protocol.md`.
- **D-5.2** `ChunkSize` is 32 KiB (a power of two under the 48 KiB frame
  limit). Resume offsets round down to a multiple of it (RES-3).
- **D-5.3 NEED stream.** The receiver sends exactly one NEED record per
  manifest entry, in increasing index order, streamed in batches. The sender
  can start sending files before the last NEED arrives.
- **D-5.4 `--verify` (RES-2).** For an existing final file of equal size, the
  receiver sends its BLAKE3 hash in the NEED record (`VERIFY_OR_SEND` or
  `VERIFY_OR_CONFLICT`). The sender compares it with its own hash and replies
  with `VERIFY_RESULT` (same) or, if different, either sends the file or
  reports the difference. Each side reads each file only once for the
  comparison.
- **D-5.5 Exit code for protocol and version errors.** The CLI-7 table has no
  row for protocol violations, version mismatch, or a rejected (hostile)
  manifest. They use **exit code 1** ("internal or protocol error").
- **D-5.6 Exit-code precedence.** CLI-9 orders 3, 5, 6, 4, 7, 0. Codes outside
  that list rank as: 2 (usage) happens before any transfer; 130 (interrupted)
  wins over everything except 1; 1 (internal or protocol) ranks first.
- **D-5.7 Ordering of finalization (XFER-3).** The receiver applies mode
  (`File.Chmod` on the open descriptor) and mtime (`Root.Chtimes` on the
  `.part` name) **before** the rename. A crash after the rename then never
  leaves a complete file with a fresh mtime, which would later read as a
  conflict.
- **D-5.8 Directory permissions.** TREE-7 covers file permission bits.
  Directories are created as `0755` (subject to umask), and their mode is not
  copied, so a read-only source directory cannot make the receiver unable to
  write its contents. Documented with TREE-8.
- **D-5.9 File permissions** are applied as `mode & 0777` exactly, like
  `rsync -p` or `scp -p`. The receiver's umask is not applied.
- **D-5.10 Manifest structure.** Every entry's parent must be the root or an
  earlier directory entry. The sender's walk always meets this. It lets the
  receiver detect file-vs-directory clashes inside a manifest cheaply.
- **D-5.11 `.part` name clashes.** If the manifest contains both `F` and
  `F.part` (or names that fold to them), `F` gets a per-file error instead of
  using a temporary name that is itself a destination file.
- **D-5.12 Mismatched `.part` (XFER-4 vs RES-4).** A `.part` file for a path
  *in the current manifest* belongs to the transfer: it is reused for resume
  and deleted on a hash mismatch, as XFER-4 requires. RES-4's "never delete"
  rule applies to `.part` files for paths not in the manifest, and to all
  other files.
- **D-5.13 Supersession and BUSY (RCV-5).** A session is *active* while it has
  an open connection. A same-`session_id` connection replaces the old
  connection after it has fully stopped. A different `session_id` gets BUSY
  only while the active connection is still open. After the old connection is
  gone, a new session (for example a re-run sender, TEST-8 scenario 3) is
  accepted. This lets a killed-and-restarted sender resume without waiting for
  the idle timeout.
- **D-5.14 Retry budget (REL-1).** The budget counts time since the first
  failure in the current run of consecutive failures. Forward progress resets
  both the backoff and the budget, so a long transfer on a flaky link isn't
  killed after 10 minutes of overall runtime. Forward progress means
  receiving an ACK, completing, or sending at least 1 MiB of file data on the
  connection. The last case covers a single huge file whose connections keep
  dropping before its FILE_END.
- **D-5.15 Completion handshake (PROTO-7).** After the sender receives the
  final DONE, it closes the connection. The receiver waits up to 5 s for that
  close before exiting. If the DONE reply itself is lost, the sender retries
  against a receiver that has exited and eventually fails with exit 4. This is
  documented as a known limitation.
- **D-5.16 Windows-invalid names (TREE-10)** are checked only on Windows
  receivers (per the spec), as per-entry errors. The checker is tested on all
  platforms.
- **D-5.17 Case and normalization collisions (TREE-9)** make the whole
  manifest invalid, as the spec says, even on case-sensitive filesystems. The
  sender runs the same check before connecting, to fail early with a clear
  message.
- **D-5.18 Closing after a fatal ERROR (found on the Windows CI runner).**
  When one side rejects the other (for example a manifest entry with
  `..`), the peer's later frames are usually still unread. Closing a TCP
  socket with unread data makes the OS send a reset, and on Windows a reset
  makes the peer discard data it has received but not read, so the sender
  never saw the receiver's ERROR (it reported a network error instead).
  `Link.Abort` therefore closes gracefully once the ERROR is written: it
  shuts down the write side, discards incoming data until the peer closes
  or the abort timeout (1 s) passes, then closes. That adds at most 1 s to
  an abort, bounded even against a peer that never closes. The bound is a
  timer that closes the socket, not only the read deadline: when the abort
  comes from a helper goroutine (the free-space check, TestNoSpace), the
  main loop may be blocked reading the same socket, holding its read lock
  and moving the deadline on every heartbeat, so the drain could wait
  forever. `Link.Recv` also stops reading once the link is closing.

## 5b. Discovery

- **D-5b.1 mDNS records.** Service `_transporter._tcp.local.`, a random
  instance name (`transfer-<8 hex>`), an SRV target with the same random
  label (`transfer-<8 hex>.local.`, not the machine's host name, to avoid
  revealing it and to avoid clashing with the system's own mDNS responder),
  the port, an A or AAAA record for the address, and TXT
  `tag=<8 hex>` and `v=1`. A receiver with several addresses advertises one
  such instance per address (D-5b.8). The sender queries once per second
  until the 5 s timeout and takes an answer with its tag (DISC-2),
  preferring an address on one of its own subnets.
- **D-5b.2 Discovery failure is final.** A failed discovery exits 4 with a
  hint to use `--to` (DISC-3) and is not retried. Once a receiver has been
  found, reconnects reuse its address without discovering again, so a lost
  multicast packet cannot end a transfer that is already running. A receiver
  that changes IP address mid-transfer needs a rerun (documented).
- **D-5b.3 Spoofed answers.** Anyone on the LAN can answer mDNS queries. A
  spoofed answer can only make the sender connect to a peer that cannot
  complete the handshake (reported as an authentication failure). That peer
  receives handshake message 1, which allows an offline guessing attack
  against at least 88 bits of code entropy. See `security.md`.
- **D-5b.4 Verification limits.** Until 2026-11-11, firewalld on the
  development machine blocked inbound UDP 5353, so the live multicast tests
  skipped as DISC-5 allows. Record construction and answer matching are
  unit-tested without the network. Since mDNS was allowed through the
  firewall, the live tests (`TestAdvertiseAndFind`, `TestE2EDiscovery`)
  run and pass there, repeatedly under `-race`. CI runners may still skip
  them.
- **D-5b.5 Reading library answers (found by the live tests).**
  hashicorp/mdns v1.0.7 sends each answer as a `*ServiceEntry` and keeps
  writing to that struct when later packets for the same service arrive.
  `Find` originally matched answers on a separate goroutine while the query
  ran, which is a data race. It now reads answers only after each
  `QueryContext` call returns, on the same goroutine, so the library has
  finished with them. The channel holds 256 answers, because the library
  drops answers when it is full. The cost is that an answer is acted on at
  the end of its one-second query window rather than immediately.
- **D-5b.6 Address-family fallback (found on the macOS CI runner).** The
  library sends each query on IPv4 and then IPv6, and fails the whole query,
  before listening for answers, if either send fails. On a host without an
  IPv6 multicast route (the GitHub macOS runner, and some Macs) discovery
  therefore failed within milliseconds even where IPv4 mDNS works, and the
  "within 5s" message was wrong. `Find` now retries a failed query on IPv4
  alone, then IPv6 alone, and uses the first family that works from then
  on. If none works, it pauses 250 ms between rounds and keeps trying until
  the timeout (DISC-3), then reports the last error. The library call is a
  package variable so unit tests can simulate per-family send failures.
- **D-5b.7 UDP unicast sweep (maintainer request, 2026-11-14).** A
  fallback for networks that drop multicast but pass unicast (switches
  with IGMP snooping and no querier, some corporate and guest Wi-Fi).
  - *Port*: UDP 29873. The IANA registry (updated 2026-11-10) lists it as
    unassigned. It is below the ephemeral ranges of Linux (32768 to
    60999), macOS and Windows (49152 and up), so an outgoing connection
    cannot be holding it. The sender cannot learn the receiver's TCP port,
    which is random by default, so the sweep needs a fixed port.
    `--sweep-port` changes it, for a port a firewall already allows, and
    lets the e2e tests use a free port (TEST-8). A second receiver on one
    machine cannot bind the port; it warns and is reachable by mDNS or
    `--to`.
  - *Order*: the sweep runs only after mDNS has found nothing (5 s), for
    3 s, so a network where mDNS works never sees sweep traffic, and the
    worst case before the DISC-3 message is 8 s. Running both at once
    would be faster on blocked networks but would scan every network on
    every run.
  - *Targets*: 127.0.0.1, then each IPv4 subnet of an up, running,
    non-loopback interface. Running excludes bridges with no carrier,
    such as an unused `docker0`. A subnet larger than /22 is cut to the
    /22 around the sender's own address (a /16 would be 65,534 probes),
    and at most 4,096 addresses are probed. IPv6 subnets (/64) cannot be
    swept, and mDNS covers IPv6.
  - *Pacing*: batches of 64 probes 20 ms apart (a /22 takes about 0.3 s),
    and a new round every second, which covers lost packets and a
    receiver that starts late.
  - *Wire format and checks* (protocol.md section 9): the probe carries
    the discovery tag, which mDNS already makes public, and a random
    nonce. The receiver answers only its own tag, so a port scan without
    the tag gets no response. The reply echoes the nonce, so a host that
    has not seen the probe cannot answer it, and is 2 bytes shorter than
    the probe, so it cannot amplify. The reply carries the TCP port; the
    sender connects to the reply's source address, as for mDNS (D-5b.3).
  - *Flags*: `--no-sweep` and `--sweep-port` on both commands and in the
    config file. `--no-mdns` alone no longer requires `--to`, because the
    sweep is still on; `--no-mdns --no-sweep` does.
  - *Verification*: unit tests sweep only 127.0.0.1 on a free port. The
    e2e tests run real binaries over loopback; the sender's sweep also
    probes the real local subnets, which no host answers. A sweep between
    two machines is not tested automatically, and the development
    machine's firewalld blocks inbound UDP 29873 unless it is opened.
- **D-5b.8 Every interface (found in runtime testing, 2026-11-20).**
  Senders and receivers on a machine with more than one network did not
  find each other. Three causes:
  - *mDNS used one interface.* hashicorp/mdns v1.0.7 joins the multicast
    group, and sends queries, only on the interface it is given, and with
    none (as before) the system picks one, normally the one with the
    default route. A receiver never saw queries arriving on its other
    networks, and a sender never asked on its other networks. The
    receiver now runs one responder per interface that is up, running,
    multicast capable, not loopback and has an address; one that fails
    only disables that interface, and if all fail one is tried on the
    system default. The sender queries on each such interface at once in
    every round, each with its own address-family fallback (D-5b.6), so
    the timeouts are unchanged. Responders reply by unicast to the query's
    source, so replies need no interface choice. On Linux every responder
    socket receives every query (`IP_MULTICAST_ALL`), so a receiver with N
    interfaces answers each query N times; the sender ignores duplicates.
  - *The sender got an arbitrary address.* The library keeps one address
    per host name from an answer, the last A record, so a receiver
    advertising all its addresses under one name could hand the sender a
    container or VPN address it cannot reach. Each address is now its own
    service instance with its own random instance and host name, so the
    sender sees all of them and picks, in order, an address on one of its
    own subnets, then any IPv4 address, then IPv6. The records reveal no
    more than before (random names, the addresses were already in A and
    AAAA records). A receiver from before this change still works; the
    sender gets one address from it, as before.
  - *Unreachable addresses were advertised.* The receiver advertised the
    addresses of interfaces that are up but have no carrier, such as an
    unused `docker0`. It now skips them, as the sweep already did.
  - *The sweep cap was first come, first served.* Targets were taken
    subnet by subnet, so a few large container or VPN subnets listed
    before the LAN could use up the 4,096-address cap before the LAN was
    reached. The subnets now take turns, one address each, so each gets
    an even share of the cap.
  - *Verification*: unit tests fake the interfaces and the library calls
    (several interfaces, one failing, the per-interface fallback, answer
    ranking, the records, the shared cap). The live tests
    (`TestAdvertiseAndFind`, `TestE2EDiscovery`) pass on the single-NIC
    development machine. Discovery between two machines across a second
    interface is not tested automatically.

## 6. Dependencies (NFR-5)

| Module | License | Why the standard library is not enough |
| --- | --- | --- |
| github.com/flynn/noise | BSD-3-Clause | Required by SEC-1 (Noise NNpsk0). |
| golang.org/x/crypto | BSD-3-Clause | Required by noise (ChaCha20-Poly1305, BLAKE2s, Curve25519). |
| lukechampine.com/blake3 | MIT | BLAKE3 required by XFER-1; not in stdlib. |
| github.com/klauspost/cpuid/v2 | MIT | Required by blake3 for SIMD detection. |
| github.com/hashicorp/mdns | MIT | mDNS/DNS-SD (DISC-1); not in stdlib. |
| github.com/miekg/dns | BSD-3-Clause | Required by hashicorp/mdns; also imported directly for its `Zone` interface (D-5b.8). |
| golang.org/x/net | BSD-3-Clause | Required by mdns (multicast sockets). |
| golang.org/x/text | BSD-3-Clause | NFC normalization and case folding (TREE-9). |
| golang.org/x/term | BSD-3-Clause | No-echo code prompt and terminal detection (CODE-8, CLI-2). |
| golang.org/x/sys | BSD-3-Clause | Required by x/term; also free-space query (RCV-9). |
| github.com/spf13/cobra | Apache-2.0 | Command-line parsing, at the maintainer's request (D-9.9). Widely used (Docker, Kubernetes, Hugo, GitHub CLI). |
| github.com/spf13/pflag | BSD-3-Clause | Flag parsing used by cobra; also used directly to define the flags. |
| github.com/inconshreveable/mousetrap | Apache-2.0 | Required by cobra (on Windows, detects a double-click start from Explorer). |
| go.yaml.in/yaml/v3 | MIT (with an Apache-2.0 NOTICE, copied into THIRD_PARTY_LICENSES) | Parses the YAML config file (D-9.9); no dependencies of its own. Maintained by the YAML organization (github.com/yaml/go-yaml); v3.0.6, 2026-10-13. |

The UDP sweep (D-5b.7) adds no dependency.

Verified with `go-licenses report ./cmd/transporter` (phase 7). The binary's
dependency closure is noise (BSD-3-Clause), hashicorp/mdns (MIT),
klauspost/cpuid/v2 (MIT), miekg/dns (BSD-3-Clause), x/crypto, x/net, x/sys,
x/term and x/text (BSD-3-Clause), and blake3 (MIT). All are on the LIC-3
allowlist. Cobra v1.10.2 (with pflag v1.0.10) and yaml/v3 v3.0.6 were the
latest releases on proxy.golang.org on 2026-11-12; `go-licenses check`
confirms they are on the allowlist. `gopkg.in/check.v1` and `kr/pretty`
appear in `go.mod` only as yaml/v3's test requirements and are not
compiled into the binary. `golang.org/x/sync` appears in `go.mod` only as a requirement of
miekg/dns and is not compiled into the binary.

The goroutine leak check (TEST-6) is a small in-repo helper
(`internal/testutil/leak.go`), not `go.uber.org/goleak`. That avoids a test
dependency (and its `testify` dependency tree) for about 60 lines of code.

## 7. Testing

- **D-7.1 Coverage.** The target is 85% statement coverage on `internal/...`
  (excluding `internal/testutil`, which is test support), measured with
  `-coverpkg` so integration tests count for the packages they exercise. It
  is enforced by `make cover` (`COVER_MIN`). As the requirements allow, the
  threshold ratchets up by phase: 70% at phase 3 (resume, verify and fault
  paths not yet tested), 78% at phase 4, 82% at phase 5, and the full 85% from phase 6
  onward.

## 7b. Performance (NFR-3)

- **D-7b.1 Measurements** (4-vCPU VM, NVMe-class disk that writes at
  1.7 GB/s with fsync). `BenchmarkTransfer` (one 256 MiB file, in-process
  over loopback, no race detector) reaches about **200 MB/s**. The CLI moved
  1 GiB over loopback in about 9 s (about 115 MB/s, before the
  optimizations below) with a sender peak RSS of 18 MB, independent of file
  size (SND-4, NFR-4).
- **D-7b.2 Optimizations made.** Frame reads go through a 64 KiB
  `bufio.Reader`, so one syscall serves many frames. The fixed frame buffer
  and the length check before reading the body are unchanged. BLAKE3
  hashing of each chunk runs on a helper goroutine (`internal/hashpipe`)
  while the chunk is encrypted and sent (sender) or written to disk
  (receiver). Hash order and results are identical to sequential hashing.
  Together these took throughput from 148 to about 200 MB/s.
- **D-7b.3 Deviation from the SHOULD.** About 200 MB/s exceeds gigabit
  Ethernet (about 117 MB/s of payload), so on a gigabit LAN the network is
  the limit, as NFR-3 asks. On loopback or 10 GbE the implementation is the
  limit: one connection processes chunks in order, and per-chunk BLAKE3,
  ChaCha20-Poly1305 and syscalls add up. Going further would mean several
  files in parallel over several connections, or batching frames into
  larger writes. That would change the protocol or the pipeline and was not
  worth the risk for v1. Recorded here per DOC-8.

## 8. Test seams

- **D-8.1** `internal/send` has one unexported, test-only hook,
  `testCorruptChunk`. It corrupts chunk data *after* it is hashed, to drive
  the XFER-4 mismatch paths. Data inside the authenticated channel cannot be
  corrupted any other way. It is nil in production builds.
- **D-8.2** A second hook, `testObserveInflight`, reports the in-flight file
  and byte counts, so tests can show that pipelining happens and stays
  within its bounds (XFER-6).

## 9. Documentation and repository

- **D-9.1 Markdown lint scope.** `docs/requirements.md` (the source
  specification, kept unchanged) and `CODE_OF_CONDUCT.md` (the Contributor
  Covenant 2.1, reproduced verbatim from contributor-covenant.org) are
  excluded from markdownlint. MD013 (line length) is off because tables and
  URLs need long lines. MD041 is off because GitHub issue and pull request
  templates do not start with a title.
- **D-9.2 Contact placeholders.** `SECURITY.md` and `CODE_OF_CONDUCT.md`
  contain `MAINTAINER-CONTACT`, a placeholder for the maintainer's contact
  address.
- **D-9.3 Interrupted runs (REL-7).** Both summaries list "not transferred
  yet" files (capped at 20 lines), in addition to the counts, so an
  interrupted run says what remains.
- **D-9.4 Project name in messages (NFR-7).** User-facing strings that
  mention the tool (`TRANSPORTER_CODE`, the write-probe file name, version
  hints) are derived from `meta.Name`. Wire constants stay literal
  (D-2.2).

- **D-9.5 CodeQL and dependency review on a private repository
  (maintainer decision, 2026-11-12).** Both need GitHub Advanced Security
  on a private repository, and the CodeQL job failed there. The workflows
  stay (CI-2), but their jobs run only when the repository is public or
  the repository variable `ENABLE_CODE_SCANNING` is `true`; otherwise they
  are skipped. The LIC-3 license allowlist is still enforced for every
  change by `make license-check` in `ci.yml`, and vulnerabilities by
  `govulncheck`, so a private repository loses CodeQL's static analysis
  and the per-PR dependency diff, not the license or vulnerability gates.
- **D-9.6 Copyright holder (maintainer decision, 2026-11-12).** The
  copyright holder is Ned McHugh, stated once in the README's License
  section ("Copyright © 2026 Ned McHugh"; 2026 is the year of the first
  commit). `LICENSE` stays the verbatim MPL-2.0 text (LIC-1). At the
  maintainer's request, every `.go` file (and the one shell script) also
  carries `Copyright 2026 Ned McHugh`, as permitted by MPL-2.0 Exhibit A.
  The line comes directly after the LIC-2 block, so files still begin with
  exactly that block; `tools/spdxcheck` requires both. It uses a fixed year
  (first publication) and plain ASCII, so the check stays an exact match.
- **D-9.7 Docker build (maintainer request, 2026-11-12).**
  `scripts/docker-build.sh` (also `make docker-build`) builds every CROSS
  platform inside Docker and copies the binaries, `SHA256SUMS`, `LICENSE`
  and `THIRD_PARTY_LICENSES` to `dist/docker/`, so a developer needs only a
  Docker engine. Choices:
  - The Go image `golang:1.27.4-bookworm` matches `go.mod`'s toolchain
    line and is pinned by digest
    `sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea`
    (pulled 2026-11-12). Dependabot proposes updates. `GOTOOLCHAIN=local`
    keeps the go command from fetching another toolchain.
  - The builder runs on the host's architecture (`--platform=$BUILDPLATFORM`)
    and cross-compiles with `CGO_ENABLED=0`, so no emulation is needed.
  - `go mod verify` checks the module downloads against `go.sum`.
  - The final stage is an empty image holding only `/out`. The script
    creates a container from it without starting it and copies the files
    out with `docker cp`, which works with any engine, without `buildx`
    output options.
  - `.git` is not sent into the build; the version (`git describe` on the
    host, else `dev`) is passed as a build argument. Builds use
    `-trimpath -buildvcs=false`.
  - The script checks that the engine is installed and reachable (`docker
    info`) and exits 1 with a hint otherwise. `DOCKER` selects another CLI
    with the same commands.
  - This is a developer convenience. Releases still come from GoReleaser
    in `release.yml`. A `docker-build` CI job keeps it working.
- **D-9.8 NOTICE and warranty note (maintainer decision, 2026-11-12).** A
  `NOTICE` file gives the project's attribution (name and copyright
  holder) and ships in every release archive, and the README's License
  section states that the software is provided "as is", pointing to MPL-2.0
  sections 6 and 7. Both only restate what the license already provides:
  MPL-2.0 has its own warranty disclaimer and liability limit (sections 6
  and 7) and protects copyright notices in source files (section 3.4).
  `LICENSE` is unchanged (LIC-1). The Docker build (D-9.7) copies it to
  `dist/docker/` too. Unlike Apache-2.0, MPL-2.0 does not
  require recipients to keep a `NOTICE` file, so it is informational, and
  says so.
- **D-9.9 Cobra, and a YAML config file of defaults (maintainer request,
  2026-11-12).** The maintainer asked for command-line parsing with cobra
  and a config file for user-set defaults. This departs from NG-5 (no
  configuration files) and from the CLI-1 recommendation to use the
  standard `flag` package; the request is the justification CLI-1 asks
  for.
  - *Viper was tried and dropped.* It worked, but added 12 modules to the
    binary (file watching, `.env`, TOML, a virtual filesystem, none of
    them used) for what is a small file of defaults. The maintainer chose
    a single YAML parser instead. Cobra stays: it is the common choice for
    Go command-line tools.
  - *Cost (NFR-5)*: 4 modules in the binary (cobra, pflag, mousetrap on
    Windows, yaml/v3): 13 in all, up from 10. The stripped Linux binary
    grows from 6.3 MB to 7.1 MB.
  - *Binary size trap*: cobra's version and usage output goes through
    `text/template` whenever a template is customized, which makes
    `reflect.Value.MethodByName` reachable and disables most dead-code
    elimination in the linker (with viper and a version template the
    binary was 10.8 MB; without viper but with the template, 9.8 MB). So
    `--version` is handled by the program, cobra's `Version` field is left
    unset, help is printed by a custom help function, and no template is
    set. `TestBinaryKeepsDeadcodeElimination` (e2e) fails if
    `MethodByName` appears in the binary again.
  - *Precedence*: command line, then config file, then built-in default.
    Each value from the file is applied through the flag's own parser and
    the same range checks, so the file accepts exactly what the command
    line accepts.
  - *Parsing*: the file is decoded into YAML's node tree, not Go values, so
    each value keeps its exact text (no YAML type conversion before the
    flag parser) and its line number for errors. Only `.yaml`/`.yml`
    files are read, at most 64 KiB. Lists, maps, aliases and null values
    are errors, as are duplicate keys and repeated sections (decoding to a
    node tree does not reject those on its own). `FuzzParseConfig` covers
    the parser.
  - *Location*: `transporter/config.yaml` in the user's config directory
    (`os.UserConfigDir`: `~/.config` on Linux, `~/Library/Application
    Support` on macOS, `%AppData%` on Windows), or the file named by
    `--config`. A missing default file is normal; a missing `--config`
    file is an error.
  - *Keys*: the flag names, under `send:` or `receive:` (plus top-level
    `verbose`), case-sensitive. Unknown keys are errors, so a typo is not
    silently ignored. The code and `code-file` cannot be set: CODE-8 fixes
    the code's sources, and a code in a file of defaults would be a
    long-lived secret on disk. The error never echoes the value.
  - *Permissions*: on Unix a config file writable by group or others is
    refused, as ssh does, because defaults such as `overwrite` or `to`
    change what a transfer does.
  - *No environment variables* are added; `TRANSPORTER_CODE` is unchanged.
  - *Help*: the help texts stay hand-written, so every flag still states
    its default in words (CLI-5); pflag's generated usage omits defaults
    for zero values. Help and `--version` work even when the config file
    is broken.
  - *Tests*: the e2e suite points the user config directory at an empty
    directory, so a developer's own config file cannot change results.

## 10. Maintainer open items

These are for the maintainer to decide or do; the implementer did not
decide them (requirements section 17).

1. Fill in the `MAINTAINER-CONTACT` placeholder (`SECURITY.md`,
   `CODE_OF_CONDUCT.md`). Done: the `OWNER` placeholder is now `nedmchugh`
   (module path, `CODEOWNERS`, workflows, docs), and the copyright holder
   is Ned McHugh, in the README's License section and every file header
   (D-9.6).
2. Review export-compliance obligations before distributing (LIC-8).
3. Apply branch protection and repository settings
   (`docs/branch-protection.md`, CI-8), and enable private vulnerability
   reporting.
4. Dependency licenses: all dependencies are on the LIC-3 allowlist, so
   nothing is outside it. Decide whether MPL-2.0 remains appropriate.
5. Actions pinned by tag: none. Every action is pinned to a commit SHA
   verified through the GitHub API on 2026-11-10 (section 1.7).
6. Confirm the name "transporter" is acceptable for the intended
   distribution channels; other small projects use the same name.
7. Consider an independent cryptographic and security review before wide
   distribution (SEC-16).
8. Done: the minimum Go version was raised to 1.26 at the maintainer's
   request (D-1.3).
