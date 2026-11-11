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
- `go.mod` uses `go 1.25.0` and `toolchain go1.27.4` (the latest stable
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
  `x/term v0.45.0`, `x/sys v0.47.0`, `x/net v0.58.0`. Dependabot updates that
  raise the `go` line fail the Go 1.25 CI job; this is intended.

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
|---|---|---|
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

### 1.8 MPL-2.0 text (LIC-1)

`LICENSE` was downloaded from <https://www.mozilla.org/media/MPL/2.0/index.txt>
(SHA-256 `3f3d9e0024b1921b067d6f7f88deb4a60cbe7a78e76c64e3f1d7fc3b779b9d04`)
and compared word for word with the SPDX copy (`spdx/license-list-data`,
`text/MPL-2.0.txt`). There were no differences.

## 2. Architecture and package layout

- **D-2.1 Layout** follows DEL-2. Additions:
  - `internal/proto/link.go`: the shared heartbeat and deadline wrapper around
    a secure connection. Sender and receiver both need it, and it belongs next
    to the message codec.
  - `internal/meta`: the single project-name constant (NFR-7) and build
    version.
  - `tools/spdxcheck`: the SPDX header checker used by CI and `make`.
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
  failure in the current run of consecutive failures. Forward progress
  (receiving an ACK, or completing) resets both the backoff and the budget, so
  a long transfer on a flaky link isn't killed after 10 minutes of overall
  runtime.
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

## 6. Dependencies (NFR-5)

| Module | License | Why the standard library is not enough |
|---|---|---|
| github.com/flynn/noise | BSD-3-Clause | Required by SEC-1 (Noise NNpsk0). |
| golang.org/x/crypto | BSD-3-Clause | Required by noise (ChaCha20-Poly1305, BLAKE2s, Curve25519). |
| lukechampine.com/blake3 | MIT | BLAKE3 required by XFER-1; not in stdlib. |
| github.com/klauspost/cpuid/v2 | MIT | Required by blake3 for SIMD detection. |
| github.com/hashicorp/mdns | MIT | mDNS/DNS-SD (DISC-1); not in stdlib. |
| github.com/miekg/dns | BSD-3-Clause | Required by hashicorp/mdns. |
| golang.org/x/net | BSD-3-Clause | Required by mdns (multicast sockets). |
| golang.org/x/text | BSD-3-Clause | NFC normalization and case folding (TREE-9). |
| golang.org/x/term | BSD-3-Clause | No-echo code prompt and terminal detection (CODE-8, CLI-2). |
| golang.org/x/sys | BSD-3-Clause | Required by x/term; also free-space query (RCV-9). |

The goroutine leak check (TEST-6) is a small in-repo helper
(`internal/testutil/leak.go`), not `go.uber.org/goleak`. That avoids a test
dependency (and its `testify` dependency tree) for about 60 lines of code.

## 7. Testing

- **D-7.1 Coverage.** The target is 85% statement coverage on `internal/...`
  (excluding `internal/testutil`, which is test support). It is enforced by
  `make cover`. See `testing.md`.
