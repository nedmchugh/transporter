# Transporter: Requirements

**Status:** Draft 1.0
**Implementation language:** Go
**License:** MPL-2.0

## 0. How to read this document

- The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and **MAY** are used as in RFC 2119. A MUST is mandatory. A SHOULD may be skipped only with a recorded reason (see DOC-8).
- Every requirement has a stable ID (for example `SEC-4`). Tests SHOULD reference the IDs they cover, in test names or comments, so coverage of requirements can be traced (TEST-1).
- Where a requirement says "constant" or "default", the value is a named constant in code, documented, and (where marked) overridable by a flag.
- Where this document leaves a design choice open, the implementer decides, records the choice and rationale in `docs/DECISIONS.md`, and continues. Stop and ask only if a choice would change the security model or contradict a requirement.
- Section 12 lists decisions already made, so they are not re-litigated. The end of Section 17 lists items the maintainer must handle.

---

## 1. Overview

### 1.1 Purpose

Transporter is a command-line tool that copies a file or directory tree from one machine to another with **no setup**: no certificates, key files, daemons, accounts, or saved state. The user starts a receiver, which prints a one-time code. The user then starts a sender and gives it the code. The transfer is encrypted, integrity-checked, and resumes automatically after network failures.

```
receiver$  transporter receive ./dest
           Listening on 192.168.1.20:4000
           Code: orbit-lantern-vivid-copper-saddle-meadow-quartz-ember

sender$    transporter send orbit-lantern-vivid-copper-saddle-meadow-quartz-ember ./project
```

Existing tools fall short for this use: `scp` and `sftp` handle directory trees poorly, `rsync` requires the user to know which flags to use, and none of them retry with backoff by default.

### 1.2 Non-goals (MUST NOT be built)

- NG-1: PAKE or OPAQUE protocols, certificates, CAs, long-term identity keys, or any key storage. (An extension point is required; see SEC-14.)
- NG-2: Relay servers, NAT traversal, internet-wide discovery, or a reverse mode where the sender listens.
- NG-3: Bidirectional sync, deletion mirroring, or delta (block-level) transfer.
- NG-4: Compression.
- NG-5: Configuration files, daemons, services, or any state outside the destination directory.
- NG-6: Transfer of symlinks, device files, FIFOs, or sockets (see TREE-6).

### 1.3 Terms

- **Sender**: the process running `transporter send`. It acts as the connection initiator.
- **Receiver**: the process running `transporter receive`. It listens, writes files into the destination directory, and acts as the connection responder.
- **Code**: the human-readable one-time secret shared out of band by the user.
- **Session**: one transfer attempt sequence identified by a random `session_id`, possibly spanning several connections.
- **Manifest**: the list of entries (files and directories) the sender intends to transfer.

---

## 2. Pairing code

- CODE-1 (MUST): The receiver generates a code of **8 words** chosen uniformly at random using `crypto/rand` from an embedded list of **2048 words** (88 bits of entropy). The implementation MAY choose a different list size and word count only if the entropy is at least 88 bits, the list has the properties in CODE-2, and the choice is recorded in `docs/DECISIONS.md`.
- CODE-2 (MUST): The wordlist has a permissive license that is on the allowlist in LIC-3, contains no duplicates, contains no word that is a prefix of another word, and has unique first four letters per word. The license and attribution MUST be recorded in `THIRD_PARTY_LICENSES`. The implementer MUST verify the license of the chosen list from its source rather than assuming it.
- CODE-3 (MUST): Code parsing is lenient: case-insensitive; separators `-`, space, `_`, `.`, `,` and runs of them are accepted; any unambiguous prefix of at least 4 letters is expanded to the full word.
- CODE-4 (MUST): An unrecognized word produces a clear error naming the unrecognized word (never the whole code) and suggesting the closest match where one exists. A wrong word count produces an error stating the expected count.
- CODE-5 (MUST): **Canonical form**: after parsing, the code is normalized to the lowercase full words joined by a single `-`. All key derivation uses this canonical string (this avoids any dependence on bit-packing of list indices).
- CODE-6 (MUST): The code type is redacting: its `String()`, `GoString()`, formatting verbs, and JSON/text marshaling output a fixed placeholder. A single, explicit method reveals the code, and it is called only where the receiver prints the code to the user.
- CODE-7 (MUST): The code MUST NOT appear in logs at any verbosity, error messages, panics, debug output, mDNS records, or on-wire in any form other than through the cryptographic handshake.
- CODE-8 (MUST): The sender accepts the code from these sources, with this precedence: (1) the first positional argument (see CLI-6), (2) `--code-file PATH` (reads the first line; `-` means stdin), (3) the `TRANSPORTER_CODE` environment variable, (4) an interactive prompt (no echo) when stdin is a terminal. If no source yields a code, the command fails with a usage error.
- CODE-9 (MUST): The security documentation (DOC-4) explains that a code passed as a command-line argument is visible to other local users in process listings and in shell history, and recommends the other input methods in sensitive situations.

---

## 3. Receive mode

- RCV-1 (MUST): `transporter receive [flags] [DEST]` listens for one sender. `DEST` defaults to the current directory and is created if absent (with `0755`-masked permissions).
- RCV-2 (MUST): On start, the receiver prints to **stdout**, in a documented stable format, the listening address(es) and the code. All logs and progress go to stderr. (End-to-end tests parse this output.)
- RCV-3 (MUST): Flags: `--port N` (default: random free port), `--bind ADDR` (default: all interfaces; documented as a deliberate choice for LAN use), `--overwrite`, `--verify`, `--idle-timeout DURATION` (default 10 minutes; `0` disables), `--no-mdns`, `--no-sweep`, `--sweep-port N` (DISC-9).
- RCV-4 (MUST): When multiple network interfaces exist, the receiver lists every reachable non-loopback address (plus loopback only if it is the sole option).
- RCV-5 (MUST): The receiver serves **one active session at a time**. A newly authenticated connection that presents the **same `session_id`** as the active session **supersedes** the old connection (the old one is closed). This is required because after a network drop the receiver may not yet have noticed the old connection is dead. An authenticated connection with a **different** `session_id` while a session is active receives a `BUSY` error and is closed.
- RCV-6 (MUST): The receiver exits with status 0 after a successful transfer completes (one-shot by default).
- RCV-7 (MUST): After a connection drop mid-session, the receiver keeps listening until the idle timeout (RCV-3) expires with no authenticated activity. The idle timer also applies before the first sender connects.
- RCV-8 (MUST): The receiver limits concurrent unauthenticated connections (default 4) and applies the handshake deadline (SEC-4). Failed handshakes MUST NOT terminate the receiver, leak goroutines, or reveal why authentication failed.
- RCV-9 (SHOULD): Before accepting file data, the receiver makes a best-effort check that the destination filesystem has enough free space for the declared total size of files that need transfer, and fails early with a clear message if clearly insufficient (best-effort only, since it is inherently racy).

## 4. Send mode

- SND-1 (MUST): `transporter send [flags] [CODE] PATH...` sends one or more files and/or directories (see CLI-6 for how CODE is recognized).
- SND-2 (MUST): Naming semantics follow `cp -r`: a file is stored in the destination under its base name; a directory is stored under its base name with its contents beneath it. If two sources share a base name, the command fails before connecting with a clear error.
- SND-3 (MUST): Flags: `--to HOST:PORT`, `--retry-timeout DURATION` (default 10 minutes), `--verify`, `--no-mdns`, `--no-sweep`, `--sweep-port N` (DISC-9), `--code-file PATH`.
- SND-4 (MUST): The sender walks the tree lazily and streams the manifest; it MUST NOT load all file contents into memory, and memory use MUST NOT grow with file size.
- SND-5 (MUST): Files that cannot be read (permissions, removed during the walk) are reported as per-file errors; the transfer continues with remaining files and the final exit code reflects partial success (CLI-7).
- SND-6 (MUST): If a file changes during transfer (its size or mtime differs after the sender finishes reading it), the sender reports a per-file "changed during transfer" error and the file is not marked complete. It MUST NOT send more than the manifest-declared number of bytes for a file.
- SND-7 (MUST): The sender is the connection initiator. If `--to` is not given, the sender discovers the receiver via mDNS (DISC-1 to DISC-5) and, if that finds nothing, via a UDP unicast sweep (DISC-6 to DISC-9).

---

## 5. Manifest, paths and tree handling

- TREE-1 (MUST): Manifest entries carry: relative path, type (file or directory), size (64-bit unsigned), permission bits, and modification time (seconds + nanoseconds or equivalent).
- TREE-2 (MUST): Wire paths are relative, UTF-8, forward-slash separated, with no empty, `.` or `..` components, no NUL bytes, no backslashes, and no leading slash.
- TREE-3 (MUST): The **sender** skips, with a warning, any file or directory whose name cannot be represented under TREE-2 (invalid UTF-8, contains a backslash or NUL). This is a documented limitation.
- TREE-4 (MUST): Empty directories are transferred.
- TREE-5 (MUST): Files larger than 4 GiB are supported (all sizes and offsets are 64-bit).
- TREE-6 (MUST): Symlinks, device files, FIFOs and sockets are **skipped on the sender with a warning** (never followed or opened, so a FIFO cannot hang the sender). The receiver MUST reject any manifest entry of such a type as a protocol violation.
- TREE-7 (MUST): File permission bits are transferred masked to `0777` (never setuid, setgid or sticky). On Windows, permission handling is best-effort and documented.
- TREE-8 (MUST): Directory modification times are not preserved in v1 (documented). File mtimes are preserved (XFER-5).
- TREE-9 (MUST): The receiver detects and rejects manifests containing duplicate paths, or paths that collide after case folding or Unicode normalization (NFC) within the same manifest, with a clear error. (A normalization dependency, if used, must satisfy LIC-3.)
- TREE-10 (MUST): On Windows receivers, paths that are invalid on Windows (reserved device names such as `CON`/`NUL`, trailing dots or spaces, characters `<>:"|?*`, drive or UNC prefixes) are rejected with a clear per-entry error.
- TREE-11 (MUST): Limits, as documented constants: maximum manifest entries (default 1,000,000), maximum path length in bytes (default 4096), maximum single path component length (255). A manifest exceeding limits is rejected as a fatal error.
- TREE-12 (MUST): Memory use for very large trees is bounded: either the manifest is streamed in batches, or memory is O(entries) within the TREE-11 limit. The chosen approach is documented.

---

## 6. Transfer, integrity and resume

- XFER-1 (MUST): Every file is verified end to end with a **BLAKE3 (256-bit)** hash over the **whole file**. The sender sends the hash after the data (FILE_END). When resuming at offset N, the sender hashes the local prefix first so the final hash covers the full file.
- XFER-2 (MUST): The receiver writes data to `NAME.part` in the same directory as the final file, hashing as it writes (re-hashing any existing `.part` prefix on resume).
- XFER-3 (MUST): On a matching hash, the receiver flushes file data (`fsync`), atomically renames `NAME.part` to `NAME`, and applies mode and mtime. The containing directory is synced where the platform supports it. A file is never visible under its final name until verified.
- XFER-4 (MUST): On a hash mismatch, the receiver deletes the `.part` file and the sender retransmits the file from offset 0 **once**. A second mismatch is a fatal integrity error for that file, reported with the integrity exit code (CLI-7) after other files finish.
- XFER-5 (MUST): After finalizing a file, its mtime is set from the manifest so later runs can use the quick check (RES-2).
- XFER-6 (MUST): Small-file throughput MUST NOT be bounded by one network round trip per file: the sender MUST NOT wait for a per-file acknowledgment before starting the next file. A bounded number of files and bytes may be in flight (defaults: 8 files, 4 MiB; constants).
- XFER-7 (MUST): Overwrite policy: an existing destination file that passes the quick check (RES-2) is skipped as "already complete". An existing file that **differs** is reported as a **conflict and skipped** unless `--overwrite` is given, in which case it is replaced atomically via the `.part` mechanism. Conflicts are listed in the final summary and affect the exit code (CLI-7, CLI-8).
- RES-1 (MUST): The destination directory is the only persisted state. No separate state files are created.
- RES-2 (MUST): **Quick check**: a file is considered already complete if its size equals the manifest size and its mtime is within **2 seconds** of the manifest mtime (tolerance for coarse filesystems such as FAT). With `--verify` (on either side, negotiated), the quick check is replaced by a content-hash comparison.
- RES-3 (MUST): For a partial file, the receiver reports its `.part` size **rounded down to a chunk boundary** (a crash may leave a torn tail), and the transfer resumes from that offset.
- RES-4 (MUST): `.part` files for paths not in the current manifest are left untouched and mentioned in the final summary. The tool never deletes files it did not create in this run.
- RES-5 (MUST): If the receiver cannot make a `.part` file for a path (for example the final path exists as a directory, or the reverse), it reports a per-file error rather than failing the whole transfer.

---

## 7. Reliability

- REL-1 (MUST): On a transient failure the sender reconnects automatically: exponential backoff with **full jitter**, base 1 s, factor 2, cap 30 s. The backoff resets after a connection makes forward progress. Total retry budget defaults to 10 minutes (`--retry-timeout`; `0` means no retry).
- REL-2 (MUST): Each reconnect performs a fresh handshake with the same code (no cipher state carries over), then HELLO with the same `session_id`, then the manifest exchange (so state is rebuilt from the destination directory), then continues.
- REL-3 (MUST): Dead-connection detection: application-level heartbeat frames (sent when a connection is idle, default every 15 s) and read/write deadlines (default 45 s dead threshold), plus TCP keepalive. No goroutine may block indefinitely on a dead connection.
- REL-4 (MUST): **Transient** (retried): network errors, timeouts, connection resets, receiver temporarily busy. **Fatal** (stop immediately, no retry): authentication failure, protocol violation, protocol version mismatch, path-validation failure, destination out of space, destination not writable, retry budget exhausted. A fatal error prints a clear human-readable message and exits with the matching code.
- REL-5 (MUST): Authentication failure is treated as fatal on the first occurrence. The message says the code may be wrong or the receiver may be a different instance.
- REL-6 (MUST): Each session uses a `context.Context` cancelled when the connection ends; all goroutines started for a connection terminate when it ends (verified by tests, TEST-6). Channels between pipeline stages are bounded to provide backpressure.
- REL-7 (MUST): The tool handles SIGINT/SIGTERM (and the closest equivalent on Windows) by stopping cleanly, leaving `.part` files intact for resume, printing what was and was not transferred, and exiting with a distinct code.
- REL-8 (SHOULD): Limit file descriptors in use under pipelining (bounded by XFER-6), so trees with many small files do not exhaust descriptors.

---

## 8. Discovery

- DISC-1 (MUST): Unless `--no-mdns` is set, the receiver advertises an mDNS/DNS-SD service `_transporter._tcp` containing a TXT record with a **4-byte discovery tag** derived from the code. The code itself is never advertised (CODE-7).
- DISC-2 (MUST): The sender derives the same tag and connects to the matching receiver, so multiple receivers on one LAN do not conflict. The receiver advertises, and the sender queries, on every up, running, multicast-capable interface, and of a receiver's addresses the sender prefers one on its own subnets.
- DISC-3 (MUST): If no matching receiver is found within a timeout (default 5 s for mDNS, then 3 s for the sweep of DISC-7), the sender fails with a message suggesting `--to HOST:PORT`, noting that mDNS is often blocked on guest and corporate networks and that the sweep needs its UDP port open on the receiving machine.
- DISC-4 (MUST): `--to` always works without mDNS or the sweep and takes precedence over discovery.
- DISC-5 (MUST): mDNS is isolated behind an interface in `internal/discover` so the library can be replaced. The library is chosen based on maintenance status and license (LIC-3), recorded in `docs/DECISIONS.md`. Tests that need multicast are skipped with a clear message when multicast is unavailable (for example in CI).
- DISC-6 (MUST): Unless `--no-sweep` is set, the receiver listens on UDP port 29873 (`--sweep-port`) on its `--bind` address, IPv4 only, and answers a sweep probe carrying its discovery tag (DISC-1) with its TCP port. It sends nothing in reply to any other packet, and its reply is shorter than the probe, so it cannot be used to amplify traffic. Failing to listen (for example because the port is in use) is a warning, not an error.
- DISC-7 (MUST): If mDNS finds no receiver, or is disabled with `--no-mdns`, and `--no-sweep` is not set, the sender sends probes with the discovery tag and a random nonce to the addresses of DISC-8 on the sweep port, in paced rounds, for up to 3 s, and connects to the first receiver that answers with that nonce. The sweep runs only after mDNS has failed, so networks where mDNS works see no sweep traffic.
- DISC-8 (MUST): The sweep probes 127.0.0.1 (a receiver on the same machine) and every other address of each IPv4 subnet of an up, running, non-loopback interface. A subnet larger than /22 is limited to the /22 that contains the sender's address, and at most 4,096 addresses are probed in all, shared evenly among the subnets. IPv6 subnets are not swept.
- DISC-9 (MUST): `--no-sweep` and `--sweep-port N` exist for both send and receive and as config file keys, so the sweep can be turned off on networks where scanning is unwelcome. `--no-mdns` and `--no-sweep` together require `--to`.

---

## 9. Security

### 9.1 Cryptographic design

- SEC-1 (MUST): Secure channel: **Noise `NNpsk0`**, X25519, ChaCha20-Poly1305, BLAKE2s, using `github.com/flynn/noise` (the implementer MUST verify the library's current API and maintenance status; if it is unsuitable, stop and record the alternative in `docs/DECISIONS.md` rather than hand-rolling a protocol). The sender is the Noise initiator and the receiver the responder.
- SEC-2 (MUST): The pre-shared key is derived with **HKDF-SHA-256** (`crypto/hkdf`) from the canonical code string (CODE-5) with `info = "transporter v1 psk"`, output 32 bytes. The discovery tag uses `info = "transporter v1 discovery"`, output 4 bytes. Labels are constants and covered by golden-value tests.
- SEC-3 (MUST): The Noise prologue is the ASCII string `transporter/1`, so protocol mismatches fail the handshake cleanly.
- SEC-4 (MUST): Handshake deadline: 10 s (constant). On failure the sender prints a generic "authentication failed" message (REL-5); the receiver reveals nothing to the remote peer beyond closing the connection.
- SEC-5 (MUST): Every connection performs a fresh handshake with fresh ephemeral keys (forward secrecy). Nothing about cipher state, nonces or keys is reused across connections.
- SEC-6 (MUST): Nonce handling is entirely delegated to the Noise library's per-direction counters. The implementation MUST NOT implement its own nonce scheme. Rekeying behavior for very large transfers is handled according to the library's guidance and documented (Noise nonces are 64-bit; document that no practical transfer approaches the limit, or implement rekeying if the library supports it).
- SEC-7 (MUST): Framing: each frame is a 2-byte big-endian length followed by a Noise transport message. The maximum plaintext per frame is **48 KiB** (constant), safely under the Noise limit of 65,535 bytes including the tag. Frames with a zero length, a length above the maximum, or that fail authentication are rejected **before** allocating buffers sized from the peer-supplied length. Any authentication failure on a frame terminates the connection.
- SEC-8 (MUST): Heartbeat, control and data messages all travel inside authenticated frames.

### 9.2 Receiver hardening

- SEC-9 (MUST): **All** filesystem operations on the destination go through `os.Root`, so `..` and symlinks cannot escape the destination directory. In addition, every path is validated explicitly (TREE-2, TREE-10) as defense in depth.
- SEC-10 (MUST): The receiver treats the authenticated sender as untrusted input: all lengths, counts, offsets and sizes in messages are bounds-checked before use; offsets must be within the declared file size and consistent with the negotiated resume offset; chunk data beyond the declared size is a protocol violation.
- SEC-11 (MUST): The receiver never creates setuid/setgid/sticky files (TREE-7) and never follows symlinks within the destination.
- SEC-12 (MUST): The receiver enforces the limits in TREE-11 and caps frame and message sizes (SEC-7).
- SEC-13 (MUST): Messages from the wrong state (for example CHUNK before NEED) are protocol violations that terminate the connection.

### 9.3 Extensibility

- SEC-14 (MUST): A small interface in `internal/pairing` abstracts how the handshake secret is obtained from user input, so a short-code PAKE mode could be added later without touching the transfer layers. Only the high-entropy-code mode is implemented now. The extension point is documented in `docs/architecture.md`.

### 9.4 Operational

- SEC-15 (MUST): Logging uses `log/slog`. No log line contains the code, key material, or file contents. Tests assert this (TEST-9).
- SEC-16 (MUST): The security documentation states plainly that the project has not been independently audited and that the metadata (file names, sizes, counts) is visible to the authenticated receiver.

---

## 10. Protocol

The complete wire format MUST be specified in `docs/protocol.md` precisely enough for an independent implementation (DOC-3). The requirements on the protocol itself:

- PROTO-1 (MUST): All application messages travel inside Noise frames (SEC-7). Control messages use a **compact hand-written binary encoding** with strict bounds checking in decoders (so they can be fuzzed). No reflection-based or self-describing formats in the hot path.
- PROTO-2 (MUST): The protocol defines at least these messages: HELLO (protocol version, `session_id` of 128 random bits, capability flags including `verify`), MANIFEST (entries in one or more frames, with an end marker), NEED (per file: skip, or send from offset N), FILE_START, CHUNK, FILE_END (BLAKE3 hash), ACK (ok, hash mismatch, or error code), HEARTBEAT, DONE, ERROR (code, message, fatal flag), BUSY.
- PROTO-3 (MUST): Version negotiation: HELLO carries the version; a mismatch yields a fatal ERROR on both sides with a message naming both versions.
- PROTO-4 (MUST): The protocol defines an explicit state machine (documented) and rejects out-of-state messages (SEC-13).
- PROTO-5 (MUST): The `session_id` is not a secret and not a security mechanism. It only identifies continuation of a session after reconnect (RCV-5).
- PROTO-6 (MUST): Chunks of different files may be pipelined (XFER-6). The protocol identifies the file of each CHUNK so that files can be completed and acknowledged independently.
- PROTO-7 (MUST): The DONE/final acknowledgment lets the receiver report totals, and the sender confirms it received a final success response before exiting 0.

---

## 11. CLI and user experience

- CLI-1 (MUST): Subcommands `send` and `receive`; global flags `-v/--verbose`, `--version`, `-h/--help`. The standard library `flag` package SHOULD be used unless a framework is justified in `docs/DECISIONS.md`.
- CLI-2 (MUST): Progress is written to stderr: current file, bytes transferred, rate, ETA, retry messages. When stderr is not a terminal, output degrades to periodic plain lines with no control characters.
- CLI-3 (MUST): A final summary reports files and bytes transferred, skipped (already complete), conflicts, per-file errors, retries, and elapsed time.
- CLI-4 (MUST): Error messages are written for end users: what went wrong, the likely cause, and what to try.
- CLI-5 (MUST): `--help` for each subcommand documents every flag with its default.
- CLI-6 (MUST): **Code vs path recognition for `send`**: the code, when given on the command line, is the **first positional argument**; remaining positionals are paths. The first positional is treated as a code if and only if it parses as a complete valid code under CODE-3/CODE-4 rules. Otherwise all positionals are paths and the code must come from another source (CODE-8). If a code is also available from another source, the positional code wins.
- CLI-7 (MUST): Exit codes (documented, and covered by tests):

  | Code | Meaning |
  |---|---|
  | 0 | Success |
  | 1 | Internal error |
  | 2 | Usage error |
  | 3 | Authentication failure |
  | 4 | Network failure or timeout (retry budget exhausted, idle timeout, discovery failed) |
  | 5 | Filesystem error (cannot write, out of space) |
  | 6 | Integrity failure (hash mismatch after retry) |
  | 7 | Partial success (conflicts or per-file errors; see CLI-8) |
  | 130 | Interrupted by signal |

- CLI-8 (MUST): Warnings that do not affect correctness (for example skipped symlinks) do not change the exit code but are listed in the summary. Conflicts and per-file errors yield exit code 7.
- CLI-9 (MUST): When several failure conditions occur, the exit code follows this precedence: 3, 5, 6, 4, 7, then 0 (fatal conditions outrank partial success).

---

## 12. Decisions already made

| Topic | Decision |
|---|---|
| Authentication model | High-entropy code as the Noise PSK (NNpsk0). No PAKE, no certificates. |
| Code entropy | At least 88 bits (8 words from a 2048-word list). |
| Key derivation input | The canonical lowercase hyphen-joined code string. |
| Receiver lifecycle | One-shot: exits after a successful transfer. |
| Resume state | Destination directory only. `.part` files plus size/mtime quick check. |
| Quick-check tolerance | 2 seconds on mtime. |
| Symlinks and special files | Skipped with a warning in v1. |
| CLI positional order | `send CODE PATH...` (code first). |
| Session supersession | Same `session_id` supersedes the old connection; different `session_id` gets BUSY. |
| Project name | **Transporter**, binary `transporter`. |
| License | **MPL-2.0** (to be revisited if dependency licenses require; see LIC-5). |

---

## 13. Platforms and non-functional requirements

- NFR-1 (MUST): Linux, macOS and Windows build and pass all tests (amd64 and arm64 cross-compile on all three families).
- NFR-2 (MUST): Go version: the project's minimum Go version is the **oldest release whose `os.Root` supports every operation the receiver needs** (open, create, mkdir including nested directories, rename, chmod, chtimes, remove, stat/lstat). This is believed to be Go 1.25, because `os.Root` in Go 1.24 lacks rename, nested mkdir and chtimes. The implementer MUST verify this against the Go release notes and the `os` package documentation, and record the result. The `go` and `toolchain` directives are set accordingly, and CI tests the minimum and the latest stable.
- NFR-3 (SHOULD): Throughput on loopback and gigabit LAN is limited by disk or network, not by the implementation (no per-chunk allocations of full frame buffers in the hot path; buffers pooled or reused).
- NFR-4 (MUST): Memory use does not grow with file size (SND-4) and is bounded under pipelining (XFER-6).
- NFR-5 (MUST): Third-party dependencies are minimized, each justified in `docs/DECISIONS.md` (maintenance status, license, why the standard library is insufficient).
- NFR-6 (MUST): Code is idiomatic, documented Go: doc comments on all exported identifiers, errors wrapped with `%w` and context, no panics for expected failures, and comments explaining **why** for non-obvious code (security checks, protocol invariants, concurrency and shutdown logic, platform workarounds).
- NFR-7 (MUST): The project name appears in one place in code (a constant) and the module path is `github.com/OWNER/transporter` with `OWNER` a clearly marked placeholder, so renaming is a small change.
- NFR-8 (MUST): No Star Trek logos, artwork, fonts, quotations or character names appear in the repository, documentation, or CLI output. The README includes a short statement that the project is not affiliated with or endorsed by the owners of that franchise.

---

## 14. Testing

Coverage target: **at least 85% statement coverage on `internal/...`** (excluding `cmd` wiring), enforced in CI, with meaningful assertions rather than coverage padding. (If the implementer finds 85% counterproductive at the start of the project, they may start lower and ratchet up, recording the choice.)

- TEST-1 (MUST): Tests reference requirement IDs they cover (in names or comments), and `docs/testing.md` includes a table mapping each MUST requirement to its tests, or states why it is verified by inspection.
- TEST-2 (MUST): **Unit tests** (table-driven where appropriate) for: code generation, parsing, leniency, error messages, redaction (the code never appears in formatted output of the type), and golden-value KDF vectors; frame encoding and decoding; every protocol message round trip; backoff schedule (using an injectable clock/sleeper, asserting jitter bounds and cap); path validation; overwrite and quick-check logic; resume offset rounding; error classification (transient vs fatal); CLI argument parsing including CLI-6.
- TEST-3 (MUST): **Secure channel tests**: handshake success with the right code; failure with a wrong code; prologue/version mismatch; tampered, replayed, reordered, oversized and zero-length frames rejected; deadlines honored; concurrent read/write is race-free.
- TEST-4 (MUST): **Fuzz tests** (`go test -fuzz`) for every decoder, the frame reader and the path validator, asserting no panics and no unbounded allocation. Seed corpora are committed.
- TEST-5 (MUST): **Hostile input tests**: a corpus of hostile paths (`../`, absolute, backslash, NUL, drive letters, UNC, reserved Windows names, overlong, case and Unicode collisions, duplicates), symlink and `os.Root` escape attempts (asserting failure and that nothing is written outside the destination), manifest limit violations, out-of-state messages, and offsets outside the declared size.
- TEST-6 (MUST): **Leak and race checks**: all tests run with `-race` and `-shuffle=on`; session tests verify no goroutine leaks after connection drops (using a maintained leak checker or a small in-repo helper, justified).
- TEST-7 (MUST): **Fault-injection integration tests** (in-process, over `net.Pipe` or loopback) using a test helper connection wrapper that can drop after N bytes, stall reads/writes, delay, truncate, and corrupt bytes. Cover: drop mid-chunk, during handshake, during manifest, repeated drops on a flaky link, a stalled connection with no close (exercising REL-3), corrupted ciphertext, and receiver restart between attempts.
- TEST-8 (MUST): **End-to-end tests** that build the real binary and run it as subprocesses over loopback with temp directories (ports from port 0, never fixed). Scenarios: (1) single file and a large file (default 64 MiB, larger only when not `-short`); (2) nested tree with empty directories, many small files (about 5,000), Unicode names, spaces; (3) kill the sender mid-transfer and rerun, verifying only the remainder transfers and the final tree is byte-identical; (4) kill and restart the receiver mid-transfer, verifying `.part` reuse; (5) repeated network interruption through a TCP proxy helper, transfer still completes correctly; (6) wrong code fails fast with exit code 3 and writes nothing; (7) hostile manifest from a test-only sender or crafted frames is rejected and nothing is written outside the destination; (8) overwrite policy and `--verify` behavior; (9) idle timeout and retry-timeout expiry produce exit code 4; (10) all code input methods (CODE-8) work; (11) mDNS discovery where multicast is available, skipped otherwise, and discovery by the UDP sweep over loopback on a free port; every other scenario uses `--to`; (12) a file modified during transfer produces exit code 7 (SND-6); (13) same-`session_id` supersession and BUSY behavior (RCV-5); (14) summary and exit-code precedence (CLI-9).
- TEST-9 (MUST): An end-to-end test captures all output at every verbosity level and asserts the code never appears in it (except the single receiver banner line).
- TEST-10 (MUST): Tests compare trees by relative path, size, content hash, and (where applicable) mode and mtime. Tests are hermetic and safe to run in parallel. Slow tests are guarded by `testing.Short()`.
- TEST-11 (SHOULD): Process-kill tests on Windows use the mechanism appropriate to that platform and document any behavioral difference.

---

## 15. CI/CD and repository hygiene

GitHub Actions workflows gate pull requests. All jobs below MUST pass for merge.

- CI-1 (MUST): `ci.yml`, triggered on `pull_request` and on `push` to `main`, with jobs:
  - **lint**: `gofmt` check, `go vet`, `golangci-lint` (with a committed `.golangci.yml` enabling at least errcheck, staticcheck, govet, gosec, ineffassign, unused, errorlint, gocritic, revive or equivalent).
  - **test**: matrix of `ubuntu-latest`, `macos-latest`, `windows-latest` by (minimum Go version, latest stable): `go test -race -shuffle=on ./...` with coverage; fail below the threshold; upload the coverage report.
  - **e2e**: build and run the end-to-end suite on all three operating systems.
  - **fuzz-smoke**: run each fuzz target briefly (about 30 s each) on Linux.
  - **vuln**: `govulncheck ./...`.
  - **license**: dependency license allowlist check and SPDX header check (LIC-2, LIC-4).
  - **build**: cross-compile linux/darwin/windows by amd64/arm64.
  - **mod-tidy**: fail if `go mod tidy` or `go mod verify` changes anything.
  - **docs**: Markdown lint and link check (tools pinned).
- CI-2 (MUST): Separate workflows for CodeQL (Go) and dependency review on PRs.
- CI-3 (SHOULD): A release workflow triggered by version tags that builds archives and checksums for all platforms (GoReleaser or equivalent), includes license files in the archives, and creates a **draft** release only (never publishes automatically). Build provenance attestation is used if feasible.
- CI-4 (MUST): Third-party GitHub Actions are pinned to full commit SHAs **obtained from the actual action repositories** (for example via `gh api` or the releases page), with a version comment. SHAs MUST NOT be invented or recalled from memory. If the implementer cannot verify a SHA in their environment, they MUST pin to the version tag, mark it with a `TODO(pin-sha)` comment, and list it under maintainer open items (Section 17).
- CI-5 (MUST): Workflows set top-level `permissions: contents: read` and grant additional permissions per job only where required; do not use `pull_request_target`; use `concurrency` to cancel superseded runs; set job timeouts.
- CI-6 (MUST): `dependabot.yml` for Go modules and GitHub Actions (weekly).
- CI-7 (MUST): A `Makefile` with targets `build`, `test`, `test-short`, `e2e`, `fuzz`, `lint`, `cover`, `tidy`, `docs-check`, `license-check`, and `ci` (runs the same checks as CI locally). The Makefile and workflows MUST stay consistent.
- CI-8 (MUST): `docs/branch-protection.md` lists the exact required status check names and recommended protection settings (pull request required, status checks required and branch up to date, no force-push) and a `gh api` command the maintainer can run. The implementer cannot apply these settings and lists this under maintainer open items.
- CI-9 (MUST): Repository templates: `PULL_REQUEST_TEMPLATE.md`, issue templates (bug, feature), and a `CODEOWNERS` file with a placeholder owner.

---

## 16. Documentation, licensing and compliance

### 16.1 Documentation

- DOC-1 (MUST): `README.md`: what and why (including an honest comparison with scp, sftp, rsync, magic-wormhole and croc), installation, quick start, common recipes, flags table, exit codes, troubleshooting (firewalls, mDNS blocked, wrong code, resume), platform notes, the license section (LIC-7), the export notice (LIC-8), and the non-affiliation statement (NFR-8).
- DOC-2 (MUST): `docs/architecture.md`: component diagram (Mermaid), data flow, concurrency model, package responsibilities, the pairing extension point.
- DOC-3 (MUST): `docs/protocol.md`: the complete wire specification (framing, message layouts and byte order, state machine, limits, error codes, version negotiation, reconnect and resume semantics).
- DOC-4 (MUST): `docs/security.md`: threat model (what is and is not protected), why 88 bits and why no PAKE, handshake properties (forward secrecy, resistance to man-in-the-middle by anyone without the code), brute-force analysis, the command-line-visibility tradeoff (CODE-9), receiver hardening, known limitations (SEC-16), and responsible disclosure instructions.
- DOC-5 (MUST): `docs/testing.md`: how to run each test category, how fault injection works, the coverage policy, and the requirements-to-tests table (TEST-1).
- DOC-6 (MUST): `CONTRIBUTING.md` (setup, `make` targets, commit and PR conventions, how CI gates work, MPL-2.0 expectations per LIC-7), `SECURITY.md`, `CHANGELOG.md` (Keep a Changelog format), `CODE_OF_CONDUCT.md`.
- DOC-7 (MUST): GoDoc on all exported symbols; runnable `Example` tests where they clarify usage.
- DOC-8 (MUST): `docs/DECISIONS.md` is a running log: one short entry per decision (including any deviation from a SHOULD), with rationale. Documentation MUST match the implemented behavior; the protocol and CLI docs are re-verified against the code before the work is considered complete.

### 16.2 Licensing (MPL-2.0)

- LIC-1 (MUST): `LICENSE` contains the verbatim, unmodified MPL-2.0 text obtained from the official source (mozilla.org/MPL/2.0). It MUST NOT be retyped from memory or paraphrased. If it cannot be fetched, stop and flag it in the maintainer items rather than approximating it.
- LIC-2 (MUST): Every `.go` file (including tests) begins with:

  ```go
  // SPDX-License-Identifier: MPL-2.0
  //
  // This Source Code Form is subject to the terms of the Mozilla Public
  // License, v. 2.0. If a copy of the MPL was not distributed with this
  // file, You can obtain one at https://mozilla.org/MPL/2.0/.
  ```

  The "Incompatible With Secondary Licenses" notice MUST NOT be added.
- LIC-3 (MUST): Dependency license **allowlist**: MIT, BSD-2-Clause, BSD-3-Clause, ISC, Apache-2.0, MPL-2.0, 0BSD, Unlicense, CC0 (plus the Go standard library's BSD license). GPL, LGPL, AGPL, SSPL, source-available or non-commercial licenses, and unlicensed code are **not** permitted without a recorded decision in `docs/DECISIONS.md` and a flag in the maintainer items, because they may force a change of project license.
- LIC-4 (MUST): CI verifies that all dependencies fall within the allowlist (with a maintained, pinned scanner such as `go-licenses` or equivalent, whose maintenance status is recorded) and that every `.go` file has the SPDX header.
- LIC-5 (MUST): If a necessary dependency is outside the allowlist and no alternative exists, the implementer records the issue and stops short of adopting it, flagging that the project license may need to change.
- LIC-6 (MUST): `THIRD_PARTY_LICENSES` lists each dependency, its license, and any required attribution, including the embedded wordlist and any Apache-2.0 NOTICE content. It is updated whenever dependencies change (enforced in CI where practical) and its content ships in release archives.
- LIC-7 (MUST): `CONTRIBUTING.md` explains that MPL-2.0 is file-level copyleft, that modifications to MPL-covered files remain under MPL-2.0, and that contributions are accepted under the same license. No CLA is added unless the maintainer requests one.

### 16.3 Export compliance

- LIC-8 (MUST): This project implements encryption. The README or `docs/security.md` carries a short, factual, non-legal-advice notice that the software contains cryptographic functionality which may be subject to export regulations in some jurisdictions (for example the US Export Administration Regulations), that the maintainer is responsible for determining and fulfilling applicable obligations before distribution, and that users are responsible for compliance in their own jurisdictions. The notice MUST NOT assert a specific classification or legal conclusion.

---

## 17. Deliverables and open items

- DEL-1 (MUST): The repository contains: the source and tests, the docs in Section 16, the CI configuration in Section 15, `LICENSE`, `THIRD_PARTY_LICENSES`, and `docs/DECISIONS.md`.
- DEL-2 (MUST): The repository layout separates concerns. The following is the expected layout (names may be adjusted if recorded in `docs/DECISIONS.md`):

  ```
  cmd/transporter/     main and subcommand wiring only
  internal/code/       generate, parse, redact; wordlist; KDF labels
  internal/pairing/    pairing interface and the high-entropy-code implementation
  internal/secure/     Noise handshake; SecureConn framing
  internal/proto/      message types, encode/decode, limits
  internal/manifest/   tree walk, entries, path validation, collision checks
  internal/recv/       receiver session, os.Root file operations, .part handling
  internal/send/       sender session, reconnect and backoff loop
  internal/discover/   mDNS and UDP sweep advertise and browse
  internal/progress/   progress rendering
  internal/testutil/   fault-injecting conn, TCP proxy, tree builders
  test/e2e/            end-to-end tests that run the built binary
  docs/                documentation
  .github/             workflows, dependabot, templates
  ```

- DEL-3 (MUST): Transfer logic is written against `net.Conn`-like interfaces so it can be tested over in-memory pipes and fault injection without real networking.
- DEL-4 (MUST): At completion, the implementer produces a report listing: an architecture summary; any deviations from this document with reasons; every third-party dependency with its license and justification; known limitations; and the **maintainer open items** below.

### Maintainer open items (to be listed in the final report, not decided by the implementer)

1. Fill in the copyright holder and the `OWNER` placeholder.
2. Review export-compliance obligations before distributing the software (LIC-8).
3. Apply branch protection and repository settings (CI-8).
4. Resolve any dependency whose license falls outside the allowlist (LIC-3, LIC-5), and decide whether MPL-2.0 remains appropriate.
5. Replace any action pinned by tag with a verified commit SHA (CI-4).
6. Confirm the name "transporter" is acceptable for the intended distribution channels (for example package managers), noting that other small projects with that name exist.
7. Consider an independent cryptographic and security review before wide distribution (the tool is unaudited, SEC-16).
