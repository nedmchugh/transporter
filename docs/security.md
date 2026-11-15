# Security

> **Transporter has not been independently audited.** It uses well-studied
> building blocks (the Noise Protocol Framework, X25519, ChaCha20-Poly1305,
> BLAKE2s, BLAKE3, HKDF), but their combination here has not been reviewed
> by a third party. Consider an independent review before relying on it
> where the stakes are high.

## 1. Threat model

### Protected against

- A **passive network observer** (anyone on the LAN, Wi-Fi or path) learns
  nothing about file contents or names. All application data, including
  the manifest, heartbeats and errors, is encrypted and authenticated.
- An **active network attacker without the code** (man in the middle,
  injector, replayer) cannot read or alter the transfer. Tampered,
  replayed, reordered or truncated frames fail authentication and end the
  connection; the sender then reconnects with a fresh handshake. Such an
  attacker can always stop the transfer, which no protocol can prevent.
- A **receiver-side escape** by a malicious or buggy authenticated sender:
  the receiver treats everything the sender says as untrusted (section 5).
- **Later compromise of the code**: each connection uses fresh ephemeral
  X25519 keys, so recording traffic and learning the code afterwards does
  not decrypt it (forward secrecy).

### Not protected against

- Anyone who **has the code**. The code is the only credential. Whoever
  holds it during the receiver's lifetime can send files to it or, by
  impersonating the receiver on the network, receive the sender's files.
  Share it only with the intended person, over a channel you trust.
- An authenticated peer learning **metadata**: the receiver sees every file
  name, size, mode, modification time and count in the manifest. That is
  inherent in copying a tree.
- **Traffic analysis**: an observer sees IP addresses, ports, timing and
  approximate volume.
- A compromised sender or receiver machine.
- **Denial of service** by anyone on the network (dropping packets,
  opening connections, answering mDNS queries or sweep probes with wrong
  addresses).

## 2. Design: why a high-entropy code and no PAKE

The receiver generates a one-time code of **9 words from a 1,999-word
list**: 1999^9 ≈ 2^98.7, about **98.7 bits** of entropy (the requirements
ask for at least 88). The canonical code string is turned into a 32-byte
key with HKDF-SHA-256 (`info = "transporter v1 psk"`). That key is the
pre-shared key of a Noise `NNpsk0` handshake (X25519, ChaCha20-Poly1305,
BLAKE2s) with the prologue `transporter/1`.

A password-authenticated key exchange (PAKE, as in magic-wormhole) allows
short codes, because each guess needs an online interaction with the real
peer. It also adds a relatively complex protocol and, in practice,
dependencies that are less widely implemented. Transporter instead makes
the code long enough that **offline guessing is infeasible**. Then a plain,
well-analyzed PSK handshake suffices, and nothing has to be invented.
The cost is a longer code to type. The pairing step sits behind an interface
(`internal/pairing`), so a short-code PAKE mode could be added later without
changing the transfer layers (see `architecture.md`).

## 3. Handshake properties

- **Mutual authentication by the code**: message 1 is encrypted under a key
  mixed from the PSK, so a receiver with a different code cannot decrypt
  it and closes the connection. Message 2 is similarly bound to the PSK, so
  the sender knows it reached a holder of the code. Neither side has
  long-term keys.
- **Man-in-the-middle resistance**: an attacker without the code cannot
  complete either half of the handshake, so it cannot relay or read
  traffic.
- **Forward secrecy**: every connection, including every reconnect, uses
  fresh ephemeral keys. No key, nonce or cipher state is reused across
  connections.
- **Clean version separation**: the prologue `transporter/1` is mixed into
  the handshake, so incompatible protocol versions fail the handshake
  instead of misinterpreting messages.
- **Nonces** are the Noise library's per-direction 64-bit counters. The
  implementation never sets or reuses them. A connection can carry
  2^64 − 2 frames per direction (about 10^24 bytes); no transfer gets
  close, so rekeying is not implemented. The library refuses to encrypt
  past the limit, and a reconnect would start a new handshake.
- **What the receiver reveals on failure**: nothing. It sends no error to
  an unauthenticated peer and only closes the connection. The sender
  reports a generic "authentication failed: the code may be wrong, or the
  receiver may be a different instance".

## 4. Brute-force analysis

| Attack | What it needs | Cost |
| --- | --- | --- |
| Online guessing against a receiver | One TCP connection and handshake per guess; at most 4 unauthenticated connections at a time, 10 s deadline each. The receiver lives minutes. | Thousands of guesses at best, against 2^98.7: negligible. |
| Offline guessing from handshake message 1 | A copy of message 1: either observed on the network, or received by pretending to be the receiver (for example with a spoofed mDNS or sweep answer). Each guess costs one HKDF and one AEAD check, with no Diffie-Hellman. | At 10^12 guesses per second (a large GPU farm), about 2^58.8 s ≈ 1.6 × 10^10 years. |
| Offline guessing from the discovery tag (mDNS or sweep) | The 4-byte discovery tag (an HKDF output) filters guesses without any handshake. | The same cost per guess as above; the tag does not shorten the search. 2^32 possible tags mean many codes share a tag, so the tag alone never confirms a guess. |

The 88-bit floor in the requirements leaves this margin even if the list
were smaller. Increasing the word count increases it further.

## 5. Receiver hardening

The receiver treats an authenticated sender as **untrusted input**:

- **Confinement**: every filesystem operation on the destination goes
  through Go's `os.Root` (Go 1.25+), so `..` components and symlinks cannot
  lead outside it. A test scans the package source to keep it that way. The
  only exceptions are creating the destination directory itself and
  querying free space.
- **No symlink following**: `os.Root` still follows symlinks that stay
  inside the root. The receiver `Lstat`s every directory, final name and
  `.part` name it uses, and refuses symlinks as per-file errors. A local
  process that swaps in a symlink between that check and the use (TOCTOU)
  is still confined to the destination by `os.Root`.
- **Path validation** before any filesystem call: relative, UTF-8, `/`
  separators only, no empty, `.` or `..` components, no NUL or backslash.
  On Windows, reserved device names and invalid characters are also
  rejected. Paths that collide after case folding or Unicode normalization
  are rejected, so a case-insensitive filesystem cannot be tricked into
  writing one file twice.
- **Bounds checks**: frame lengths are checked before reading;
  message decoders check every length against the input actually present;
  chunk offsets must continue exactly and stay within the declared size;
  manifest limits (1,000,000 entries, 4,096-byte paths, 255-byte components)
  are enforced; messages out of state end the connection.
- **No privilege bits**: file modes are applied as `mode & 0777` through
  the open file descriptor. Setuid, setgid and sticky bits are never
  created. Directories are created `0755` (subject to the umask).
- **Integrity**: data is written to `NAME.part`, hashed with BLAKE3 as it is
  written, and becomes visible under its final name only after the
  whole-file hash from the sender matches, fsync and an atomic rename.
- **Resource limits**: at most 4 concurrent unauthenticated connections
  (extra ones wait in the kernel backlog), a 10-second handshake deadline,
  one active session, at most 8 files open for writing, and 45-second
  read/write deadlines.
- **Terminal safety**: names and messages from the peer are printed with
  control characters escaped, so a crafted file name cannot inject terminal
  escape sequences.

## 6. The code on the command line

Passing the code as an argument (`transporter send CODE PATH...`) is
convenient, but **other local users can see command-line arguments** in
process listings (`ps`, `/proc`, Task Manager), and the shell may save it in
its history file. On shared or sensitive machines, use one of:

- `--code-file PATH` (the first line of a file you protect), or
  `--code-file -` to read it from standard input;
- the `TRANSPORTER_CODE` environment variable (visible only to the same
  user and root on most systems);
- no code at all, and type it at the prompt when stdin is a terminal (it is
  not echoed).

The code is valid only for one receiver run, which limits the exposure, but
during that run it is the only credential.

The implementation keeps the code out of everything except the receiver's
banner line: the `Code` type redacts itself in every formatting and
marshaling path, logs never include it, error messages name at most the
single mistyped word, and mDNS carries only the derived tag. An end-to-end
test checks all output at every verbosity.

The optional config file of defaults (README, "Config file") cannot hold
the code or `code-file`: a code stored there would be a long-lived secret
on disk, and CODE-8 fixes the code's sources. Because the file can change
what a transfer does (for example `overwrite` or `to`), it is refused on
Unix if group or others can write it. It is read-only state: Transporter
never writes it (DECISIONS.md D-9.9).

## 7. Known limitations

- **Not independently audited** (see the top of this document).
- **Metadata is visible to the authenticated receiver**: names, sizes,
  modes, timestamps and counts, by design.
- **mDNS is unauthenticated**: anyone on the LAN can answer discovery
  queries. A spoofed answer cannot break confidentiality (the handshake
  fails), but it can stop the transfer and obtain handshake message 1 for
  the offline attack in section 4. Use `--to` on untrusted networks. The
  advertisement reveals that a Transporter receiver is running, its port,
  its addresses, and a random instance name; it does not include the
  machine's host name.
- **The UDP sweep is unauthenticated too**, with the same consequences as
  a spoofed mDNS answer. A sweep answer must echo the probe's random
  nonce, so an attacker has to see the probe first, as any host on the
  subnet does. The probe carries the same tag that mDNS already
  advertises. The receiver answers only probes with its tag, so a scan of
  UDP port 29873 without the tag finds nothing, and its 15-byte reply is
  shorter than the 17-byte probe, so it cannot amplify a spoofed-source
  flood. When mDNS fails, the sender's sweep sends one small probe to
  each address of its subnets (up to 4,096) every second for up to 3 s,
  which
  network intrusion detection may report as a scan. Disable it with
  `--no-sweep` (or `no-sweep: true` in the config file) where that is
  unwelcome.
- **Rejection signal**: a receiver that is killed exactly while answering a
  handshake looks, to the sender, like a wrong code (exit 3). Rerun.
- **Key material in memory**: Go cannot reliably erase memory, so derived
  keys live until garbage collected.
- **Partial files**: `.part` files hold received but unverified data until
  completed. They live in the destination with the receiving user's
  permissions (`0600`).

## 8. Export notice

This software contains cryptographic functionality. Its export,
re-export, import or use may be subject to export control and other laws
in some jurisdictions, for example the United States Export Administration
Regulations. This notice is not legal advice and does not state a
classification. The maintainer is responsible for determining and meeting
any obligations that apply before distributing the software. Users are
responsible for complying with the laws of their own jurisdictions.

## 9. Reporting a vulnerability

Please report vulnerabilities **privately** through GitHub's private
vulnerability reporting for this repository ("Security" tab, "Report a
vulnerability"). See [SECURITY.md](../SECURITY.md). Do not open a public
issue, and never include a pairing code in a report.
