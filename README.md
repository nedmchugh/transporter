# Transporter

**Transporter: zero-setup, encrypted, resumable file and directory transfer
between two machines on the same network.**

Start a receiver; it prints a one-time code. Give that code to the sender.
The transfer is encrypted, every file is verified end to end, and it resumes
automatically after network failures. There are no certificates, key
files, accounts, daemons, configuration files or saved state.

```console
receiver$ transporter receive ./dest
Listening on 192.168.1.20:41853
Code: orbit-lava-vivid-copper-saddle-meadow-coral-valve-velvet

sender$ transporter send orbit-lava-vivid-copper-saddle-meadow-coral-valve-velvet ./project
```

> Other small projects are also called "transporter". This one is the
> zero-setup LAN file-transfer tool described here.

## Why

| Tool | Good at | Where it falls short for this use |
| --- | --- | --- |
| `scp` | Ubiquitous, simple for one file | Needs an SSH server and an account on the receiver; no resume; one failure restarts the copy. |
| `sftp` | Interactive browsing, `reput` resume | Needs SSH set up; resuming trees is manual. |
| `rsync` | Delta transfer, mirroring, very flexible | Needs rsync on both ends and usually SSH; getting resume, partial files and retries right takes the right flags; it does not reconnect with backoff by itself. |
| magic-wormhole | Short, human-friendly codes (PAKE); works across the internet through a relay | Uses a relay server by default; no resume of interrupted transfers; directories are sent as an archive. |
| croc | Codes, resume, works across the internet through a relay | Uses a public relay by default; a short code depends on its PAKE. |
| **Transporter** | Direct LAN transfer with nothing to set up; resume and retry by default; trees with empty directories, modes and mtimes | **No relay or NAT traversal**: the sender must be able to reach the receiver's IP and port. Codes are long (9 words), because the design uses a high-entropy secret instead of a PAKE. One transfer per receiver run. |

## Install

From a release: download the archive for your platform from the project's
releases page, check it against `checksums.txt`, and put `transporter` on
your `PATH`.

From source (Go 1.26 or newer):

```console
go install github.com/nedmchugh/transporter/cmd/transporter@latest
```

From source with only Docker installed: in a checkout, run

```console
scripts/docker-build.sh
```

It builds Linux, macOS and Windows binaries for amd64 and arm64 in a
container and copies them to `dist/docker/` (with `SHA256SUMS`, `LICENSE`
and `THIRD_PARTY_LICENSES`), then names the one for your machine, such as
`dist/docker/transporter-linux-amd64`. An optional argument sets a
different output directory. The script needs a POSIX shell, so on Windows
run it from Git Bash or WSL.

### Install script (Linux and macOS)

In a checkout, run as your normal user (not with `sudo`):

```console
scripts/install.sh            # build in Docker (default)
scripts/install.sh --local    # build with Go and make on this machine
```

The script builds the binary for this machine's OS and architecture
(amd64 or arm64) and installs it as `/usr/local/bin/transporter`.
`make install` runs it with the defaults.

- **Root is used only for the copy.** Before building, the script checks
  that it can get root: it runs `sudo -v` (or `doas true` where `sudo` is
  not installed), which may ask for your password. If that fails, it stops
  before building anything. The build then runs as you, and only the final
  `mkdir -p /usr/local/bin` and `install -m 0755` run through `sudo`. Run
  with `sudo`, the script refuses, because the build would run as root
  too; in a plain root shell (for example a container) it needs no
  elevation.
- **Docker build (default):** needs only a Docker engine that your user
  can reach. It runs `scripts/docker-build.sh`, which builds every
  platform into `dist/docker/`, and checks the binary for this machine
  against `dist/docker/SHA256SUMS`.
- **Local build (`--local`):** needs Go 1.26 or newer and `make`. It runs
  `make build` with `GOOS` and `GOARCH` set to this machine, producing
  `bin/transporter`.
- Before installing, the script runs the new binary with `--version`, and
  afterwards prints the installed version. Running it again replaces the
  installed binary.
- `DOCKER` and `GO` select other commands; `VERSION` overrides the
  version stamped into the binary.

To uninstall, remove the file: `sudo rm /usr/local/bin/transporter`.

## Quick start

1. On the machine that should **receive** files:

   ```console
   transporter receive ~/incoming
   ```

   It prints its addresses and a code, then waits (10 minutes by default).

2. On the machine that **sends**:

   ```console
   transporter send CODE ./photos ./notes.txt
   ```

   The sender finds the receiver on the local network with mDNS, or, if
   mDNS is blocked, by sending a small UDP probe to every address on its
   subnet ([Finding the receiver](#finding-the-receiver) has the
   details). If neither works, add `--to` with an address the receiver
   printed:

   ```console
   transporter send --to 192.168.1.20:41853 CODE ./photos
   ```

3. Both sides print a summary and exit. If the network drops, the sender
   reconnects by itself. If you stop either side (Ctrl-C), run the same
   commands again: completed files are skipped and partial files resume.

Files keep their names (`./photos` arrives as `~/incoming/photos`, like
`cp -r`), permission bits and modification times.

## Common recipes

```console
# Keep the code out of shell history and process listings
transporter send --code-file ~/code.txt ./project
echo "$CODE" | transporter send --code-file - ./project
TRANSPORTER_CODE="$CODE" transporter send ./project
transporter send ./project              # prompts for the code (no echo)

# A fixed port, e.g. for a firewall rule
transporter receive --port 4000 ./dest

# Listen on one interface only
transporter receive --bind 192.168.1.20 ./dest

# Replace files that already exist and differ
transporter receive --overwrite ./dest

# Compare by content hash instead of size and mtime
transporter send --verify CODE ./project

# Wait indefinitely for the sender / give up quickly on a dead network
transporter receive --idle-timeout 0 ./dest
transporter send --retry-timeout 1m CODE ./project
```

## Finding the receiver

The sender does not need the receiver's address: the code is enough. From
the code, both sides derive a short **discovery tag** (4 bytes; the code
itself is never sent). The receiver announces that tag, and the sender
looks for it in up to three ways, in order:

1. **mDNS** (up to 5 s): the receiver advertises a `_transporter._tcp`
   service on every multicast-capable interface, and the sender asks for
   it. This is how most home networks find the receiver.
2. **UDP sweep** (up to 3 s, only if mDNS found nothing): the sender sends
   a small UDP probe to port 29873 on every address of its own IPv4
   subnets, and to `127.0.0.1`. Only a receiver with the same tag answers.
   This helps on networks that drop multicast but pass unicast, such as
   some Wi-Fi and switched networks.
3. **`--to HOST:PORT`**, given by you: skips discovery entirely. Use it
   when both of the above are blocked, or the receiver is on another
   subnet.

Discovery runs once, at the start. After that the sender reconnects to the
same address, so a transfer in progress does not depend on mDNS. Because
the sender looks for its own tag, several receivers can run on one network
at the same time: each sender finds the receiver whose code it was given.

### Seeing what discovery does

Discovery is silent unless something goes wrong. Add `-v` to the sender to
see which receiver it found (log lines go to stderr):

```console
sender$ transporter send -v CODE ./photos
time=2026-11-21T19:37:31.490-08:00 level=INFO msg="found receiver" addr=192.168.1.20:44093
time=2026-11-21T19:37:31.493-08:00 level=INFO msg=connected receiver=192.168.1.20:44093
Summary: 1 file(s) sent (6 B), 0 already complete, 0 conflict(s), 0 error(s), 0 integrity failure(s), 0 retries, 0:01 elapsed
```

When mDNS is blocked, the sender waits out its 5 s and then sweeps:

```console
sender$ transporter send -v CODE ./photos
time=2026-11-21T19:37:43.849-08:00 level=INFO msg="mDNS found no receiver; sweeping the local network" udp-port=29873
time=2026-11-21T19:37:43.852-08:00 level=INFO msg="found receiver" addr=192.168.1.20:38369
...
```

When nothing answers within 8 s (5 s of mDNS and 3 s of sweep), the
sender exits with code 4 and says what to try. Nothing has been sent, and
the receiver keeps waiting, so you can rerun with `--to`:

```text
transporter: error: could not find the receiver on the local network within 8s: mDNS: no answer; UDP sweep: no answer
transporter: hint: use --to HOST:PORT with an address the receiver printed; mDNS is often blocked on guest and corporate networks; the UDP sweep needs UDP port 29873 open on the receiving machine and only reaches the local subnet
```

### Discovery recipes

```console
# mDNS never works on this network: go straight to the sweep (saves 5 s)
transporter send --no-mdns CODE ./photos

# Scanning is unwelcome here: use mDNS only, never sweep
transporter receive --no-sweep ~/incoming
transporter send --no-sweep CODE ./photos

# Port 29873 is taken or blocked: use another sweep port on both sides
transporter receive --sweep-port 40000 ~/incoming
transporter send --sweep-port 40000 CODE ./photos

# No discovery at all: the receiver announces nothing, and the sender
# uses an address the receiver printed (--to always skips discovery)
transporter receive --no-mdns --no-sweep ~/incoming
transporter send --to 192.168.1.20:41853 CODE ./photos

# Receiver and sender on the same machine: the sweep always probes
# 127.0.0.1, so this works even without mDNS
transporter send --no-mdns CODE ./photos
```

To make one of these the default, put the keys in the config file (see
[Config file](#config-file)), for example `no-sweep: true` under `send:`
and `receive:`.

### Firewalls

The receiving machine must accept these inbound connections:

| What | Protocol and port | Needed for |
| --- | --- | --- |
| The transfer | TCP, the port printed after `Listening on` (random unless you set `--port`) | Always |
| mDNS | UDP 5353 (multicast) | Discovery with mDNS |
| Sweep | UDP 29873 (or `--sweep-port`) | Discovery with the sweep |

For example, with a fixed transfer port of 4000:

```console
# firewalld (Fedora, RHEL)
sudo firewall-cmd --add-service=mdns --add-port=29873/udp --add-port=4000/tcp

# ufw (Ubuntu)
sudo ufw allow mdns && sudo ufw allow 29873/udp && sudo ufw allow 4000/tcp

receiver$ transporter receive --port 4000 ~/incoming
```

The firewalld rules last until the next reload; add `--permanent` (and run
`sudo firewall-cmd --reload`) to keep them. Open only the ones you use:
with `--to`, only the TCP port is needed.

### Limits

- Discovery reaches the local network only. mDNS does not cross routers,
  and the sweep covers the sender's own subnets (at most the /22 around
  its address, 4,096 addresses in all). For a receiver on another subnet
  or over a VPN, use `--to`.
- The sweep is IPv4 only. mDNS covers IPv6, and `--to` accepts
  `[IPv6]:PORT`.
- Only one receiver per machine can answer the sweep, because it needs the
  fixed UDP port. A second receiver on the same machine warns
  `cannot answer the UDP sweep; senders must use mDNS or --to` and can
  still be found with mDNS, or reached with `--to`.
- Discovery answers are not trusted: a spoofed answer can only point the
  sender at a machine that cannot complete the encrypted handshake, which
  then fails as an authentication error. See
  [docs/security.md](docs/security.md).

## Receiver output

The receiver prints to **stdout**, in this stable format (one `Listening
on` line per usable address, then the code):

```text
Listening on HOST:PORT
Code: WORD-WORD-WORD-WORD-WORD-WORD-WORD-WORD-WORD
```

Everything else (logs, progress, summary) goes to **stderr**.

## Flags

`transporter receive [flags] [DEST]` (DEST defaults to the current
directory and is created if missing):

| Flag | Default | Meaning |
| --- | --- | --- |
| `--port N` | `0` (random free port) | TCP port to listen on. |
| `--bind ADDR` | all interfaces | Address to listen on. All interfaces is deliberate: senders elsewhere on the LAN must reach it. |
| `--overwrite` | off | Replace existing files that differ. Without it they are kept and reported as conflicts. |
| `--verify` | off | Compare by BLAKE3 hash instead of size and mtime. Either side can enable it. |
| `--idle-timeout DUR` | `10m` | Give up after this long without sender activity; `0` waits forever. |
| `--no-mdns` | off | Do not advertise on the local network with mDNS. |
| `--no-sweep` | off | Do not answer senders' UDP sweep probes. |
| `--sweep-port N` | `29873` | UDP port to answer the sweep on (IPv4 only). |

`transporter send [flags] [CODE] PATH...`:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--to HOST:PORT` | discover with mDNS, then the UDP sweep | Receiver address. Always takes precedence over discovery. |
| `--code-file PATH` | not used | Read the code from the first line of PATH (`-` = stdin). |
| `--retry-timeout DUR` | `10m` | How long to keep retrying without progress; `0` disables retries. |
| `--verify` | off | As for receive. |
| `--no-mdns` | off | Do not use mDNS. |
| `--no-sweep` | off | Do not sweep the local subnet when mDNS finds nothing. With `--no-mdns`, requires `--to`. |
| `--sweep-port N` | `29873` | UDP port of the sweep; must match the receiver's. |

Global flags: `-v`/`--verbose` (repeat for debug output), `--config PATH`
(see below), `--version`, `-h`/`--help` (also `transporter send --help`).

The code is recognized as the first argument only if it is a complete valid
code; otherwise every argument is a path, and the code must come from
`--code-file`, `TRANSPORTER_CODE` or the prompt.

### Config file

You can set your own defaults for any flag except the code in a config
file. Transporter reads `transporter/config.yaml` from your user config
directory if it exists:

| OS | Default location |
| --- | --- |
| Linux | `~/.config/transporter/config.yaml` (or `$XDG_CONFIG_HOME/transporter/config.yaml`) |
| macOS | `~/Library/Application Support/transporter/config.yaml` |
| Windows | `%AppData%\transporter\config.yaml` |

Or name another file with `--config PATH` (YAML, with a `.yaml` or `.yml`
extension). Keys are the flag names without `--`, under `send:` or
`receive:`; only `verbose` goes at the top level:

```yaml
verbose: 1
send:
  retry-timeout: 30m
  verify: true
receive:
  port: 4000
  idle-timeout: 1h
  no-mdns: true
  no-sweep: true
```

A flag on the command line always wins over the file (for example
`--verify=false`), and the file wins over the built-in defaults. Values are
checked exactly as on the command line, and errors give the line number.
An unknown or repeated key is an error, so a typo is reported rather than
ignored. The code (and `code-file`) cannot be
set in the file. On Linux and macOS the file must not be writable by other
users (`chmod go-w`), because settings like `overwrite` change what a
transfer does.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Internal error, or a protocol error (for example different versions) |
| 2 | Usage error |
| 3 | Authentication failure (wrong code, or a different receiver) |
| 4 | Network failure or timeout (retry budget spent, idle timeout, discovery failed) |
| 5 | Filesystem error on the receiver (not writable, out of space) |
| 6 | Integrity failure (a file failed its hash check after a retransmission) |
| 7 | Partial success (conflicts or per-file errors; listed in the summary) |
| 130 | Interrupted by a signal (Ctrl-C) |

When several apply, the most serious wins: 3, 5, 6, 4, 7, then 0. Warnings,
such as skipped symlinks, are listed but do not change the exit code.

## Troubleshooting

- **"could not find the receiver on the local network"**: mDNS is often
  blocked on guest, corporate and some home networks, and by host firewalls.
  The sender then sweeps its local subnets (up to 1,022 addresses each,
  4,096 in all) with UDP probes for 3 s, which needs inbound UDP port 29873
  open on the receiving machine and both machines on the same subnet. Otherwise, use
  `--to HOST:PORT` with an address the receiver printed. On networks where
  scanning is unwelcome, turn the sweep off with `--no-sweep` or
  `no-sweep: true` in the config file. See
  [Finding the receiver](#finding-the-receiver) for examples and the
  firewall ports.
- **The sender cannot connect (connection refused or timed out)**: check
  the address and port, that both machines are on the same network, and
  that a firewall allows inbound TCP to the receiver's port. Use `--port`
  to choose a fixed port you can open.
- **"authentication failed"**: the code is wrong, or the address belongs to
  a different receiver run (every run has a new code). Check the code the
  receiver is showing now.
- **"the receiver is busy"**: another sender is transferring to that
  receiver. Wait for it to finish, or start another receiver.
- **Resuming**: just run the same commands again. Completed files are
  recognized by size and modification time (or by hash with `--verify`);
  `NAME.part` files hold partial data and are continued. A `.part` file
  for a name that is no longer being sent is left alone and, if it is in
  the destination's top level or under a path being sent, listed in the
  summary.
- **Conflicts**: an existing file that differs is not replaced unless the
  receiver runs with `--overwrite`.
- **More detail**: add `-v` or `-v -v`. Logs never contain the code.

## Platform notes

- Linux, macOS and Windows on amd64 and arm64.
- **Symlinks, device files, FIFOs and sockets** are skipped with a warning
  (never followed). Names that cannot be sent (invalid UTF-8, a backslash
  or NUL in the name) are skipped with a warning.
- **Names that differ only in case or Unicode normalization** (`README` and
  `readme`) cannot be sent together, because they would collide on
  case-insensitive filesystems.
- **Directory permissions and modification times** are not copied in this
  version; directories are created `0755` (subject to the umask). File
  permission bits are copied (`& 0777`, never setuid, setgid or sticky).
- **Windows**: permission bits map only to the read-only attribute
  (best effort). Names Windows cannot store (`CON`, `aux.txt`, trailing
  dots or spaces, `<>:"|?*`) are reported as per-file errors on a Windows
  receiver. Directory fsync is not available, so a power loss right after a
  rename is slightly less safe than on Unix.
- **Files changed while being sent** are reported as errors and not
  completed. Run again to send the new version.
- Memory use does not grow with file size. Very large trees use memory in
  proportion to the number of entries (up to 1,000,000 per transfer).

More: [architecture](docs/architecture.md), [protocol](docs/protocol.md),
[security](docs/security.md), [testing](docs/testing.md),
[decisions](docs/DECISIONS.md).

## Security

Transporter has **not been independently audited**. The receiver learns the
names, sizes and times of the files it receives. Read
[docs/security.md](docs/security.md) for the threat model, and
[SECURITY.md](SECURITY.md) to report a vulnerability.

## License

Copyright © 2026 Ned McHugh.

Transporter is licensed under the **Mozilla Public License 2.0**
([LICENSE](LICENSE)). MPL-2.0 is a file-level copyleft: you may combine
Transporter with code under other licenses, but modifications to
MPL-covered files must stay under MPL-2.0 and be made available in source
form when you distribute them. Third-party components and their licenses
are listed in [THIRD_PARTY_LICENSES](THIRD_PARTY_LICENSES). Contributions
are accepted under the same license; see [CONTRIBUTING.md](CONTRIBUTING.md).
Attribution for the project is in [NOTICE](NOTICE).

Transporter is provided "as is", without warranty of any kind. See sections
6 (Disclaimer of Warranty) and 7 (Limitation of Liability) of the
[license](LICENSE).

## Export notice

This software contains cryptographic functionality, which may be subject to
export control and other laws in some jurisdictions (for example the United
States Export Administration Regulations). This notice is not legal advice
and does not state a classification. The maintainer is responsible for
determining and meeting any obligations before distributing the software;
users are responsible for compliance in their own jurisdictions.

## Not affiliated

Transporter is not affiliated with, endorsed by, or connected to the owners
of the Star Trek franchise.
