# Security policy

## Reporting a vulnerability

Please report vulnerabilities **privately**:

- Use GitHub's private vulnerability reporting: the repository's
  **Security** tab, then **Report a vulnerability**.
- Or contact the maintainer at MAINTAINER-CONTACT (placeholder for the
  maintainer to fill in).

Please do not open a public issue for a vulnerability. Never include a
pairing code, or files you would not want published, in a report.

Include the version (`transporter --version`), platforms, what you did,
what happened, and why it is a security problem. We aim to acknowledge
reports within 7 days and to agree on a disclosure date once a fix is
ready.

## Supported versions

Security fixes are made for the latest release.

## Scope and design

The threat model, cryptographic design and known limitations are in
[docs/security.md](docs/security.md). Transporter has **not been
independently audited**.
