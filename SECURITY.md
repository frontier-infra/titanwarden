# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's private vulnerability
reporting: open the repository's Security tab and choose "Report a
vulnerability". Do not open a public issue, pull request or discussion for a
security problem.

Include what you found, how to reproduce it, the version or commit, and the
impact you expect. Never include a real secret value in a report.

We aim to acknowledge a report within 3 business days and to agree on a fix
and disclosure timeline with you.

## Scope

In scope: the broker, the `tw` and `twadmin` clients, the store and its
encryption, the redaction path, the optional web console, the install
scripts and the service units in this repository.

The boundaries Titanwarden does and does not claim are in
[docs/threat-model.md](docs/threat-model.md). For example, a process the
broker launches can read its own injected environment. Reports that show a
claimed boundary failing are the most valuable.

## Supported versions

Security fixes go to the latest release on the default branch.
