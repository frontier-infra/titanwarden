# Titanwarden

Titanwarden is a local secret broker for machines where AI agents work: use,
never see. An agent names a secret and a command. The broker checks which
process is asking, writes the audit row first, starts the command with the
value injected, and redacts the value from anything that tries to leave. The
agent protocol has no operation that returns plaintext.

- One encrypted SQLite store per machine (AES-256-GCM values, Argon2id
  passphrase and recovery slots).
- Every restart starts sealed. A human unseals.
- Every use is audited: who, which secret, which version, when.
- macOS and Linux, Python 3.12 or newer.

Titanwarden is open source under the [Apache License 2.0](LICENSE). It is a
[Frontier Infra](https://frontierinfra.org) project. Website and guide:
[titanwarden.com](https://www.titanwarden.com).

## Install

You need macOS or Linux, Python 3.12 or newer, [uv](https://docs.astral.sh/uv/),
and SSH from a device you trust. The first setup is human-only.

```sh
git clone https://github.com/frontier-infra/titanwarden && cd titanwarden
uv sync --frozen && scripts/install.sh
twadmin init      # over SSH from your own device
twadmin unseal && tw status
```

`scripts/install.sh` creates the home (`~/.titanwarden` on macOS,
`/data/titanwarden` on Linux, or `TW_HOME` if set), builds a release, links
`tw` and `twadmin` into `~/bin`, and loads three jobs: the broker, a 60 second
watch and a daily backup. On macOS these are LaunchAgents from `launchd/`. On
Linux they are system units from `systemd/` that run as the installing
account, and `/etc/profile.d/titanwarden.sh` exports `TW_HOME` for SSH
sessions.

`twadmin init` asks for a passphrase twice (at least 30 characters) and prints
the recovery key once. Record it offline. Then `twadmin unseal` opens the
vault and the broker serves agents.

Do not let an agent run `twadmin init`, `unseal`, recovery rotation or reveal.
If you hand the install to an agent, let it run `uv sync --frozen` and
`scripts/install.sh`, then stop.

## Use

```sh
twadmin put infra/github                       # a human adds a value
tw run --env GITHUB_TOKEN=infra/github -- gh pr create
tw names infra                                 # names and versions, never values
tw who-touched infra/github                    # the audit trail for one secret
```

See [docs/guide.md](docs/guide.md) for the full guide,
[docs/support/agent.md](docs/support/agent.md) for agent usage and
[docs/threat-model.md](docs/threat-model.md) for boundaries and guardrails.

## Operating model

- `tw.sock` serves the closed agent operation set.
- `admin.sock` serves human operations after passphrase authentication.
- `tw.db` holds ciphertext, wrapped keys, token hashes, metadata and audit.
- Every restart starts sealed. After a restart, unseal with `twadmin unseal`
  over SSH, or with the passphrase form on the optional web console.
- `FREEZE` latches agent operations off until an authorized unfreeze.
- Panic seal enters lockdown. A passphrase-authenticated clear is required.
- Backups use SQLite's online backup API and include a names-only manifest.

The broker has an optional hook for an external approval tool (a `desk`
command on `PATH`). Without it, requests wait for the operator in `twadmin`.
The display name whose answers count as decisions is set by
`TW_DESK_OPERATOR` (default `Operator`).

## Development

```sh
uv sync --frozen
uv run python -m unittest discover -s tests -v
```

Tests always use a short temporary `TW_HOME` under `/tmp`. Never point
development commands at a live store.

## License

Copyright 2026 Frontier Infra contributors.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
