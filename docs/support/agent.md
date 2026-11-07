# Agent guide

You can use a credential through Titanwarden, but you cannot read its value.
The broker starts the child process and injects the requested value through an
environment variable, a pipe file descriptor, or standard input. Prefer file
descriptors or standard input when the target tool supports them.

## Use

```sh
tw run --env API_TOKEN=project/name -- command argument
tw run --fd 3=project/name -- command --token-file /dev/fd/3
tw run --stdin project/name -- command --token-stdin
tw run --soft OPTIONAL_TOKEN=project/name -- command
tw inject --manifest .env.tw -- command
```

A manifest line is either `VARIABLE=tw://project/name` or a non-secret literal.
Manifests are safe to commit after review.

`tw run` has no pseudo-terminal in v0. Interactive programs are unsupported.
The process runs in a new process group under the broker LaunchAgent. macOS
privacy permissions can therefore differ from the calling pane. Closing the
client ends its child. Broker restart also ends children and returns sealed.

The broker preserves the submitted working directory, `PATH`, and ordinary
environment variables, including helper sockets. It removes every incoming
`TW_*` variable and supplies only the lease marker it owns. `--fd` values never
enter the child environment. `--stdin` supplies the value and then EOF instead
of forwarding the caller's standard input.

Use `--soft` only for work that can genuinely continue without the variable.
If the broker is sealed or frozen, the child starts without soft variables. If
the broker is unreachable and every reference is soft, the local client starts
the command, prints a names-only notice, and cannot write an audit event. A
denied soft reference still fails.

## Output and failures

`[tw:project/name]` means output matched a stored value inside your effective
permission. `[tw:redacted]` means it matched a value outside that permission.
Redaction is a guardrail and does not cover arbitrary transformations.
It covers raw values, standard and URL-safe base64, hex, percent encoding,
JSON escaping, and stable base64 cores. It scans active and grace values from
the whole store, not only values injected into the current child. A guessed
low-entropy value can therefore reveal that some stored value matched, without
revealing its path. Treat this as an accepted oracle, not a security boundary.

- `E_SEALED` or `E_FROZEN`: continue with other work and retry later.
- `E_DENIED`: request access with a concrete reason.
- Exit 78: a worker waits 60 seconds and retries once, then tells its lead. A
  lead asks the master to issue or repair its token and pane binding.
- Suspected token leak: run `tw token revoke-self`, then request rotation of any
  affected provider credential.

A nested `tw` call made by a script under `tw run` stays bound to the parent
lease. It cannot issue tokens, make requests, or grant access, and it cannot
reach beyond the parent principal's effective permission.

Useful names-only operations include `tw status`, `tw names`, `tw who-touched`,
and `tw dependents`. Use `tw request access PATH --ops inject --reason TEXT`
for missing scope. A lead issues a worker credential with `tw task-token issue
--dispatch ID --scope SCOPE`; the broker writes the token and pane binding, and
the token value is never returned by the command.

When coordinating, send only paths, token ids, lease ids, request ids, version
numbers, and audit sequence numbers. Never send values.
