"""Titanwarden agent command line client."""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Sequence

from .protocol import (
    ERROR_EXIT_CODES,
    PROTOCOL_VERSION,
    recv_frame,
    send_frame,
    send_frame_with_fds,
)


class CliError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _home() -> Path:
    return Path(os.environ.get("TW_HOME", "~/.titanwarden")).expanduser()


def resolve_identity(home: Path, environment: dict[str, str]) -> tuple[str | None, str | None]:
    token_file = environment.get("TW_TOKEN_FILE")
    if token_file:
        try:
            return Path(token_file).read_text(encoding="ascii").strip(), None
        except (OSError, UnicodeError) as exc:
            raise CliError("E_NO_IDENTITY", "tw: token file is unavailable") from exc
    lease = environment.get("TW_LEASE")
    if lease:
        return None, lease
    handle = environment.get("ORCA_TERMINAL_HANDLE")
    if handle:
        if not all(character.isalnum() or character in "_-" for character in handle):
            raise CliError("E_NO_IDENTITY", "tw: no identity for this pane")
        pointer = home / "panes" / handle
        if pointer.exists():
            try:
                path = Path(pointer.read_text(encoding="utf-8").strip())
                return path.read_text(encoding="ascii").strip(), None
            except (OSError, UnicodeError) as exc:
                raise CliError("E_NO_IDENTITY", "tw: pane binding is unavailable") from exc
    raise CliError(
        "E_NO_IDENTITY",
        "tw: no identity for this pane. Workers: ask your lead to run "
        "'tw task-token issue --dispatch <id>'. Leads: ask the master to run "
        "'tw token issue --principal lead:<id>'.",
    )


def _context(lease: str | None = None, job: str | None = None) -> dict[str, Any]:
    return {
        "cwd": os.getcwd(),
        "pid": os.getpid(),
        "argv0": sys.argv[0],
        "job": job,
        "orca_terminal": os.environ.get("ORCA_TERMINAL_HANDLE"),
        "orca_run": os.environ.get("ORCA_RUN_ID"),
        "dispatch": os.environ.get("ORCA_DISPATCH_ID"),
        "lease": lease,
    }


def _request(op: str, args: dict[str, Any], *, job: str | None = None) -> dict[str, Any]:
    token = None
    lease = None
    if op != "hello":
        token, lease = resolve_identity(_home(), dict(os.environ))
    return {
        "v": PROTOCOL_VERSION,
        "op": op,
        "request_id": str(uuid.uuid4()),
        "token": token,
        "args": args,
        "ctx": _context(lease, job),
    }


def _connect() -> socket.socket:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(str(_home() / "run" / "tw.sock"))
    return client


def _safe_output(value: object) -> None:
    rendered = json.dumps(value, sort_keys=True, ensure_ascii=False)
    if "twt_" in rendered:
        raise CliError("E_INTEGRITY", "tw: unsafe response refused")
    print(rendered)


def _handle_response(response: dict[str, Any], *, as_json: bool = True) -> dict[str, Any]:
    if not response.get("ok"):
        raise CliError(str(response.get("code", "E_BAD_REQUEST")), str(response.get("error", "tw: request failed")))
    result = response.get("result", {})
    if not isinstance(result, dict):
        raise CliError("E_BAD_REQUEST", "tw: invalid broker response")
    if as_json:
        _safe_output(result)
    return result


def _call(op: str, args: dict[str, Any], *, fds: Sequence[int] = (), as_json: bool = True):
    try:
        with _connect() as client:
            request = _request(op, args, job=args.get("job"))
            send_frame_with_fds(client, request, fds)
            return _handle_response(recv_frame(client), as_json=as_json)
    except CliError:
        raise
    except (OSError, EOFError) as exc:
        raise CliError("E_UNREACHABLE", "tw: broker unreachable") from exc


def _parse_assignment(value: str, label: str) -> tuple[str, str]:
    left, separator, right = value.partition("=")
    if not separator or not left or not right:
        raise CliError("E_USAGE", f"tw: invalid {label} assignment")
    return left, right


def _run_command(namespace: argparse.Namespace) -> int:
    env_refs = dict(_parse_assignment(item, "environment") for item in namespace.env)
    soft_refs = dict(_parse_assignment(item, "soft") for item in namespace.soft)
    fd_refs = {
        int(number): path for number, path in (_parse_assignment(item, "fd") for item in namespace.fd)
    }
    if any(number < 3 for number in fd_refs):
        raise CliError("E_USAGE", "tw: secret fd must be at least 3")
    command = list(namespace.command)
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        raise CliError("E_USAGE", "tw: command required after --")
    args = {
        "argv": command,
        "cwd": os.getcwd(),
        "environment": dict(os.environ),
        "env_refs": env_refs,
        "fd_refs": {str(key): value for key, value in fd_refs.items()},
        "stdin_ref": namespace.stdin_ref,
        "soft_refs": soft_refs,
        "manifest": namespace.manifest,
        "job": namespace.job,
        "client_fds": {"stdin": 0, "stdout": 1, "stderr": 2},
    }
    try:
        client = _connect()
    except OSError:
        hard_refs = bool(env_refs or fd_refs or namespace.stdin_ref or namespace.manifest)
        if hard_refs or not soft_refs:
            raise CliError("E_UNREACHABLE", "tw: broker unreachable")
        names = ", ".join(sorted(soft_refs))
        print(f"tw: broker unreachable; {names} not set", file=sys.stderr)
        environment = {key: value for key, value in os.environ.items() if not key.startswith("TW_")}
        return subprocess.call(command, cwd=os.getcwd(), env=environment)
    with client:
        request = _request("run", args, job=namespace.job)
        send_frame_with_fds(client, request, [0, 1, 2])
        previous = {}

        def forward(signum, _frame):
            names = {
                signal.SIGINT: "INT",
                signal.SIGTERM: "TERM",
                signal.SIGHUP: "HUP",
            }
            send_frame(
                client,
                {
                    "v": PROTOCOL_VERSION,
                    "op": "signal",
                    "request_id": str(uuid.uuid4()),
                    "token": None,
                    "args": {"sig": names[signum]},
                    "ctx": _context(request["ctx"].get("lease"), namespace.job),
                },
            )

        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            previous[signum] = signal.signal(signum, forward)
        try:
            started = _handle_response(recv_frame(client), as_json=False)
            lease_id = started.get("lease_id")
            if lease_id:
                request["ctx"]["lease"] = lease_id
            finished = _handle_response(recv_frame(client), as_json=False)
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)
        return int(finished.get("exit_code", 0))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tw")
    subparsers = parser.add_subparsers(dest="verb", required=True)
    status = subparsers.add_parser("status")
    status.add_argument("--json", action="store_true")
    names = subparsers.add_parser("names")
    names.add_argument("project", nargs="?")
    for verb in ("run", "inject"):
        command = subparsers.add_parser(verb)
        command.add_argument("--env", action="append", default=[])
        command.add_argument("--fd", action="append", default=[])
        command.add_argument("--stdin", dest="stdin_ref")
        command.add_argument("--soft", action="append", default=[])
        command.add_argument("--manifest")
        command.add_argument("--job")
        command.add_argument("command", nargs=argparse.REMAINDER)
    put = subparsers.add_parser("put")
    put.add_argument("path")
    put.add_argument("--class", dest="secret_class", default="sensitive")
    put.add_argument("--kind", default="opaque")
    put.add_argument("--note")
    put.add_argument("--generate", type=int)
    put.add_argument("--charset", choices=("alnum", "urlsafe", "hex"), default="urlsafe")
    put.add_argument("--prompt", action="store_true")
    importer = subparsers.add_parser("import")
    import_sub = importer.add_subparsers(dest="import_kind", required=True)
    env_import = import_sub.add_parser("env")
    env_import.add_argument("path")
    env_import.add_argument("--project", required=True)
    request = subparsers.add_parser("request")
    request_sub = request.add_subparsers(dest="request_kind", required=True)
    access = request_sub.add_parser("access")
    access.add_argument("target")
    access.add_argument("--ops", required=True)
    access.add_argument("--reason", required=True)
    access.add_argument("--ttl")
    for kind in ("create", "rotate"):
        item = request_sub.add_parser(kind)
        item.add_argument("target")
        item.add_argument("--reason", required=True)
    for action in ("approve", "deny"):
        item = request_sub.add_parser(action)
        item.add_argument("target")
        item.add_argument("--reason", required=True)
    task = subparsers.add_parser("task-token")
    task_sub = task.add_subparsers(dest="task_action", required=True)
    issue = task_sub.add_parser("issue")
    selector = issue.add_mutually_exclusive_group(required=True)
    selector.add_argument("--dispatch")
    selector.add_argument("--task")
    issue.add_argument("--scope", required=True)
    issue.add_argument("--ttl", default="8h")
    revoke = task_sub.add_parser("revoke")
    revoke.add_argument("token_id")
    token = subparsers.add_parser("token")
    token_sub = token.add_subparsers(dest="token_action", required=True)
    revoke_self = token_sub.add_parser("revoke-self")
    revoke_self.add_argument("--reason", default="self revocation")
    token_issue = token_sub.add_parser("issue")
    token_issue.add_argument("--principal", required=True)
    for verb in ("who-touched", "dependents"):
        item = subparsers.add_parser(verb)
        item.add_argument("path")
        item.add_argument("--n", type=int, default=10)
        item.add_argument("--json", action="store_true")
    roster = subparsers.add_parser("roster")
    roster.add_subparsers(dest="roster_action", required=True).add_parser("sync")
    grant = subparsers.add_parser("grant")
    grant_sub = grant.add_subparsers(dest="grant_action", required=True)
    grant_add = grant_sub.add_parser("add")
    grant_add.add_argument("principal")
    grant_add.add_argument("scope")
    grant_add.add_argument("--reason", required=True)
    grant_add.add_argument("--ttl")
    grant_rm = grant_sub.add_parser("rm")
    grant_rm.add_argument("grant_id")
    grant_rm.add_argument("--reason", required=True)
    for verb in ("freeze", "unfreeze", "panic-seal"):
        item = subparsers.add_parser(verb)
        item.add_argument("--reason", required=True)
    help_parser = subparsers.add_parser("help")
    help_parser.add_argument("topic", choices=("agent",))
    return parser


def _dispatch(namespace: argparse.Namespace) -> int:
    if namespace.verb in {"run", "inject"}:
        return _run_command(namespace)
    if namespace.verb == "help":
        path = Path(__file__).parents[1] / "docs" / "support" / "agent.md"
        print(path.read_text(encoding="utf-8"), end="")
        return 0
    if namespace.verb == "status":
        try:
            result = _call("status", {}, as_json=namespace.json)
        except CliError as exc:
            if exc.code != "E_NO_IDENTITY":
                raise
            result = _call("hello", {}, as_json=namespace.json)
        if not namespace.json:
            for key in sorted(result):
                print(f"{key}: {result[key]}")
        return 0
    if namespace.verb == "names":
        _call("names", {"project": namespace.project})
    elif namespace.verb == "put":
        if namespace.generate is not None:
            _call(
                "generate",
                {
                    "path": namespace.path,
                    "length": namespace.generate,
                    "charset": namespace.charset,
                    "class": namespace.secret_class,
                    "kind": namespace.kind,
                    "note": namespace.note,
                },
            )
        else:
            if sys.stdin.isatty() and not namespace.prompt:
                raise CliError("E_USAGE", "tw: refusing a TTY stdin without --prompt")
            if namespace.prompt:
                import getpass

                read_fd, write_fd = os.pipe()
                value = getpass.getpass("Value: ").encode()
                os.write(write_fd, value)
                os.close(write_fd)
                try:
                    _call(
                        "put",
                        {
                            "path": namespace.path,
                            "class": namespace.secret_class,
                            "kind": namespace.kind,
                            "note": namespace.note,
                            "value_fd": 0,
                        },
                        fds=[read_fd],
                    )
                finally:
                    os.close(read_fd)
            else:
                _call(
                    "put",
                    {
                        "path": namespace.path,
                        "class": namespace.secret_class,
                        "kind": namespace.kind,
                        "note": namespace.note,
                        "value_fd": 0,
                    },
                    fds=[0],
                )
    elif namespace.verb == "import":
        _call("import_env", {"path": namespace.path, "project": namespace.project})
    elif namespace.verb == "request":
        if namespace.request_kind in {"approve", "deny"}:
            _call(
                "request_decide",
                {
                    "request_id": namespace.target,
                    "decision": namespace.request_kind,
                    "reason": namespace.reason,
                },
            )
        else:
            _call(
                "request",
                {
                    "kind": namespace.request_kind,
                    "target": namespace.target,
                    "ops": getattr(namespace, "ops", None),
                    "reason": namespace.reason,
                    "ttl": getattr(namespace, "ttl", None),
                },
            )
    elif namespace.verb == "task-token":
        if namespace.task_action == "issue":
            _call(
                "task_token_issue",
                {
                    "dispatch": namespace.dispatch,
                    "task": namespace.task,
                    "scope": namespace.scope,
                    "ttl": namespace.ttl,
                },
            )
        else:
            _call("task_token_revoke", {"token_id": namespace.token_id})
    elif namespace.verb == "token":
        if namespace.token_action == "issue":
            _call("token_issue", {"principal": namespace.principal})
        else:
            _call("token_revoke_self", {"reason": namespace.reason})
    elif namespace.verb == "who-touched":
        _call("who_touched", {"path": namespace.path, "n": namespace.n})
    elif namespace.verb == "dependents":
        _call("dependents", {"path": namespace.path})
    elif namespace.verb == "roster":
        _call("roster_sync", {})
    elif namespace.verb == "grant":
        if namespace.grant_action == "add":
            _call(
                "grant_add",
                {
                    "principal": namespace.principal,
                    "scope": namespace.scope,
                    "reason": namespace.reason,
                    "ttl": namespace.ttl,
                },
            )
        else:
            _call("grant_rm", {"grant_id": namespace.grant_id, "reason": namespace.reason})
    elif namespace.verb in {"freeze", "unfreeze", "panic-seal"}:
        _call(namespace.verb.replace("-", "_"), {"reason": namespace.reason})
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return _dispatch(_parser().parse_args(argv))
    except CliError as exc:
        message = str(exc)
        if "twt_" in message:
            message = "tw: unsafe error refused"
        print(message if message.startswith("tw:") else "tw: " + message, file=sys.stderr)
        return ERROR_EXIT_CODES.get(exc.code, 70)
    except (OSError, EOFError):
        print("tw: broker unreachable", file=sys.stderr)
        return ERROR_EXIT_CODES["E_UNREACHABLE"]


if __name__ == "__main__":
    raise SystemExit(main())
