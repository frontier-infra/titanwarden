"""Titanwarden human console client."""

from __future__ import annotations

import argparse
import ctypes
import getpass
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import warnings
from pathlib import Path
from typing import Any

from .protocol import exit_code_for, recv_frame, send_frame_with_fds


SENSITIVE_SCREEN_OPS = {"init", "reveal", "recovery-rotate", "import-bitwarden"}


def human_context_allowed(
    op: str,
    *,
    environ: dict[str, str] | None = None,
    process_listing: str | None = None,
) -> bool:
    env = dict(os.environ if environ is None else environ)
    if env.get("ORCA_TERMINAL_HANDLE"):
        return False
    if op not in SENSITIVE_SCREEN_OPS or env.get("SSH_CONNECTION"):
        return True
    if process_listing is None:
        process_listing = subprocess.run(
            ["/bin/ps", "-axo", "command="], capture_output=True, text=True, check=False,
            env={"PATH": "/usr/bin:/bin"}
        ).stdout
    lowered = process_listing.lower()
    return not any(marker in lowered for marker in ("orca", "claude", "codex"))


def peer_pid(sock: socket.socket) -> int | None:
    if sys.platform == "darwin":
        try:
            data = sock.getsockopt(getattr(socket, "SOL_LOCAL", 0), 2, 4)
            return struct.unpack("i", data)[0]
        except OSError:
            return None
    if hasattr(socket, "SO_PEERCRED"):
        try:
            data = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            return struct.unpack("3i", data)[0]
        except OSError:
            return None
    return None


def launchd_broker_pid() -> int | None:
    completed = subprocess.run(
        ["/bin/launchctl", "print", f"gui/{os.getuid()}/org.frontierinfra.titanwarden"],
        capture_output=True,
        text=True,
        check=False,
        env={"PATH": "/usr/bin:/bin"},
    )
    if completed.returncode != 0:
        return None
    match = re.search(r"^\s*pid\s*=\s*(\d+)\s*$", completed.stdout, re.MULTILINE)
    return None if match is None else int(match.group(1))


def systemd_broker_pid() -> int | None:
    # System unit with User=sem, so no user bus is needed to read the pid.
    completed = subprocess.run(
        ["/usr/bin/systemctl", "show", "-p", "MainPID", "--value", "titanwarden.service"],
        capture_output=True,
        text=True,
        check=False,
        env={"PATH": "/usr/bin:/bin"},
    )
    if completed.returncode != 0:
        return None
    try:
        pid = int(completed.stdout.strip())
    except ValueError:
        return None
    return pid or None


PROC = Path("/proc")


def proc_cmdline(pid: int) -> list[str] | None:
    try:
        raw = (PROC / str(pid) / "cmdline").read_bytes()
    except OSError:
        return None
    if not raw.endswith(b"\0"):
        return None
    return [part.decode("utf-8", "surrogateescape") for part in raw[:-1].split(b"\0")]


def service_broker_pid() -> int | None:
    """The broker pid as the init system reports it: launchd on macOS, systemd on Linux."""
    return launchd_broker_pid() if sys.platform == "darwin" else systemd_broker_pid()


def broker_argv(pid: int) -> list[str] | None:
    return kern_procargs2(pid) if sys.platform == "darwin" else proc_cmdline(pid)


def kern_procargs2(pid: int) -> list[str] | None:
    if sys.platform != "darwin":
        return None
    libc = ctypes.CDLL(None, use_errno=True)
    mib = (ctypes.c_int * 3)(1, 49, pid)
    size = ctypes.c_size_t()
    if libc.sysctl(mib, 3, None, ctypes.byref(size), None, 0) != 0 or size.value < 5:
        return None
    buffer = ctypes.create_string_buffer(size.value)
    if libc.sysctl(mib, 3, buffer, ctypes.byref(size), None, 0) != 0:
        return None
    raw = buffer.raw[: size.value]
    argc = struct.unpack_from("i", raw)[0]
    offset = 4
    executable_end = raw.find(b"\0", offset)
    if argc <= 0 or executable_end < 0:
        return None
    offset = executable_end + 1
    while offset < len(raw) and raw[offset] == 0:
        offset += 1
    argv: list[str] = []
    for _ in range(argc):
        end = raw.find(b"\0", offset)
        if end < 0:
            return None
        argv.append(raw[offset:end].decode("utf-8", "surrogateescape"))
        offset = end + 1
    return argv


def verify_broker_peer(sock: socket.socket, home: Path) -> bool:
    pid = peer_pid(sock)
    if pid is None or pid <= 1 or pid != service_broker_pid():
        return False
    argv = broker_argv(pid)
    if argv is None or len(argv) < 5 or (len(argv) - 1) % 2:
        return False
    arguments = {}
    for index in range(1, len(argv), 2):
        flag, value = argv[index:index + 2]
        if flag in arguments:
            return False
        arguments[flag] = value
    resolved_home = home.expanduser().resolve()
    expected = {"-m": "tw.broker", "--home": str(resolved_home)}
    # Desk values configure the pinned process; they do not authenticate it.
    # Require the complete pair, without assuming master/master or flag order.
    desk_flags = {"--desk-identity", "--desk-project"}
    if desk_flags.intersection(arguments):
        if not desk_flags.issubset(arguments):
            return False
        expected.update({flag: arguments[flag] for flag in desk_flags})
    console_flags = {"--console-config", "--console-rp-id", "--console-user"}
    if console_flags.intersection(arguments):
        if not console_flags.issubset(arguments):
            return False
        rp_id, user = arguments["--console-rp-id"], arguments["--console-user"]
        if (not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.[a-z0-9-]+\.ts\.net", rp_id)
                or not 1 <= len(user) <= 254 or not all(33 <= ord(c) <= 126 for c in user)):
            return False
        expected.update({"--console-config": str(resolved_home / "console" / "config.json"),
                         "--console-rp-id": rp_id, "--console-user": user})
    # Exact flag set and values, including -m; unknown flags never broaden trust.
    # Keep this contract checked against the shipped launchd plist regression.
    return arguments == expected


def read_put_value() -> bytes:
    if sys.stdin.isatty():
        return getpass.getpass("Secret value: ").encode("utf-8")
    value = sys.stdin.buffer.read()
    return value[:-1] if value.endswith(b"\n") else value


def operator_tty() -> str:
    """The real terminal device, never /dev/tty.

    The broker writes the recovery key through the descriptor we pass it. It
    runs under launchd with no controlling terminal, and /dev/tty resolves to
    the controlling terminal of whoever writes, so from the broker it fails
    with EIO. The named pty (for example /dev/ttys003) works from any process.
    """
    for fd in (0, 1, 2):
        try:
            return os.ttyname(fd)
        except OSError:
            continue
    raise RuntimeError("twadmin: this command needs a terminal")


class AdminClient:
    def __init__(self, home: Path) -> None:
        self.home = home.expanduser().resolve()
        self.socket: socket.socket | None = None

    def __enter__(self) -> AdminClient:
        return self

    def __exit__(self, *_args: object) -> None:
        if self.socket is not None:
            self.socket.close()

    def _connect(self) -> socket.socket:
        # Connect on the first call, after any passphrase prompt: the broker
        # closes an admin connection that stays silent for 30 seconds, and a
        # human typing two passphrases takes longer than that.
        # ponytail: a prompt between two calls (passphrase-change, join) still
        # races that timeout; fix by prompting before the first call if it bites.
        if self.socket is None:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(str(self.home / "run" / "admin.sock"))
            if not verify_broker_peer(sock, self.home):
                sock.close()
                raise RuntimeError("twadmin: admin socket peer is not the Titanwarden broker")
            self.socket = sock
        return self.socket

    def call(self, op: str, args: dict[str, Any], fds: list[int] | None = None) -> dict[str, Any]:
        sock = self._connect()
        send_frame_with_fds(sock, {"v": 1, "op": op, "args": args}, fds or [])
        response = recv_frame(sock)
        if not isinstance(response, dict):
            raise RuntimeError("twadmin: invalid broker response")
        return response


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="twadmin")
    parser.add_argument("--home", default=os.environ.get("TW_HOME", "~/.titanwarden"))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    init = sub.add_parser("init")
    init.add_argument("--cloud-broker", action="store_true")
    join = sub.add_parser('join')
    join.add_argument('--url', default='https://api.titanwarden.com')
    join.add_argument('--org', required=True)
    join.add_argument('--name', required=True)
    sub.add_parser('cloud-status')
    resolve = sub.add_parser('resolve')
    resolve.add_argument('--head', required=True, help='Selected policy head SEQ:HASH')
    resolve.add_argument('--through-conflict', required=True, type=int)
    sub.add_parser("import-bitwarden", help="import a names-only Bitwarden manifest")
    sub.add_parser("unseal")
    sub.add_parser("seal")
    reveal = sub.add_parser("reveal")
    reveal.add_argument("path")
    reveal.add_argument("--reason", required=True)
    put = sub.add_parser("put")
    put.add_argument("path")
    put.add_argument("--class", dest="secret_class", default="sensitive")
    put.add_argument("--kind", default="opaque")
    put.add_argument("--note")
    request = sub.add_parser("request")
    request.add_argument("decision", choices=("approve", "deny"))
    request.add_argument("request_id")
    request.add_argument("--reason", required=True)
    sub.add_parser("freeze")
    sub.add_parser("unfreeze")
    sub.add_parser("panic-seal")
    sub.add_parser("lockdown-clear")
    sub.add_parser("passphrase-change")
    sub.add_parser("recovery-rotate")
    audit = sub.add_parser("audit")
    audit.add_argument("verb", choices=("verify", "tail", "who-touched", "dependents"))
    audit.add_argument("path", nargs="?")
    audit.add_argument("--n", type=int, default=20)
    backup = sub.add_parser("backup")
    backup.add_argument("destination")
    return parser


def _print_response(response: dict[str, Any], *, as_json: bool = False) -> int:
    if not response.get("ok"):
        print(str(response.get("error", "tw: request failed")), file=sys.stderr)
        return exit_code_for(str(response.get("code", "E_BAD_REQUEST")))
    result = response.get("result", {})
    if as_json:
        import json

        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    elif isinstance(result, dict):
        for key, value in result.items():
            if key not in {"revealed"}:
                print(f"{key}: {value}", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    actual_argv = sys.argv[1:] if argv is None else argv
    if "import-bitwarden" in actual_argv:
        if not human_context_allowed("import-bitwarden"):
            print("twadmin: this operation must run over SSH or with Orca and agents stopped", file=sys.stderr)
            return 77
        from .bitwarden_import import main as import_bitwarden
        index = actual_argv.index("import-bitwarden")
        return import_bitwarden(actual_argv[:index] + actual_argv[index + 1:])
    options = _parser().parse_args(argv)
    command = options.command
    if not human_context_allowed(command):
        print("twadmin: this operation must run over SSH or with Orca and agents stopped", file=sys.stderr)
        return 77
    home = Path(options.home)
    try:
        with AdminClient(home) as client:
            if command == "status":
                return _print_response(client.call("status", {}))
            tty_fd: int | None = None
            if command in SENSITIVE_SCREEN_OPS:
                tty_fd = os.open(operator_tty(), os.O_WRONLY)
            try:
                if command == "init":
                    if options.cloud_broker:
                        # getpass must never fall back to stdin in this mode.
                        with open('/dev/tty', 'r+') as tty:
                            if not os.isatty(tty.fileno()):
                                raise RuntimeError('cloud broker initialization requires a tty')
                        warnings.filterwarnings('error', category=getpass.GetPassWarning)
                    first = getpass.getpass("Titanwarden passphrase: ")
                    second = getpass.getpass("Confirm passphrase: ")
                    if first != second:
                        print("twadmin: passphrases do not match", file=sys.stderr)
                        return 64
                    return _print_response(client.call("init", {"passphrase": first, "cloud_broker": options.cloud_broker}, [tty_fd]))
                passphrase = getpass.getpass("Titanwarden passphrase: ")
                auth_op = "lockdown_clear" if command == "lockdown-clear" else "auth"
                auth = client.call(auth_op, {"passphrase": passphrase})
                if not auth.get("ok"):
                    return _print_response(auth)
                if command == "unseal":
                    return _print_response(auth)
                if command == 'cloud-status':
                    return _print_response(client.call('cloud_status',{}))
                if command == 'join':
                    code = getpass.getpass('Enrollment code from the console: ')
                    reserved = client.call('cloud_join',dict(origin=options.url,org=options.org,name=options.name,code=code))
                    if not reserved.get('ok'):
                        return _print_response(reserved)
                    print('Read these words to the console administrator: '+reserved['result']['words'])
                    words = input('Type the words shown by the console: ').strip()
                    paired = client.call('cloud_pair',dict(words=words))
                    if not paired.get('ok'):
                        return _print_response(paired)
                    print('Approve this broker in the console, then run twadmin cloud-status to check synchronization.')
                    return _print_response(client.call('cloud_poll',{}))
                if command == 'resolve':
                    seq,hash_value = options.head.split(':',1)
                    root = input('Independently verified organization root: ').strip()
                    return _print_response(client.call('cloud_resolve',dict(head=dict(seq=int(seq),hash=hash_value),
                        through_conflict=options.through_conflict,typed_root=root)))
                if command == "seal":
                    return _print_response(client.call("seal", {}))
                if command == "reveal":
                    return _print_response(
                        client.call("reveal", {"path": options.path, "reason": options.reason}, [tty_fd])
                    )
                if command == "put":
                    value = read_put_value()
                    read_fd, write_fd = os.pipe()

                    def write_value() -> None:
                        try:
                            view = memoryview(value)
                            while view:
                                written = os.write(write_fd, view)
                                view = view[written:]
                        finally:
                            os.close(write_fd)

                    writer = threading.Thread(target=write_value, daemon=True)
                    writer.start()
                    try:
                        response = client.call(
                            "put",
                            {
                                "path": options.path,
                                "class": options.secret_class,
                                "kind": options.kind,
                                "note": options.note,
                            },
                            [read_fd],
                        )
                    finally:
                        os.close(read_fd)
                        writer.join()
                    return _print_response(response)
                if command == "request":
                    return _print_response(
                        client.call(
                            "request_decide",
                            {
                                "request_id": options.request_id,
                                "decision": options.decision,
                                "reason": options.reason,
                            },
                        )
                    )
                if command in {"freeze", "unfreeze"}:
                    return _print_response(client.call(command, {}))
                if command == "panic-seal":
                    return _print_response(client.call("panic_seal", {}))
                if command == "lockdown-clear":
                    return _print_response(auth)
                if command == "passphrase-change":
                    first = getpass.getpass("New passphrase: ")
                    second = getpass.getpass("Confirm new passphrase: ")
                    if first != second:
                        print("twadmin: passphrases do not match", file=sys.stderr)
                        return 64
                    return _print_response(client.call("passphrase_change", {"new_passphrase": first}))
                if command == "recovery-rotate":
                    return _print_response(client.call("recovery_rotate", {}, [tty_fd]))
                if command == "audit":
                    op = "audit_" + options.verb.replace("-", "_")
                    args = {"n": options.n}
                    if options.path:
                        args["path"] = options.path
                    return _print_response(client.call(op, args), as_json=True)
                if command == "backup":
                    return _print_response(client.call("backup", {"destination": options.destination}))
            finally:
                if tty_fd is not None:
                    os.close(tty_fd)
    except (OSError, RuntimeError, getpass.GetPassWarning) as exc:
        print(f"twadmin: {exc}", file=sys.stderr)
        return 69
    return 64


def pin_cloud_enrollment(session, store, genesis: bytes, *, typed_words: str):
    """Offline human ceremony helper; deliberately absent from CLI/socket routes.

    The caller must obtain words independently, then type all six words locally.
    A server pairing flag or polling status is never an input to this gate.
    """
    from .cloud_enroll import EnrollmentSession
    if not isinstance(session, EnrollmentSession):
        raise ValueError('local enrollment session required')
    return session.pin(store, genesis, typed_words=typed_words)


def resolve_cloud_policy(sync, *, expected_head, through_conflict, typed_root, now):
    """Offline local resolution helper, absent from production socket/CLI routes.

    No offline argument authenticates the broker's existing admin session.
    CloudSync.resolve therefore refuses until authenticated history-selection
    wiring is reviewed; database-readable pins never authorize resolution.
    """
    from .cloud_sync import CloudSync
    if not isinstance(sync, CloudSync):
        raise ValueError('local cloud sync instance required')
    return sync.resolve(expected_head=expected_head, through_conflict=through_conflict,
                        typed_root=typed_root, now=now)


if __name__ == "__main__":
    raise SystemExit(main())
