"""Broker-owned process execution and redacted output relaying."""

from __future__ import annotations

import hashlib
import json
import os
import fcntl
import shutil
import select
import signal as signal_module
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping, Sequence

from .redact import Redactor


class BusyError(RuntimeError):
    code = "E_BUSY"


class ExecutionError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ExecutionRequest:
    lease_id: str
    token_id: str
    principal_id: str
    argv: Sequence[str]
    cwd: str
    environment: Mapping[str, str]
    env_refs: Mapping[str, str] = field(default_factory=dict)
    fd_refs: Mapping[int, str] = field(default_factory=dict)
    stdin_ref: str | None = None
    soft_refs: Mapping[str, str] = field(default_factory=dict)
    job: str | None = None
    parent_lease_id: str | None = None
    context_verified: bool = False
    no_shell: bool = False


SHELL_EXECUTABLES = frozenset(
    {"sh", "bash", "zsh", "fish", "dash", "env", "printenv", "python", "python3", "node", "ruby", "perl"}
)


def is_inline_shell(argv: Sequence[str]) -> bool:
    return bool(argv) and os.path.basename(argv[0]) in SHELL_EXECUTABLES and any(
        argument in {"-c", "-e"} for argument in argv[1:]
    )


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        view = view[written:]


class ExecutionHandle:
    def __init__(
        self,
        executor: "Executor",
        request: ExecutionRequest,
        process: subprocess.Popen,
        relay_threads: list[threading.Thread],
        writer_threads: list[threading.Thread],
        redaction_counts: dict[str, int],
        process_done: threading.Event,
    ):
        self.executor = executor
        self.request = request
        self.process = process
        self.relay_threads = relay_threads
        self.writer_threads = writer_threads
        self.redaction_counts = redaction_counts
        self.process_done = process_done
        self.pid = process.pid
        self._wait_lock = threading.Lock()
        self._finished = False
        self._exit_code: int | None = None
        self._end_reason = "exit"
        self._disconnect_started = False

    def signal(self, signum: int) -> None:
        if signum not in {
            signal_module.SIGINT,
            signal_module.SIGTERM,
            signal_module.SIGHUP,
        }:
            raise ExecutionError("E_SIGNAL", "unsupported signal")
        if self.process.poll() is None:
            os.killpg(self.process.pid, signum)

    def disconnect(self) -> None:
        with self._wait_lock:
            if self._finished or self._disconnect_started:
                return
            self._disconnect_started = True
            self._end_reason = "client_gone"
        if self.process.poll() is not None:
            return
        try:
            os.killpg(self.process.pid, signal_module.SIGTERM)
        except ProcessLookupError:
            return

        def enforce_kill() -> None:
            try:
                self.process.wait(timeout=self.executor.disconnect_grace)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(self.process.pid, signal_module.SIGKILL)
                except ProcessLookupError:
                    pass

        thread = threading.Thread(target=enforce_kill, name=f"tw-kill-{self.pid}", daemon=True)
        thread.start()

    def wait(self) -> int:
        with self._wait_lock:
            if self._finished:
                return self._exit_code if self._exit_code is not None else 1
            returncode = self.process.wait()
            self.process_done.set()
            for thread in self.writer_threads:
                thread.join(timeout=0.25)
            for thread in self.relay_threads:
                thread.join(timeout=0.25)
            for thread in self.relay_threads:
                thread.join(timeout=0.25)
            exit_code = returncode if returncode >= 0 else 128 + (-returncode)
            self.executor._lease_close(
                lease_id=self.request.lease_id,
                exit_code=exit_code,
                end_reason=self._end_reason,
                redactions=sum(self.redaction_counts.values()),
            )
            self.executor._release(self)
            self._exit_code = exit_code
            self._finished = True
            return exit_code


class Executor:
    def __init__(
        self,
        secret_resolver: Callable[[str], bytes],
        redactor_factory: Callable[[str], Redactor],
        lease_open: Callable[..., None] | None = None,
        lease_close: Callable[..., None] | None = None,
        max_total: int = 64,
        max_per_principal: int = 8,
        disconnect_grace: float = 10.0,
    ):
        self.secret_resolver = secret_resolver
        self.redactor_factory = redactor_factory
        self._lease_open = lease_open or (lambda **_fields: None)
        self._lease_close = lease_close or (lambda **_fields: None)
        self.max_total = max_total
        self.max_per_principal = max_per_principal
        self.disconnect_grace = disconnect_grace
        self._lock = threading.Lock()
        self._handles: set[ExecutionHandle] = set()
        self._principal_counts: dict[str, int] = {}
        self._reserved_total = 0

    def _reserve(self, principal_id: str) -> None:
        with self._lock:
            count = self._principal_counts.get(principal_id, 0)
            if self._reserved_total >= self.max_total or count >= self.max_per_principal:
                raise BusyError("execution concurrency limit reached")
            self._principal_counts[principal_id] = count + 1
            self._reserved_total += 1

    def _release_reservation(self, principal_id: str) -> None:
        self._reserved_total -= 1
        count = self._principal_counts.get(principal_id, 0)
        if count <= 1:
            self._principal_counts.pop(principal_id, None)
        else:
            self._principal_counts[principal_id] = count - 1

    def _release(self, handle: ExecutionHandle) -> None:
        with self._lock:
            self._handles.discard(handle)
            self._release_reservation(handle.request.principal_id)

    def start(
        self,
        request: ExecutionRequest,
        stdout_fd: int,
        stderr_fd: int,
        stdin_fd: int | None = None,
        relay_chunk_size: int = 65536,
    ) -> ExecutionHandle:
        if not request.argv:
            raise ExecutionError("E_EXEC", "empty command")
        shell = is_inline_shell(request.argv)
        if request.no_shell and shell:
            raise ExecutionError("E_DENIED", "inline shell execution denied by policy")
        self._reserve(request.principal_id)
        pipe_reads: list[int] = []
        pipe_writes: list[tuple[int, bytes]] = []
        process: subprocess.Popen | None = None
        try:
            environment = {
                key: value for key, value in request.environment.items() if not key.startswith("TW_")
            }
            refs: list[dict[str, object]] = []
            for variable, path in request.env_refs.items():
                value = self.secret_resolver(path)
                try:
                    environment[variable] = value.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise ExecutionError(
                        "E_EXEC", "secret value is not valid UTF-8"
                    ) from exc
                refs.append({"path": path, "via": "env"})
            for variable, path in request.soft_refs.items():
                try:
                    value = self.secret_resolver(path)
                except ExecutionError as exc:
                    if exc.code not in {"E_SEALED", "E_FROZEN"}:
                        raise
                else:
                    try:
                        environment[variable] = value.decode("utf-8")
                    except UnicodeDecodeError as exc:
                        raise ExecutionError(
                            "E_EXEC", "secret value is not valid UTF-8"
                        ) from exc
                    refs.append({"path": path, "via": "env"})
            environment["TW_LEASE"] = request.lease_id

            fd_map: dict[int, int] = {}
            minimum_safe_fd = max([64, *(int(fd) + 1 for fd in request.fd_refs)])
            for target_fd, path in request.fd_refs.items():
                if target_fd < 3:
                    raise ExecutionError("E_EXEC", "secret fd must be at least 3")
                read_fd, write_fd = os.pipe()
                safe_read_fd = fcntl.fcntl(
                    read_fd, fcntl.F_DUPFD_CLOEXEC, minimum_safe_fd
                )
                os.close(read_fd)
                pipe_reads.append(safe_read_fd)
                fd_map[safe_read_fd] = target_fd
                value = self.secret_resolver(path)
                pipe_writes.append((write_fd, value))
                refs.append({"path": path, "via": "fd"})

            child_stdin: int | subprocess._FILE = subprocess.DEVNULL
            stdin_payload: bytes | None = None
            if request.stdin_ref:
                child_stdin = subprocess.PIPE
                stdin_payload = self.secret_resolver(request.stdin_ref)
                refs.append({"path": request.stdin_ref, "via": "stdin"})
            # Client stdin is deliberately never inherited. A child could write
            # a secret back through a writable tty descriptor and bypass output
            # redaction. Only a broker-owned secret pipe may become stdin.

            executable = shutil.which(request.argv[0], path=environment.get("PATH"))
            if executable is None:
                raise ExecutionError("E_EXEC", "command not found")

            child_argv = [executable, *request.argv[1:]]
            if fd_map:
                mapping = ",".join(f"{source}:{target}" for source, target in fd_map.items())
                child_argv = [
                    sys.executable,
                    str(Path(__file__).with_name("exec_child.py")),
                    "--map",
                    mapping,
                    "--",
                    *child_argv,
                ]
            process = subprocess.Popen(
                child_argv,
                cwd=request.cwd,
                env=environment,
                stdin=child_stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                pass_fds=tuple(pipe_reads),
                start_new_session=True,
            )
            for read_fd in pipe_reads:
                os.close(read_fd)
            pipe_reads.clear()

            writer_threads: list[threading.Thread] = []
            for write_fd, payload in pipe_writes:
                thread = threading.Thread(
                    target=self._write_and_close,
                    args=(write_fd, payload),
                    name=f"tw-fd-{process.pid}",
                    daemon=True,
                )
                thread.start()
                writer_threads.append(thread)
            pipe_writes.clear()
            if stdin_payload is not None and process.stdin is not None:
                thread = threading.Thread(
                    target=self._write_file_and_close,
                    args=(process.stdin, stdin_payload),
                    name=f"tw-stdin-{process.pid}",
                    daemon=True,
                )
                thread.start()
                writer_threads.append(thread)

            relay_threads = []
            redaction_counts: dict[str, int] = {}
            process_done = threading.Event()
            for source, destination, label in (
                (process.stdout, stdout_fd, "stdout"),
                (process.stderr, stderr_fd, "stderr"),
            ):
                thread = threading.Thread(
                    target=self._relay,
                    args=(
                        source,
                        destination,
                        self.redactor_factory(request.principal_id),
                        relay_chunk_size,
                        redaction_counts,
                        label,
                        process_done,
                    ),
                    name=f"tw-{label}-{process.pid}",
                    daemon=True,
                )
                thread.start()
                relay_threads.append(thread)

            argv_hash = hashlib.sha256(
                json.dumps(list(request.argv), separators=(",", ":")).encode()
            ).hexdigest()
            self._lease_open(
                lease_id=request.lease_id,
                token_id=request.token_id,
                principal_id=request.principal_id,
                pid=process.pid,
                pgid=process.pid,
                argv0=request.argv[0],
                argv_sha256=argv_hash,
                cwd=request.cwd,
                job=request.job,
                refs=refs,
                parent_lease_id=request.parent_lease_id,
                context_verified=request.context_verified,
                shell=shell,
            )
            handle = ExecutionHandle(
                self,
                request,
                process,
                relay_threads,
                writer_threads,
                redaction_counts,
                process_done,
            )
            with self._lock:
                self._handles.add(handle)
            return handle
        except BaseException:
            if process is not None and process.poll() is None:
                try:
                    os.killpg(process.pid, signal_module.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
            for fd in pipe_reads:
                os.close(fd)
            for fd, _payload in pipe_writes:
                os.close(fd)
            with self._lock:
                self._release_reservation(request.principal_id)
            raise

    @staticmethod
    def _write_and_close(fd: int, payload: bytes) -> None:
        try:
            _write_all(fd, payload)
        except BrokenPipeError:
            pass
        finally:
            os.close(fd)

    @staticmethod
    def _write_file_and_close(file, payload: bytes) -> None:
        try:
            file.write(payload)
            file.flush()
        except BrokenPipeError:
            pass
        finally:
            file.close()

    @staticmethod
    def _relay(
        source,
        destination_fd: int,
        redactor: Redactor,
        chunk_size: int,
        redaction_counts: dict[str, int],
        label: str,
        process_done: threading.Event,
    ) -> None:
        stream = redactor.stream()
        try:
            while True:
                ready, _, _ = select.select([source.fileno()], [], [], 0.1)
                if not ready:
                    if process_done.is_set():
                        break
                    continue
                chunk = os.read(source.fileno(), chunk_size)
                if not chunk:
                    break
                output = stream.feed(chunk)
                if output:
                    _write_all(destination_fd, output)
            output = stream.finish()
            if output:
                _write_all(destination_fd, output)
        except (OSError, ValueError):
            pass
        finally:
            redaction_counts[label] = stream.count
            source.close()

    def close(self) -> None:
        with self._lock:
            handles = list(self._handles)
        for handle in handles:
            handle.disconnect()
        for handle in handles:
            handle.wait()
