"""Human Bitwarden import, with metadata-only recovery and fixed diagnostics."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import resource
import selectors
import signal
import sqlite3
import stat
import subprocess
import sys
import threading
import time
import uuid
import warnings


MESSAGES = {
    "E_IMPORT_MANIFEST": "invalid names-only manifest",
    "E_IMPORT_SOURCE": "source read refused",
    "E_IMPORT_REVISION": "source revision changed",
    "E_IMPORT_CORE": "core dump protection unavailable",
    "E_IMPORT_LOCK": "maintenance window unavailable",
    "E_IMPORT_JOURNAL": "journal unavailable or inconsistent",
    "E_IMPORT_SEALED": "broker is sealed",
    "E_IMPORT_ORG": "broker is not joined",
    "E_IMPORT_HEAD": "verified current head required",
    "E_IMPORT_EXISTS": "target already exists; import requires new names",
    "E_IMPORT_STALE": "source changed during import; new-name re-import required",
    "E_IMPORT_AUTH": "admin authentication refused",
    "E_IMPORT_WRITE": "write outcome requires resume",
    "E_IMPORT_VERIFY": "stored value verification refused",
    "E_IMPORT_ABORT": "import interrupted",
    "E_IMPORT_INTERNAL": "import refused",
}
MAX_VALUE = 1024 * 1024
MAX_MANIFEST = 1024 * 1024
MAX_SOURCE = 8 * 1024 * 1024
NAMESPACE = uuid.UUID("40cc172e-659e-5bfc-ab11-6c32738bbdac")
NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}\Z")
REVISION = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z\Z")


class ImportFailure(Exception):
    def __init__(self, code):
        self.code = code if code in MESSAGES else "E_IMPORT_INTERNAL"
        super().__init__(self.code)


def failure_code(failure):
    if type(failure) is ImportFailure:
        return failure.code
    return "E_IMPORT_ABORT" if isinstance(failure, KeyboardInterrupt) else "E_IMPORT_INTERNAL"


def require(condition, code):
    if not condition:
        raise ImportFailure(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def parse_json(raw):
    return json.loads(raw, object_pairs_hook=unique_object,
                      parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))


def validate_entry(entry):
    code = "E_IMPORT_MANIFEST"
    require(type(entry) is dict, code)
    selector = set(entry) & {"field", "login"}
    require(len(selector) == 1 and set(entry) == {"item_id", "project", "path", "class"} | selector, code)
    require(type(entry["item_id"]) is str, code)
    try:
        require(str(uuid.UUID(entry["item_id"])) == entry["item_id"], code)
    except (ValueError, AttributeError):
        raise ImportFailure(code) from None
    require(type(entry["project"]) is str and NAME.fullmatch(entry["project"]) is not None, code)
    require(type(entry["path"]) is str and NAME.fullmatch(entry["path"]) is not None, code)
    require(type(entry["class"]) is str and entry["class"] in {"standard", "sensitive", "restricted"}, code)
    if "login" in entry:
        require(type(entry["login"]) is str and entry["login"] in {"username", "password", "totp"}, code)
    else:
        require(type(entry["field"]) is str and 0 < len(entry["field"]) <= 128
                and all(ord(c) >= 32 and ord(c) != 127 for c in entry["field"]), code)
    return entry


def load_manifest(path):
    try:
        with open(path, "rb") as stream:
            raw = stream.read(MAX_MANIFEST + 1)
        require(len(raw) <= MAX_MANIFEST, "E_IMPORT_MANIFEST")
        manifest = parse_json(raw)
        require(type(manifest) is dict and set(manifest) == {"version", "items"}
                and type(manifest["version"]) is int and manifest["version"] == 1,
                "E_IMPORT_MANIFEST")
        entries = manifest["items"]
        require(type(entries) is list and 0 < len(entries) <= 1000, "E_IMPORT_MANIFEST")
        targets = set()
        for entry in entries:
            validate_entry(entry)
            target = (entry["project"], entry["path"])
            require(target not in targets, "E_IMPORT_MANIFEST")
            targets.add(target)
        return entries
    except ImportFailure:
        raise
    except BaseException:
        raise ImportFailure("E_IMPORT_MANIFEST") from None


def disable_core():
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        require(resource.getrlimit(resource.RLIMIT_CORE) == (0, 0), "E_IMPORT_CORE")
    except BaseException:
        raise ImportFailure("E_IMPORT_CORE") from None


# Deployment settings are code constants, never caller environment or CLI options.
BW_EXECUTABLE = "/usr/local/libexec/titanwarden/bw"
BW_HOME = "/var/db/titanwarden"
BW_APPDATA = "/var/db/titanwarden/bitwarden"
SOURCE_TIMEOUT = 30


def trusted_executable(path, *, expected_owner=0):
    candidate = Path(path)
    require(candidate.is_absolute() and ".." not in candidate.parts, "E_IMPORT_SOURCE")
    for component in (candidate, *candidate.parents):
        metadata = component.lstat()
        require(metadata.st_uid == expected_owner, "E_IMPORT_SOURCE")
        require(metadata.st_mode & 0o022 == 0, "E_IMPORT_SOURCE")
        require(stat.S_ISREG(metadata.st_mode) if component == candidate
                else stat.S_ISDIR(metadata.st_mode), "E_IMPORT_SOURCE")
    require(os.access(candidate, os.X_OK), "E_IMPORT_SOURCE")
    return str(candidate)


def source_environment(session=None):
    environment = {"PATH": "/usr/bin:/bin", "HOME": BW_HOME,
                   "BITWARDENCLI_APPDATA_DIR": BW_APPDATA}
    # Temporary P6 input. P5 replaces this with the protected human ceremony.
    if session is not None:
        environment["BW_SESSION"] = session
    return environment


ABORT_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT)


@contextmanager
def blocked_abort_signals():
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, ABORT_SIGNALS)
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


@contextmanager
def source_output(arguments, *, capture=True, session=None):
    child = None
    try:
        require(resource.getrlimit(resource.RLIMIT_CORE) == (0, 0), "E_IMPORT_CORE")
        executable = trusted_executable(BW_EXECUTABLE)
        with blocked_abort_signals():
            child = subprocess.Popen(
                [executable, *arguments], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE if capture else subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                shell=False, env=source_environment(session), start_new_session=True, close_fds=True,
            )
        deadline = time.monotonic() + SOURCE_TIMEOUT
        output = bytearray()
        if capture:
            os.set_blocking(child.stdout.fileno(), False)
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    require(remaining > 0, "E_IMPORT_SOURCE")
                    require(bool(selector.select(remaining)), "E_IMPORT_SOURCE")
                    chunk = os.read(child.stdout.fileno(), min(65536, MAX_SOURCE + 1 - len(output)))
                    if not chunk:
                        break
                    output.extend(chunk)
                    require(len(output) <= MAX_SOURCE, "E_IMPORT_SOURCE")
        # Observe exit without reaping: the leader reserves its PID and PGID
        # until group termination below, including the successful output path.
        while True:
            status = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if status is not None:
                require(status.si_code == os.CLD_EXITED and status.si_status == 0, "E_IMPORT_SOURCE")
                break
            require(time.monotonic() < deadline, "E_IMPORT_SOURCE")
            time.sleep(0.01)
    finally:
        with blocked_abort_signals():
            if child is not None:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    # Darwin returns EPERM for a group containing only its zombie
                    # leader. Confirm exit without reaping before accepting it.
                    status = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    if sys.platform != "darwin" or status is None:
                        raise
                finally:
                    try:
                        if child.stdout is not None:
                            child.stdout.close()
                    finally:
                        child.wait()
    # No parser or caller runs while a session-bearing group remains alive.
    yield output


def sync_source(*, session=None):
    try:
        with source_output(["sync"], capture=False, session=session):
            pass
    except ImportFailure:
        raise
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException:
        raise ImportFailure("E_IMPORT_SOURCE") from None


def read_source(entry, *, revision_only=False, session=None):
    """Read from the batch's cache. Only the requested member leaves this frame."""
    try:
        with source_output(["get", "item", entry["item_id"]], session=session) as raw:
            item = parse_json(raw)
        require(type(item) is dict and item.get("id") == entry["item_id"], "E_IMPORT_SOURCE")
        revision = item.get("revisionDate")
        require(type(revision) is str and REVISION.fullmatch(revision) is not None, "E_IMPORT_SOURCE")
        if revision_only:
            return revision, None
        if "field" in entry:
            fields = item.get("fields")
            require(type(fields) is list and all(type(field) is dict for field in fields), "E_IMPORT_SOURCE")
            matches = [field for field in fields if field.get("name") == entry["field"]]
            require(len(matches) == 1, "E_IMPORT_SOURCE")
            value = matches[0].get("value")
        else:
            login = item.get("login")
            require(type(login) is dict, "E_IMPORT_SOURCE")
            value = login.get(entry["login"])
        require(type(value) is str, "E_IMPORT_SOURCE")
        selected = value.encode("utf-8")
        require(0 < len(selected) <= MAX_VALUE, "E_IMPORT_SOURCE")
        return revision, selected
    except ImportFailure:
        raise
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException:
        raise ImportFailure("E_IMPORT_SOURCE") from None


def entry_hash(entry):
    return hashlib.sha256(canonical(entry).encode()).hexdigest()


def request_id(entry, revision):
    # Cloud admission requires the v4 wire shape. These logical IDs are stable,
    # with 122 digest-derived bits, rather than freshly generated on each retry.
    digest = hashlib.sha256(NAMESPACE.bytes + canonical([entry, revision]).encode()).digest()
    return str(uuid.UUID(bytes=digest[:16], version=4))


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextmanager
def maintenance(state):
    """Persistent marker survives crashes. Only a clean exit removes it."""
    fd = None
    try:
        fd = os.open(state / "bitwarden-import.mutex", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        require(stat.S_ISREG(os.fstat(fd).st_mode) and os.fstat(fd).st_uid == os.getuid(), "E_IMPORT_LOCK")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        marker = os.open(state / "bitwarden-import.lock", os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            os.fsync(marker)
        finally:
            os.close(marker)
        sync_directory(state)
    except BaseException:
        if fd is not None:
            os.close(fd)
        raise ImportFailure("E_IMPORT_LOCK") from None
    try:
        yield
    except BaseException:
        # Leave the marker for the operator and exact journal resume.
        raise
    else:
        (state / "bitwarden-import.lock").unlink()
        sync_directory(state)
    finally:
        os.close(fd)


class Journal:
    def __init__(self, state, entries):
        self.state = state
        self.batch = hashlib.sha256(canonical(entries).encode()).hexdigest()
        self.db = None
        try:
            path = state / "bitwarden-import.sqlite3"
            fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            try:
                info = os.fstat(fd)
                require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                        and info.st_nlink == 1 and info.st_mode & 0o077 == 0, "E_IMPORT_JOURNAL")
            finally:
                os.close(fd)
            self.db = sqlite3.connect(path, isolation_level=None)
            self.db.row_factory = sqlite3.Row
            self.db.execute("PRAGMA journal_mode=DELETE")
            self.db.execute("PRAGMA synchronous=EXTRA")
            self.db.execute("PRAGMA temp_store=MEMORY")
            self.db.execute("CREATE TABLE IF NOT EXISTS items (batch TEXT NOT NULL, item TEXT NOT NULL, "
                            "revision TEXT NOT NULL, request_id TEXT UNIQUE, "
                            "state TEXT NOT NULL CHECK(state IN ('planned','written','verified','failed')), "
                            "error TEXT NOT NULL, PRIMARY KEY(batch,item))")
            batches = self.db.execute("SELECT DISTINCT batch FROM items").fetchall()
            require(not batches or (len(batches) == 1 and batches[0][0] == self.batch), "E_IMPORT_JOURNAL")
            for entry in entries:
                self.db.execute("INSERT OR IGNORE INTO items VALUES (?,?,'',NULL,'planned','')",
                                (self.batch, entry_hash(entry)))
            self.flush()
        except BaseException:
            self.close()
            raise ImportFailure("E_IMPORT_JOURNAL") from None

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None

    def flush(self):
        fd = os.open(self.state / "bitwarden-import.sqlite3", os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        sync_directory(self.state)

    def row(self, entry):
        return self.db.execute("SELECT * FROM items WHERE batch=? AND item=?",
                               (self.batch, entry_hash(entry))).fetchone()

    def plan(self, entry, revision):
        self.db.execute("UPDATE items SET revision=?,request_id=?,state='planned',error='' WHERE batch=? AND item=?",
                        (revision, request_id(entry, revision), self.batch, entry_hash(entry)))
        self.flush()

    def mark(self, entry, state, error=""):
        require(state in {"written", "verified", "failed"} and (not error or error in MESSAGES), "E_IMPORT_JOURNAL")
        self.db.execute("UPDATE items SET state=?,error=? WHERE batch=? AND item=?",
                        (state, error, self.batch, entry_hash(entry)))
        self.flush()


def broker_call(client, op, args, code, fds=None):
    try:
        response = client.call(op, args, fds)
        if (op == "import_put" and type(response) is dict and response.get("ok") is False
                and response.get("code") == "E_IMPORT_EXISTS"):
            raise ImportFailure("E_IMPORT_EXISTS")
        require(type(response) is dict and response.get("ok") is True, code)
        result = response.get("result")
        require(type(result) is dict, code)
        return result
    except (KeyboardInterrupt, SystemExit):
        raise
    except ImportFailure as failure:
        raise ImportFailure("E_IMPORT_EXISTS" if op == "import_put" and failure.code == "E_IMPORT_EXISTS" else code) from None
    except BaseException:
        raise ImportFailure(code) from None


def ready(client, entries=None):
    result = broker_call(client, "import_status", {} if entries is None else {"entries": entries}, "E_IMPORT_HEAD")
    require(result.get("seal_state") == "unsealed", "E_IMPORT_SEALED")
    require(result.get("joined") is True, "E_IMPORT_ORG")
    require(result.get("current_head") is True, "E_IMPORT_HEAD")
    return result


def check_targets(client, entries, journal):
    fresh = [entry for entry in entries if not journal.row(entry)["revision"]]
    if not fresh:
        return
    result = ready(client, fresh)
    existing = result.get("existing_targets")
    expected = {entry_hash(entry) for entry in fresh}
    require(type(existing) is list and all(type(item) is str and item in expected for item in existing), "E_IMPORT_HEAD")
    for entry in fresh:
        if entry_hash(entry) in existing:
            journal.mark(entry, "failed", "E_IMPORT_EXISTS")
            raise ImportFailure("E_IMPORT_EXISTS")


def put(client, entry, rid, value):
    read_fd, write_fd = os.pipe()
    errors = []

    def feed():
        try:
            view = memoryview(value)
            while view:
                count = os.write(write_fd, view)
                view = view[count:]
        except BaseException:
            errors.append(True)
        finally:
            os.close(write_fd)

    writer = threading.Thread(target=feed, daemon=True)
    writer.start()
    try:
        broker_call(client, "import_put", {"entry": entry, "request_id": rid}, "E_IMPORT_WRITE", [read_fd])
    finally:
        os.close(read_fd)
        writer.join()
    require(not errors, "E_IMPORT_WRITE")


def verify(client, entry, rid, value):
    key = os.urandom(32)
    expected = hmac.digest(key, value, "sha256").hex()
    result = broker_call(client, "import_verify", {"entry": entry, "request_id": rid,
                         "key": key.hex()}, "E_IMPORT_VERIFY")
    require(type(result.get("digest")) is str and hmac.compare_digest(result["digest"], expected), "E_IMPORT_VERIFY")


def finish_source(journal, entries, written, used, *, session=None):
    """Refresh once and inspect all known written rows, even after an abort.

    A use proof is deliberately not a verified checkpoint until the refreshed
    source revision also agrees. A crash before this point resumes by receipt.
    """
    candidates = [entry for entry in entries if entry_hash(entry) in written
                  or journal.row(entry)["state"] in {"written", "verified"}
                  or journal.row(entry)["error"] == "E_IMPORT_VERIFY"]
    if not candidates:
        return
    try:
        sync_source(session=session)
    except BaseException as failure:
        code = failure_code(failure)
        for entry in candidates:
            journal.mark(entry, "failed", code)
        raise ImportFailure(code) from None
    errors = []
    for entry in candidates:
        row = journal.row(entry)
        try:
            revision, _unused = read_source(entry, revision_only=True, session=session)
            require(revision == row["revision"], "E_IMPORT_STALE")
            if entry_hash(entry) in used or row["state"] == "verified":
                journal.mark(entry, "verified")
        except BaseException as failure:
            code = failure_code(failure)
            journal.mark(entry, "failed", code)
            errors.append(code)
    if errors:
        raise ImportFailure("E_IMPORT_STALE" if "E_IMPORT_STALE" in errors else errors[0])


def run_import(home, entries, client, maintenance_dir=None, *, session=None):
    state = home / "state"
    require(state.is_dir(), "E_IMPORT_JOURNAL")
    ready(client)
    with maintenance(state if maintenance_dir is None else maintenance_dir):
        journal = Journal(state, entries)
        window_started = False
        written, used = set(), set()
        try:
            require(not any(journal.row(entry)["error"] == "E_IMPORT_STALE" for entry in entries), "E_IMPORT_STALE")
            if all(journal.row(entry)["state"] == "verified" for entry in entries):
                return
            check_targets(client, entries, journal)
            try:
                sync_source(session=session)
            except BaseException as failure:
                code = failure_code(failure)
                for entry in entries:
                    if journal.row(entry)["state"] != "verified":
                        journal.mark(entry, "failed", code)
                raise ImportFailure(code) from None
            window_started = True
            # Freeze every revision before the first write. Never persist source values.
            for entry in entries:
                if not journal.row(entry)["revision"]:
                    try:
                        revision, value = read_source(entry, session=session)
                        del value
                        journal.plan(entry, revision)
                    except BaseException as failure:
                        code = failure_code(failure)
                        journal.mark(entry, "failed", code)
                        raise ImportFailure(code) from None
            for entry in entries:
                row = journal.row(entry)
                if row["state"] == "verified":
                    continue
                try:
                    require(row["request_id"] == request_id(entry, row["revision"]), "E_IMPORT_JOURNAL")
                    revision, value = read_source(entry, session=session)
                    require(revision == row["revision"], "E_IMPORT_REVISION")
                    ready(client)
                    # Always replay the stable request, including after an ambiguous response.
                    put(client, entry, row["request_id"], value)
                    written.add(entry_hash(entry))
                    journal.mark(entry, "written")
                    verify(client, entry, row["request_id"], value)
                    del value
                    used.add(entry_hash(entry))
                except BaseException as failure:
                    code = failure_code(failure)
                    journal.mark(entry, "failed", code)
                    raise ImportFailure(code) from None
        finally:
            try:
                if window_started:
                    finish_source(journal, entries, written, used, session=session)
            finally:
                journal.close()


class QuietParser(argparse.ArgumentParser):
    def error(self, _message):
        raise ImportFailure("E_IMPORT_MANIFEST")


def main(argv=None):
    """Catch even parser, signal, child and broker failures without their text."""
    session = os.environ.pop("BW_SESSION", None)
    handlers = {}
    original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, [])
    first_signal = None
    code = None
    verified = False
    refused = False
    try:
        def record_abort(signum, _frame):
            nonlocal first_signal
            if first_signal is None:
                first_signal = signum

        def interrupted(signum, _frame):
            nonlocal first_signal
            if first_signal is not None:
                return
            first_signal = signum
            signal.pthread_sigmask(signal.SIG_BLOCK, ABORT_SIGNALS)
            raise ImportFailure("E_IMPORT_ABORT")
        for signum in ABORT_SIGNALS:
            handlers[signum] = signal.signal(signum, interrupted)
        from .admin import human_context_allowed
        refused = not human_context_allowed("import-bitwarden")
        if not refused:
            disable_core()
            os.umask(0o077)
            parser = QuietParser(prog="twadmin import-bitwarden")
            parser.add_argument("--home", default=os.environ.get("TW_HOME", "~/.titanwarden"))
            parser.add_argument("--maintenance-dir", type=Path)
            parser.add_argument("manifest")
            options = parser.parse_args(argv)
            entries = load_manifest(options.manifest)
            from .admin import AdminClient
            import getpass
            home = Path(options.home).expanduser().resolve()
            with AdminClient(home) as client:
                ready(client)
                with warnings.catch_warnings():
                    warnings.simplefilter("error", getpass.GetPassWarning)
                    passphrase = getpass.getpass("Titanwarden passphrase: ")
                broker_call(client, "import_auth", {"passphrase": passphrase}, "E_IMPORT_AUTH")
                del passphrase
                run_import(home, entries, client, options.maintenance_dir, session=session)
            verified = True
    except BaseException as failure:
        if not (type(failure) is SystemExit and failure.code == 0):
            code = failure_code(failure)
    finally:
        # Keep non-raising recorders installed through delivery, including aborts
        # originally blocked by the caller. A Python checkpoint and pending check
        # precede restoring the caller mask and handlers.
        try:
            signal.pthread_sigmask(signal.SIG_BLOCK, ABORT_SIGNALS)
            for signum in handlers:
                signal.signal(signum, record_abort)
            signal.pthread_sigmask(signal.SIG_UNBLOCK, ABORT_SIGNALS)
            delivery_checkpoint = None
            require(not (signal.sigpending() & set(ABORT_SIGNALS)), "E_IMPORT_ABORT")
        except BaseException as failure:
            code = failure_code(failure)
        finally:
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
            except BaseException as failure:
                code = failure_code(failure)
            # After mask restoration, newly pending caller-blocked signals belong
            # to the caller. After each original handler is restored, new signals
            # for that handler are also outside the importer's lifetime.
            for signum, handler in handlers.items():
                try:
                    signal.signal(signum, handler)
                except BaseException as failure:
                    code = failure_code(failure)

    if first_signal is not None:
        code = "E_IMPORT_ABORT"
    if code is not None:
        recovery = ("retain journal for new-name re-import" if code == "E_IMPORT_STALE"
                    else "resume from journal")
        print("twadmin: " + code + ": " + MESSAGES[code] + "; earlier writes remain in place; " + recovery, file=sys.stderr)
        return 1
    if refused:
        print("twadmin: this operation must run over SSH or with Orca and agents stopped", file=sys.stderr)
        return 77
    if verified:
        print("twadmin: import verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
