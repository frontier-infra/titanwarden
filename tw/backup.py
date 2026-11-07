"""Ciphertext-only SQLite online backup job."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

# A launchd job whose interpreter lacks the macOS Removable Volumes grant blocks
# forever in open() on the external drive, so every external touch runs in a
# child process that is killed after this many seconds.
EXTERNAL_TIMEOUT = 60
DESK = shutil.which("desk", path=os.path.expanduser("~/bin") + ":/usr/local/bin:/opt/homebrew/bin:/usr/bin") or os.path.expanduser("~/bin/desk")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def backup(home: Path, external: Path | None = None) -> tuple[Path, Path | None]:
    source_path = home / "state" / "tw.db"
    backup_dir = home / "backups"
    backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%d")
    target = backup_dir / f"tw-{stamp}.db"
    with closing(sqlite3.connect(source_path)) as source, closing(sqlite3.connect(target)) as output:
        with output:
            source.backup(output)
    os.chmod(target, 0o600)
    with closing(sqlite3.connect(target)) as copied:
        tables = [
            row[0]
            for row in copied.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        ]
        counts = {table: copied.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0] for table in tables}
        audit = copied.execute(
            "SELECT seq,hex(hash) FROM audit_events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
    manifest = {
        "created_at": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "database": target.name,
        "sha256": file_sha256(target),
        "row_counts": counts,
        "audit_head": None if audit is None else {"seq": audit[0], "hash": audit[1].lower()},
    }
    manifest_path = target.with_suffix(".manifest.json")
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
    os.chmod(manifest_path, 0o600)
    backups = sorted(backup_dir.glob("tw-*.db"), reverse=True)
    for old in backups[30:]:
        old.unlink()
        old.with_suffix(".manifest.json").unlink(missing_ok=True)

    external_target: Path | None = None
    if external is not None:
        command = [sys.executable, "-m", "tw.backup", "--copy-external", str(target), str(external), manifest["sha256"]]
        try:
            subprocess.run(command, check=True, timeout=EXTERNAL_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"external copy to {external} timed out after {EXTERNAL_TIMEOUT}s") from None
        except subprocess.CalledProcessError as error:
            raise RuntimeError(f"external copy to {external} failed with exit {error.returncode}") from None
        external_target = external / target.name
    return target, external_target


def copy_external(target: Path, external: Path, sha256: str) -> None:
    """Child-process side: copy the database and manifest, temp then rename."""
    external.mkdir(mode=0o700, parents=True, exist_ok=True)
    for source in (target, target.with_suffix(".manifest.json")):
        final = external / source.name
        temp = external / f".{source.name}.tmp"
        try:
            shutil.copy2(source, temp)
            with temp.open("rb") as copied:
                os.fsync(copied.fileno())
            if source == target and file_sha256(temp) != sha256:
                raise RuntimeError("external backup checksum mismatch")
            os.replace(temp, final)
        finally:
            temp.unlink(missing_ok=True)


ALERT_TITLE = "Titanwarden backup failed"


def alert(message: str) -> None:
    """Post one Desk action per failure streak: a later failure notes the open item."""
    desk = [DESK, "--as", "lead-titanwarden"]
    try:
        listed = subprocess.run([*desk, "list", "--project", "titanwarden", "--json"], capture_output=True, text=True, timeout=60)
        items = json.loads(listed.stdout) if listed.returncode == 0 else []
        open_id = next((item["id"] for item in items if item.get("title") == ALERT_TITLE), None)
        if open_id is None:
            command = [*desk, "action", "titanwarden", ALERT_TITLE, "--body", message]
        else:
            command = [*desk, "update", str(open_id), "--note", message]
        subprocess.run(command, check=False, timeout=60)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"desk alert failed: {error}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--home")
    parser.add_argument("--external")
    parser.add_argument("--alert", action="store_true", help="post a Desk action on failure")
    parser.add_argument("--copy-external", nargs=3, metavar=("DB", "DIR", "SHA256"), help=argparse.SUPPRESS)
    options = parser.parse_args(argv)
    if options.copy_external:
        database, directory, sha256 = options.copy_external
        copy_external(Path(database), Path(directory), sha256)
        return 0
    if options.home is None:
        parser.error("--home is required")
    try:
        backup(Path(options.home), None if options.external is None else Path(options.external))
    except Exception as error:
        print(f"backup failed: {error}", file=sys.stderr)
        if options.alert:
            alert(f"{error}. Internal copies under ~/.titanwarden/backups are kept. No substitute destination was used.")
        return 1
    return 0


def disposable_adoption_copy(source_home: Path, target_home: Path) -> Path:
    """Create an exclusive, verified SQLite copy for the local adoption draft.

    No source schema or rows change. The marker binds this copy's absolute path;
    the draft refuses ordinary stores or copies moved to another directory.
    """
    source_home, target_home = source_home.resolve(), target_home.resolve()
    source_path = source_home / "state" / "tw.db"
    if not source_path.is_file() or target_home == source_home or source_home in target_home.parents:
        raise ValueError("distinct disposable target required")
    target_home.mkdir(mode=0o700, parents=False, exist_ok=False)
    state = target_home / "state"
    state.mkdir(mode=0o700)
    target = state / "tw.db"
    inventory = {}
    with closing(sqlite3.connect(source_path.as_uri() + '?mode=ro', uri=True)) as source:
        with closing(sqlite3.connect(target)) as output:
            source.backup(output)
            if output.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise RuntimeError('adoption backup integrity check failed')
            output.row_factory = sqlite3.Row
            for table in ('meta','keyring','slots','projects','secrets','secret_versions'):
                inventory[table] = [{k:(v.hex() if isinstance(v,bytes) else v) for k,v in dict(row).items()}
                    for row in output.execute(f'SELECT * FROM {table} ORDER BY 1')]
    from .cloud_wire import hash_object
    os.chmod(target, 0o600)
    # Keep the original copy immutable: the working database changes during
    # journal commits, so its initial physical checksum cannot certify resumes.
    checkpoint = target_home / 'ADOPTION-SOURCE.db'
    shutil.copyfile(target, checkpoint)
    os.chmod(checkpoint, 0o400)
    marker = dict(format=1, source=str(source_path), target=str(target), checkpoint=str(checkpoint),
                  sha256=file_sha256(checkpoint), inventory_digest=hash_object(inventory))
    path = target_home / 'ADOPTION-DRAFT-COPY.json'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as out:
        out.write(json.dumps(marker, sort_keys=True, separators=(',', ':')))
        out.flush()
        os.fsync(out.fileno())
    return target_home


if __name__ == "__main__":
    raise SystemExit(main())
