"""Names-only dotenv import with quarantine and policy enforcement."""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Callable, Mapping


KEY_RE = re.compile(rb"^[A-Za-z_][A-Za-z0-9_]*$")
SECRET_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
PLACEHOLDERS = {b"", b"changeme", b"change-me", b"xxx", b"todo", b"replace-me"}


class EnvImportError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _unquote(value: bytes) -> bytes:
    stripped = value.strip()
    if len(stripped) >= 2 and stripped[:1] == stripped[-1:] and stripped[:1] in {b"'", b'"'}:
        inner = stripped[1:-1]
        if stripped[:1] == b'"':
            inner = (
                inner.replace(b"\\n", b"\n")
                .replace(b"\\r", b"\r")
                .replace(b"\\t", b"\t")
                .replace(b'\\"', b'"')
                .replace(b"\\\\", b"\\")
            )
        return inner
    return stripped


def parse_dotenv(payload: bytes) -> list[tuple[str, bytes]]:
    entries: list[tuple[str, bytes]] = []
    for line_number, raw_line in enumerate(payload.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith(b"#"):
            continue
        if line.startswith(b"export "):
            line = line[7:].lstrip()
        key, separator, raw_value = line.partition(b"=")
        key = key.strip()
        if not separator or not KEY_RE.fullmatch(key):
            raise EnvImportError("E_POLICY", f"invalid dotenv syntax on line {line_number}")
        entries.append((key.decode("ascii"), _unquote(raw_value)))
    return entries


def _is_placeholder(value: bytes) -> bool:
    lowered = value.strip().lower()
    return lowered in PLACEHOLDERS or (lowered.startswith(b"<") and lowered.endswith(b">"))


def _secret_name(variable: str) -> str:
    name = variable.lower().replace("_", "-")
    if not SECRET_NAME_RE.fullmatch(name):
        raise EnvImportError("E_POLICY", f"variable {variable} cannot become a secret name")
    return name


def _git_origin(path: Path) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(path.parent), "config", "--get", "remote.origin.url"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return completed.stdout.strip() or None


def _contains_symlink(path: Path) -> bool:
    candidate = path.expanduser().absolute()
    root = Path(candidate.anchor)
    while True:
        if candidate == root or candidate.parent == root:
            return False
        if candidate.is_symlink():
            return True
        candidate = candidate.parent


class EnvImporter:
    def __init__(
        self,
        policy_path: str | os.PathLike[str],
        *,
        store_value: Callable[[str, bytes, str], Mapping[str, object]],
        store_quarantine: Callable[[str, str, bytes], str],
    ):
        self.policy_path = Path(policy_path)
        self.store_value = store_value
        self.store_quarantine = store_quarantine

    def _policies(self) -> dict[str, dict[str, object]]:
        return json.loads(self.policy_path.read_text(encoding="utf-8"))

    def _refuse_before_read(
        self, path: Path, project: str, extra_path_roots: tuple[str, ...] = ()
    ) -> None:
        policies = self._policies()
        client_policy = policies.get("client", {})
        if project == "client" and client_policy.get("import_env") == "refuse":
            raise EnvImportError("E_POLICY", "dotenv import is disabled by project policy")
        if _contains_symlink(path):
            raise EnvImportError("E_POLICY", "dotenv import through a symlink is disabled")
        try:
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise EnvImportError("E_POLICY", "dotenv source is unavailable") from exc
        for root_text in (*client_policy.get("path_roots", []), *extra_path_roots):
            root = Path(str(root_text)).expanduser().resolve(strict=False)
            if resolved == root or root in resolved.parents:
                raise EnvImportError("E_POLICY", "dotenv import is disabled by repository policy")
        origin = _git_origin(resolved)
        if origin and any(
            str(pattern).casefold() in origin.casefold()
            for pattern in client_policy.get("repo_patterns", [])
        ):
            raise EnvImportError("E_POLICY", "dotenv import is disabled by repository policy")

    def ensure_allowed(
        self,
        path: str | os.PathLike[str],
        project: str,
        *,
        extra_path_roots: tuple[str, ...] = (),
    ) -> None:
        self._refuse_before_read(Path(path).expanduser(), project, extra_path_roots)

    def import_file(
        self,
        path: str | os.PathLike[str],
        project: str,
        *,
        extra_path_roots: tuple[str, ...] = (),
    ) -> dict[str, object]:
        source = Path(path).expanduser()
        self.ensure_allowed(source, project, extra_path_roots=extra_path_roots)
        payload = source.read_bytes()
        entries = parse_dotenv(payload)
        stored: list[dict[str, object]] = []
        skipped: list[str] = []
        manifest_lines: list[str] = []
        for variable, value in entries:
            if _is_placeholder(value):
                skipped.append(variable)
                continue
            name = _secret_name(variable)
            secret_path = f"{project}/{name}"
            receipt = dict(self.store_value(secret_path, value, "import_env"))
            stored.append(
                {
                    "name": name,
                    "path": secret_path,
                    "version_no": receipt.get("version_no"),
                    **({"linked_to": receipt["linked_to"]} if "linked_to" in receipt else {}),
                }
            )
            manifest_reference = str(receipt.get("linked_to", secret_path))
            manifest_lines.append(f"{variable}=tw://{manifest_reference}\n")

        quarantine_id = self.store_quarantine(project, str(source.resolve()), payload)
        manifest = source.with_name(".env.tw")
        manifest.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(prefix=".env.tw.", dir=manifest.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as output:
                output.writelines(manifest_lines)
                output.flush()
                os.fsync(output.fileno())
            os.chmod(temporary_name, 0o600)
            os.replace(temporary_name, manifest)
        finally:
            if os.path.exists(temporary_name):
                os.unlink(temporary_name)
        os.chmod(source, 0o600)
        return {
            "stored": stored,
            "skipped": skipped,
            "manifest_path": str(manifest),
            "quarantine_id": quarantine_id,
        }


def parse_manifest(
    path: str | os.PathLike[str], stored_value_matches: Callable[[bytes], bool]
) -> dict[str, dict[str, str]]:
    env_refs: dict[str, str] = {}
    literals: dict[str, str] = {}
    payload = Path(path).read_bytes()
    for line_number, raw_line in enumerate(payload.splitlines(), 1):
        try:
            parsed = parse_dotenv(raw_line + b"\n")
        except EnvImportError as exc:
            raise EnvImportError(exc.code, f"invalid manifest syntax on line {line_number}") from exc
        if not parsed:
            continue
        variable, value = parsed[0]
        if value.startswith(b"tw://"):
            reference = value[5:].decode("ascii", "strict")
            if reference.count("/") != 1:
                raise EnvImportError("E_POLICY", f"invalid secret reference on line {line_number}")
            env_refs[variable] = reference
            continue
        if stored_value_matches(value):
            raise EnvImportError(
                "E_POLICY",
                f".env.tw line {line_number} holds a stored secret value; replace it with tw://PATH",
            )
        literals[variable] = value.decode("utf-8")
    return {"env_refs": env_refs, "literals": literals}
