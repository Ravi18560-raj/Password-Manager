"""SECURE STORAGE: how the vault file is written to disk.

* File permissions 0600 (owner read/write only) on POSIX.
* Atomic write: write temp file -> fsync -> rename. A crash can't leave a
  half-written (corrupt) vault.
* Location comes from an ENVIRONMENT VARIABLE (PWM_VAULT) or a safe default.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

ENV_VAULT_PATH = "PWM_VAULT"


def default_vault_path() -> Path:
    env = os.environ.get(ENV_VAULT_PATH)
    if env:
        return Path(env).expanduser()
    return Path.home() / ".pwmanager" / "vault.json"


def write_secure(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)  # atomic on same filesystem
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def check_permissions(path: Path) -> str | None:
    """Return a warning string if the vault is readable by others."""
    if os.name != "posix" or not path.exists():
        return None
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        return f"Vault permissions are {oct(mode)}; should be 0o600. Fix: chmod 600 {path}"
    return None
