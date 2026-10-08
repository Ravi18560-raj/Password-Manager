"""Vault logic: master password, entries, search, delete, export/import.

On-disk file (JSON, but the secrets inside are encrypted):
{
  "version": 1,
  "kdf": {"n":..., "r":..., "p":...},
  "salt": "<b64>",          # for key derivation
  "verifier": "<b64>",      # lets us reject a wrong master password quickly
  "data": "<b64 nonce||AES-GCM(ciphertext+tag)>"   # all entries
}
Entries are kept in memory only while the program runs.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

from . import crypto
from .storage import write_secure

VERSION = 1
AAD = b"pwmanager-vault-v1"      # bound to ciphertext: swapping file types fails
EXPORT_AAD = b"pwmanager-export-v1"
MIN_MASTER_LEN = 12


class VaultError(Exception):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Entry:
    site: str
    username: str
    password: str
    notes: str = ""
    created: str = ""
    updated: str = ""


def check_master_strength(pw: str) -> list[str]:
    problems = []
    if len(pw) < MIN_MASTER_LEN:
        problems.append(f"at least {MIN_MASTER_LEN} characters")
    if pw.lower() == pw or pw.upper() == pw:
        problems.append("mixed upper and lower case")
    if not any(c.isdigit() for c in pw):
        problems.append("at least one digit")
    return problems


class Vault:
    def __init__(self, path: Path, params: crypto.KdfParams | None = None):
        self.path = Path(path)
        self.params = params or crypto.KdfParams()
        self._key: bytes | None = None
        self._salt: bytes | None = None
        self.entries: dict[str, Entry] = {}

    # ---- lifecycle -------------------------------------------------
    def exists(self) -> bool:
        return self.path.exists()

    def create(self, master: str) -> None:
        if self.exists():
            raise VaultError(f"Vault already exists at {self.path}")
        problems = check_master_strength(master)
        if problems:
            raise VaultError("Master password too weak. Needs: " + ", ".join(problems))
        self._salt = crypto.random_bytes(crypto.SALT_LEN)
        self._key = crypto.derive_key(master, self._salt, self.params)
        self.entries = {}
        self.save()

    def unlock(self, master: str) -> None:
        if not self.exists():
            raise VaultError("No vault found. Run 'init' first.")
        doc = json.loads(self.path.read_text())
        if doc.get("version") != VERSION:
            raise VaultError("Unsupported vault version.")
        params = crypto.KdfParams.from_dict(doc["kdf"])
        salt = crypto.b64d(doc["salt"])
        key = crypto.derive_key(master, salt, params)
        if not crypto.verify(key, salt, crypto.b64d(doc["verifier"])):
            raise VaultError("Wrong master password.")
        try:
            raw = crypto.decrypt(key, crypto.b64d(doc["data"]), AAD)
        except crypto.CryptoError as exc:
            raise VaultError(str(exc)) from exc
        self.params, self._salt, self._key = params, salt, key
        self.entries = {k: Entry(**v) for k, v in json.loads(raw).items()}

    def save(self) -> None:
        assert self._key is not None and self._salt is not None, "vault is locked"
        payload = json.dumps({k: asdict(v) for k, v in self.entries.items()}).encode()
        doc = {
            "version": VERSION,
            "kdf": self.params.to_dict(),
            "salt": crypto.b64e(self._salt),
            "verifier": crypto.b64e(crypto.make_verifier(self._key, self._salt)),
            "data": crypto.b64e(crypto.encrypt(self._key, payload, AAD)),
        }
        write_secure(self.path, json.dumps(doc, indent=2).encode())

    def change_master(self, new_master: str) -> None:
        problems = check_master_strength(new_master)
        if problems:
            raise VaultError("Master password too weak. Needs: " + ", ".join(problems))
        self._salt = crypto.random_bytes(crypto.SALT_LEN)   # fresh salt too
        self._key = crypto.derive_key(new_master, self._salt, self.params)
        self.save()

    # ---- entries ---------------------------------------------------
    @staticmethod
    def _id(site: str, username: str) -> str:
        return f"{site.strip().lower()}|{username.strip()}"

    def add(self, site: str, username: str, password: str, notes: str = "",
            overwrite: bool = False) -> Entry:
        if not site.strip() or not password:
            raise VaultError("Site and password are required.")
        eid = self._id(site, username)
        if eid in self.entries and not overwrite:
            raise VaultError("Entry exists for this site/username (use --overwrite).")
        old = self.entries.get(eid)
        e = Entry(site.strip(), username.strip(), password, notes,
                  created=old.created if old else _now(), updated=_now())
        self.entries[eid] = e
        self.save()
        return e

    def search(self, term: str) -> list[Entry]:
        t = term.lower()
        return sorted((e for e in self.entries.values()
                       if t in e.site.lower() or t in e.username.lower()
                       or t in e.notes.lower()), key=lambda e: e.site.lower())

    def list_all(self) -> list[Entry]:
        return self.search("")

    def delete(self, site: str, username: str | None = None) -> int:
        matches = [k for k, e in self.entries.items()
                   if e.site.lower() == site.strip().lower()
                   and (username is None or e.username == username)]
        for k in matches:
            del self.entries[k]
        if matches:
            self.save()
        return len(matches)

    # ---- export / import ------------------------------------------
    def export_encrypted(self, dest: Path, export_password: str) -> None:
        """Backup encrypted under its OWN password + fresh salt."""
        problems = check_master_strength(export_password)
        if problems:
            raise VaultError("Export password too weak. Needs: " + ", ".join(problems))
        salt = crypto.random_bytes(crypto.SALT_LEN)
        key = crypto.derive_key(export_password, salt, self.params)
        payload = json.dumps([asdict(e) for e in self.entries.values()]).encode()
        doc = {"type": "pwmanager-export", "version": VERSION,
               "kdf": self.params.to_dict(), "salt": crypto.b64e(salt),
               "data": crypto.b64e(crypto.encrypt(key, payload, EXPORT_AAD))}
        write_secure(Path(dest), json.dumps(doc, indent=2).encode())

    def export_plain(self, dest: Path) -> None:
        """DANGEROUS: unencrypted JSON. Caller must warn the user."""
        write_secure(Path(dest), json.dumps(
            [asdict(e) for e in self.entries.values()], indent=2).encode())

    def import_file(self, src: Path, export_password: str | None,
                    overwrite: bool = False) -> tuple[int, int]:
        """Returns (imported, skipped)."""
        try:
            doc = json.loads(Path(src).read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise VaultError(f"Cannot read import file: {exc}") from exc
        if isinstance(doc, dict) and doc.get("type") == "pwmanager-export":
            if export_password is None:
                raise VaultError("This export is encrypted; password required.")
            salt = crypto.b64d(doc["salt"])
            key = crypto.derive_key(export_password, salt,
                                    crypto.KdfParams.from_dict(doc["kdf"]))
            try:
                raw = crypto.decrypt(key, crypto.b64d(doc["data"]), EXPORT_AAD)
            except crypto.CryptoError as exc:
                raise VaultError(str(exc)) from exc
            items = json.loads(raw)
        elif isinstance(doc, list):
            items = doc
        else:
            raise VaultError("Unrecognized import format.")
        imported = skipped = 0
        for it in items:
            try:
                e = Entry(**{k: it.get(k, "") for k in
                             ("site", "username", "password", "notes", "created", "updated")})
            except AttributeError:
                skipped += 1
                continue
            eid = self._id(e.site, e.username)
            if not e.site or not e.password or (eid in self.entries and not overwrite):
                skipped += 1
                continue
            e.created = e.created or _now()
            e.updated = _now()
            self.entries[eid] = e
            imported += 1
        if imported:
            self.save()
        return imported, skipped
