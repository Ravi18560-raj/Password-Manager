"""Command-line interface (argparse).

Security habits shown here:
* Secrets are typed via getpass (no echo, never in shell history / `ps`).
  We deliberately do NOT accept passwords as command-line arguments.
* Passwords are masked in output unless you pass --show.
* PWM_MASTER_PASSWORD env var exists for scripting/tests only, with a warning:
  environment variables can leak (child processes, /proc, CI logs).
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
import time
from pathlib import Path

from .generator import generate_password
from .storage import ENV_VAULT_PATH, check_permissions, default_vault_path
from .vault import Entry, Vault, VaultError

ENV_MASTER = "PWM_MASTER_PASSWORD"


def ask_secret(prompt: str) -> str:
    return getpass.getpass(prompt)


def get_master(prompt="Master password: ") -> str:
    env = os.environ.get(ENV_MASTER)
    if env:
        print(f"warning: using {ENV_MASTER} from environment (insecure; "
              "for automation only).", file=sys.stderr)
        return env
    return ask_secret(prompt)


def open_vault(path: Path) -> Vault:
    v = Vault(path)
    warn = check_permissions(path)
    if warn:
        print("warning:", warn, file=sys.stderr)
    for attempt in range(3):
        try:
            v.unlock(get_master())
            return v
        except VaultError as exc:
            if "Wrong master" not in str(exc) or attempt == 2 or os.environ.get(ENV_MASTER):
                raise
            print(f"{exc} Try again.", file=sys.stderr)
            time.sleep(2 ** attempt)  # slow down guessing
    raise VaultError("Too many attempts.")


def show(e: Entry, reveal: bool) -> None:
    pw = e.password if reveal else "*" * 10
    print(f"- {e.site}\n    user: {e.username}\n    pass: {pw}")
    if e.notes:
        print(f"    notes: {e.notes}")


# ---- commands ------------------------------------------------------
def cmd_init(a, path):
    v = Vault(path)
    if v.exists():
        raise VaultError(f"Vault already exists at {path}")
    print("Choose a master password. It is NEVER stored and CANNOT be recovered.")
    pw = ask_secret("New master password: ")
    if pw != ask_secret("Confirm master password: "):
        raise VaultError("Passwords do not match.")
    v.create(pw)
    print(f"Vault created at {path}")


def cmd_add(a, path):
    v = open_vault(path)
    if a.generate:
        pw = generate_password(a.length)
        print("Generated a strong password.")
    else:
        pw = ask_secret("Password for entry: ")
    v.add(a.site, a.username, pw, a.notes or "", overwrite=a.overwrite)
    print(f"Saved {a.site} ({a.username}).")
    if a.generate and a.show:
        print("Password:", pw)


def cmd_generate(a, path):
    print(generate_password(a.length, symbols=not a.no_symbols,
                            avoid_ambiguous=a.avoid_ambiguous))


def cmd_search(a, path):
    v = open_vault(path)
    res = v.search(a.term)
    if not res:
        print("No matches.")
    for e in res:
        show(e, a.show)


def cmd_list(a, path):
    v = open_vault(path)
    for e in v.list_all():
        show(e, False)
    print(f"{len(v.entries)} entries.")


def cmd_delete(a, path):
    v = open_vault(path)
    if not a.yes and input(f"Delete all entries for '{a.site}'? [y/N] ").lower() != "y":
        print("Cancelled.")
        return
    n = v.delete(a.site, a.username)
    print(f"Deleted {n} entr{'y' if n == 1 else 'ies'}.")


def cmd_export(a, path):
    v = open_vault(path)
    dest = Path(a.file)
    if dest.exists():
        raise VaultError(f"{dest} already exists; refusing to overwrite.")
    if a.plain:
        print("DANGER: plain export is NOT encrypted. Anyone can read it.")
        if input("Type 'yes' to continue: ") != "yes":
            print("Cancelled.")
            return
        v.export_plain(dest)
    else:
        pw = ask_secret("Export password (can differ from master): ")
        if pw != ask_secret("Confirm export password: "):
            raise VaultError("Passwords do not match.")
        v.export_encrypted(dest, pw)
    print(f"Exported {len(v.entries)} entries to {dest}")


def cmd_import(a, path):
    v = open_vault(path)
    pw = None
    if not a.plain:
        pw = ask_secret("Export password: ")
    imported, skipped = v.import_file(Path(a.file), pw, overwrite=a.overwrite)
    print(f"Imported {imported}, skipped {skipped}.")


def cmd_change_master(a, path):
    v = open_vault(path)
    pw = ask_secret("New master password: ")
    if pw != ask_secret("Confirm new master password: "):
        raise VaultError("Passwords do not match.")
    v.change_master(pw)
    print("Master password changed; vault re-encrypted with a new salt and key.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pwmanager", description="CLI password manager")
    p.add_argument("--vault", help=f"vault file (default: ${ENV_VAULT_PATH} or ~/.pwmanager/vault.json)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create vault + master password").set_defaults(fn=cmd_init)

    s = sub.add_parser("add", help="add a password")
    s.add_argument("site"); s.add_argument("username")
    s.add_argument("--notes"); s.add_argument("--overwrite", action="store_true")
    s.add_argument("--generate", "-g", action="store_true", help="generate instead of typing")
    s.add_argument("--length", type=int, default=16)
    s.add_argument("--show", action="store_true", help="print generated password")
    s.set_defaults(fn=cmd_add)

    s = sub.add_parser("generate", help="generate a password (no vault needed)")
    s.add_argument("--length", type=int, default=16)
    s.add_argument("--no-symbols", action="store_true")
    s.add_argument("--avoid-ambiguous", action="store_true")
    s.set_defaults(fn=cmd_generate)

    s = sub.add_parser("search", help="search site/username/notes")
    s.add_argument("term"); s.add_argument("--show", action="store_true")
    s.set_defaults(fn=cmd_search)

    sub.add_parser("list", help="list entries (masked)").set_defaults(fn=cmd_list)

    s = sub.add_parser("delete", help="delete entries for a site")
    s.add_argument("site"); s.add_argument("--username")
    s.add_argument("--yes", "-y", action="store_true")
    s.set_defaults(fn=cmd_delete)

    s = sub.add_parser("export", help="export (encrypted by default)")
    s.add_argument("file"); s.add_argument("--plain", action="store_true")
    s.set_defaults(fn=cmd_export)

    s = sub.add_parser("import", help="import an export file")
    s.add_argument("file"); s.add_argument("--plain", action="store_true")
    s.add_argument("--overwrite", action="store_true")
    s.set_defaults(fn=cmd_import)

    sub.add_parser("change-master", help="change master password").set_defaults(fn=cmd_change_master)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    path = Path(args.vault).expanduser() if args.vault else default_vault_path()
    try:
        args.fn(args, path)
    except VaultError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\nAborted.", file=sys.stderr)
        return 130
    return 0
