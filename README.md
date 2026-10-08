# pwmanager - CLI Password Manager (learning project)

Encrypted local password vault. Uses only established crypto (`cryptography` library:
Scrypt + AES-256-GCM). **No home-made cryptography.**

## Setup
```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## Usage
```bash
python3 -m pwmanager init                       # create master password
python3 -m pwmanager add github.com ravi        # type password (hidden)
python3 -m pwmanager add github.com ravi -g --show   # generate one
python3 -m pwmanager generate --length 20       # just generate
python3 -m pwmanager search git [--show]        # search; masked unless --show
python3 -m pwmanager list
python3 -m pwmanager delete github.com [--username ravi] [-y]
python3 -m pwmanager export backup.json         # encrypted (own password)
python3 -m pwmanager import backup.json
python3 -m pwmanager export plain.json --plain  # DANGEROUS, unencrypted
python3 -m pwmanager change-master
```
Environment variables:
* `PWM_VAULT` - vault file location (default `~/.pwmanager/vault.json`)
* `PWM_MASTER_PASSWORD` - skip the prompt (automation only; insecure, warns)

## Tests
```bash
python3 -m unittest discover -s tests -v   # (pytest also works)
```

## Layout
| File | Role |
|---|---|
| `pwmanager/crypto.py` | ALL crypto calls (Scrypt, AES-GCM, HMAC) |
| `pwmanager/vault.py` | master password, entries, export/import |
| `pwmanager/storage.py` | secure file writing, env var path |
| `pwmanager/generator.py` | `secrets`-based password generator |
| `pwmanager/cli.py` | argparse commands |
| `LEARNING.md` | the security concepts + exercises |

## Limits (be honest in interviews)
Local-only, single user; no clipboard auto-clear; secrets live in Python memory
while running (Python can't reliably wipe memory); not audited. For real use,
prefer Bitwarden/KeePassXC.
