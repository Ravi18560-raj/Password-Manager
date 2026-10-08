# Security Learning Guide

Read each section, then find the matching code and do the exercise.

## 1. Hashing  -> `crypto.derive_key`, `make_verifier`
A hash is a one-way function: easy forward, infeasible to reverse. Same input
always gives same output; tiny change -> totally different output.
* **Fast hashes (SHA-256) are bad for passwords**: attackers try billions of guesses/sec.
* **Password hashing/KDFs** (Scrypt, Argon2, bcrypt, PBKDF2) are deliberately slow
  (scrypt also needs lots of memory), making brute force expensive.
* **Salt**: random per-vault bytes mixed in, stored openly. Defeats precomputed
  (rainbow) tables and makes identical passwords hash differently.
* Compare secrets with `hmac.compare_digest` (constant time), not `==`.
* We never store the master password. We store salt + a verifier.
**Exercise:** time `derive_key` with n=2**10 vs 2**15 vs 2**18. Why is slower better here?

## 2. Encryption  -> `crypto.encrypt / decrypt`
Hashing is one-way; encryption is two-way with a key.
* **Symmetric** (same key to lock/unlock): AES. **Asymmetric**: RSA/ECC (not used here).
* **AES-GCM** is *authenticated*: besides secrecy it detects tampering (the tag).
  Flip one byte of the vault and decryption fails (see `test_tampered_file_detected`).
* **Nonce**: unique per encryption; reusing a nonce with the same key breaks GCM.
  We use a fresh random 12-byte nonce each save.
* **Key derivation**: the user's password isn't a good key; Scrypt turns it into a
  uniform 256-bit key.
* Hash vs encrypt vs encode: base64 is *encoding*, NOT security.
**Exercise:** open the vault file. What's visible? What isn't? Edit one char in `data`, try to unlock.

## 3. Environment variables  -> `storage.py`, `cli.py`
Key/value settings inherited by processes.
* Good for **config** (`PWM_VAULT` path) - keeps paths out of code.
* Risky for **secrets** (`PWM_MASTER_PASSWORD`): visible to child processes, in
  `/proc/<pid>/environ`, shell history if set inline, CI logs, crash dumps.
  Hence the warning; prefer prompts (`getpass`) or a secrets manager.
* Never hard-code secrets or commit them to git (add `.env`, vault files to `.gitignore`).
**Exercise:** `PWM_VAULT=/tmp/test.json python3 -m pwmanager init`. Then `env | grep PWM`.

## 4. Secure storage  -> `storage.write_secure`, `vault.py`
* Encrypt at rest; plaintext only in memory, briefly.
* File mode `0600`, directory `0700` (check with `ls -l`).
* Atomic writes (temp file + `os.replace`) so a crash can't corrupt the vault.
* Never take secrets as CLI arguments (`ps`, shell history leak them).
* Mask output by default; plain exports need explicit confirmation.
* Backups (export) are encrypted under their own password + salt.
* `secrets` (not `random`) for anything security-related.
* Store KDF params in the file so you can raise the cost later (crypto agility).

## 5. Threat model - what this does and doesn't protect
Protects: stolen vault file, casual snooping, tampering.
Doesn't: keyloggers/malware on your machine, weak master password, shoulder
surfing with `--show`, memory scraping while unlocked.

## Next steps / stretch goals
1. Swap Scrypt for Argon2id (`pip install argon2-cffi`) and compare.
2. Clipboard copy with auto-clear after 15 s.
3. Auto-lock/session timeout; failed-attempt lockout stored on disk.
4. Password-breach check via HIBP k-anonymity API (hash prefix only).
5. Add entropy/strength estimation for entries.
6. Read about OWASP Password Storage Cheat Sheet and "Have I Been Pwned".
