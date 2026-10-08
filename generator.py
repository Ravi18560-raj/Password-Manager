"""Password generation using the `secrets` module (CSPRNG).

Never use `random` for passwords: it is predictable (Mersenne Twister).
"""
import secrets
import string

AMBIGUOUS = set("Il1O0o")


def generate_password(length: int = 16, *, upper=True, lower=True, digits=True,
                      symbols=True, avoid_ambiguous=False) -> str:
    if length < 8:
        raise ValueError("Password length must be at least 8.")
    pools = []
    if lower:
        pools.append(string.ascii_lowercase)
    if upper:
        pools.append(string.ascii_uppercase)
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append("!@#$%^&*()-_=+[]{};:,.?")
    if avoid_ambiguous:
        pools = ["".join(c for c in p if c not in AMBIGUOUS) for p in pools]
    if not pools:
        raise ValueError("Select at least one character type.")
    if length < len(pools):
        raise ValueError("Length too short for the chosen character types.")
    # Guarantee one char from every selected pool, fill the rest from the union.
    chars = [secrets.choice(p) for p in pools]
    union = "".join(pools)
    chars += [secrets.choice(union) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)
