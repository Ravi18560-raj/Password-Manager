import time
from pwmanager import crypto

salt = crypto.random_bytes(16)

for n in (2**10, 2**14, 2**15, 2**18):
    params = crypto.KdfParams(n=n, r=8, p=1)
    start = time.perf_counter()
    crypto.derive_key("my-master-password", salt, params)
    print(f"n={n:>7}  took {time.perf_counter() - start:.3f}s")