import json, os, stat, sys, tempfile, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pwmanager import crypto
from pwmanager.generator import generate_password
from pwmanager.vault import Vault, VaultError

FAST = crypto.KdfParams(n=2**10, r=8, p=1)   # fast for tests only
MASTER = "Correct-Horse-9"


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "v" / "vault.json"
    def tearDown(self): self.tmp.cleanup()
    def vault(self):
        v = Vault(self.path, FAST); v.create(MASTER); return v


class CryptoTests(unittest.TestCase):
    def test_roundtrip_and_tamper(self):
        k = crypto.random_bytes(32)
        blob = crypto.encrypt(k, b"secret")
        self.assertEqual(crypto.decrypt(k, blob), b"secret")
        bad = bytearray(blob); bad[-1] ^= 1
        with self.assertRaises(crypto.CryptoError): crypto.decrypt(k, bytes(bad))
        with self.assertRaises(crypto.CryptoError): crypto.decrypt(crypto.random_bytes(32), blob)
    def test_nonce_unique(self):
        k = crypto.random_bytes(32)
        self.assertNotEqual(crypto.encrypt(k, b"x"), crypto.encrypt(k, b"x"))
    def test_kdf_salt_matters(self):
        a = crypto.derive_key("pw", b"1"*16, FAST); b = crypto.derive_key("pw", b"2"*16, FAST)
        self.assertNotEqual(a, b)


class VaultTests(Base):
    def test_create_unlock_wrong_password(self):
        self.vault()
        Vault(self.path).unlock(MASTER)
        with self.assertRaises(VaultError): Vault(self.path).unlock("Wrong-Pass-123")
    def test_weak_master_rejected(self):
        with self.assertRaises(VaultError): Vault(self.path, FAST).create("abc")
    def test_no_plaintext_on_disk(self):
        v = self.vault(); v.add("github.com", "ravi", "SuperSecretPW!1")
        text = self.path.read_text()
        self.assertNotIn("SuperSecretPW", text); self.assertNotIn("github", text)
    def test_add_search_delete(self):
        v = self.vault(); v.add("GitHub.com", "ravi", "pw1"); v.add("gmail.com", "ravi", "pw2")
        self.assertEqual(len(v.search("git")), 1)
        with self.assertRaises(VaultError): v.add("github.com", "ravi", "x")
        self.assertEqual(v.delete("github.com"), 1)
        w = Vault(self.path); w.unlock(MASTER); self.assertEqual(len(w.entries), 1)
    @unittest.skipUnless(os.name == "posix", "posix perms")
    def test_permissions(self):
        self.vault()
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
    def test_tampered_file_detected(self):
        self.vault()
        doc = json.loads(self.path.read_text())
        raw = bytearray(crypto.b64d(doc["data"])); raw[20] ^= 1
        doc["data"] = crypto.b64e(bytes(raw)); self.path.write_text(json.dumps(doc))
        with self.assertRaises(VaultError): Vault(self.path).unlock(MASTER)
    def test_change_master(self):
        v = self.vault(); v.add("a.com", "u", "p1"); v.change_master("New-Master-Pass-1")
        with self.assertRaises(VaultError): Vault(self.path).unlock(MASTER)
        w = Vault(self.path); w.unlock("New-Master-Pass-1"); self.assertEqual(len(w.entries), 1)


class ExportImportTests(Base):
    def test_encrypted_roundtrip(self):
        v = self.vault(); v.add("a.com", "u", "p1")
        dest = Path(self.tmp.name) / "exp.json"; v.export_encrypted(dest, "Export-Pass-123")
        self.assertNotIn("p1", dest.read_text())
        other = Vault(Path(self.tmp.name) / "o.json", FAST); other.create(MASTER)
        self.assertEqual(other.import_file(dest, "Export-Pass-123"), (1, 0))
        self.assertEqual(other.import_file(dest, "Export-Pass-123"), (0, 1))  # dup skipped
        with self.assertRaises(VaultError): other.import_file(dest, "Wrong-Export-1")
    def test_plain_import(self):
        v = self.vault(); f = Path(self.tmp.name) / "p.json"
        f.write_text(json.dumps([{"site": "x.com", "username": "u", "password": "p"}, {"site": ""}]))
        self.assertEqual(v.import_file(f, None), (1, 1))


class GeneratorTests(unittest.TestCase):
    def test_properties(self):
        for _ in range(50):
            p = generate_password(20)
            self.assertEqual(len(p), 20)
            self.assertTrue(any(c.isdigit() for c in p) and any(c.isupper() for c in p)
                            and any(c.islower() for c in p))
    def test_errors(self):
        with self.assertRaises(ValueError): generate_password(4)
        with self.assertRaises(ValueError):
            generate_password(12, upper=False, lower=False, digits=False, symbols=False)


if __name__ == "__main__":
    unittest.main()
