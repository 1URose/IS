import unittest
import json
import tempfile
from pathlib import Path

from security_labs.core import rsa
from security_labs.core.number_theory import inverse_mod, is_probable_prime, mod_pow


class NumberTheoryTests(unittest.TestCase):
    def test_inverse_and_power(self):
        self.assertEqual(inverse_mod(17, 3120), 2753)
        self.assertEqual(mod_pow(7, 560, 561), pow(7, 560, 561))

    def test_miller_rabin(self):
        self.assertTrue(is_probable_prime(2**127 - 1))
        self.assertFalse(is_probable_prime(561))


class RsaTests(unittest.TestCase):
    def setUp(self):
        self.key = rsa.from_primes(61, 53, 17)

    def test_standard_vector(self):
        self.assertEqual(self.key.n, 3233)
        self.assertEqual(self.key.d, 2753)
        self.assertEqual(rsa.encrypt_integer(self.key.public, 65), 2790)
        self.assertEqual(rsa.decrypt_integer(self.key, 2790), 65)

    def test_randomized_blocks_and_unicode(self):
        key = rsa.generate_keypair(512)
        data = ("Проверка произвольной длины. ".encode("utf-8")) * 20
        first = rsa.encrypt(key.public, data)
        second = rsa.encrypt(key.public, data)
        self.assertNotEqual(first, second)
        self.assertEqual(rsa.decrypt(key, first), data)

    def test_rejects_malformed_ciphertext_and_inconsistent_private_key(self):
        key = rsa.generate_keypair(512)
        with self.assertRaises(ValueError):
            rsa.decrypt(key, b"not-a-full-rsa-block")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.private.json"
            rsa.save_private(path, key)
            content = json.loads(path.read_text(encoding="utf-8"))
            content["d"] = "1"
            path.write_text(json.dumps(content), encoding="utf-8")
            with self.assertRaises(ValueError):
                rsa.load_private(path)


if __name__ == "__main__":
    unittest.main()
