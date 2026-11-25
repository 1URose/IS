"""Integration check for the saved RSA-32768 demonstration key.

The reference project ships a generated key and verifies it rather than
generating two 16,384-bit primes during every test run.
"""

import unittest
from pathlib import Path

from security_labs.core import rsa


class Rsa32768IntegrationTests(unittest.TestCase):
    KEY_PATH = Path(__file__).resolve().parents[1] / "results" / "verification" / "keys" / "rsa32768.private.json"

    def test_saved_key_encrypt_decrypt(self):
        if not self.KEY_PATH.exists():
            self.skipTest("saved RSA-32768 key is absent")

        key = rsa.load_private(self.KEY_PATH)
        self.assertEqual(key.n.bit_length(), 32768)
        self.assertEqual(key.p.bit_length(), 16384)
        self.assertEqual(key.q.bit_length(), 16384)
        self.assertNotEqual(key.p, key.q)
        self.assertEqual(key.e, 65537)
        self.assertEqual(key.p * key.q, key.n)
        self.assertEqual(key.e * key.d % ((key.p - 1) * (key.q - 1)), 1)

        # Two RSA blocks exercise chunking and PKCS#1 v1.5 padding.
        message = b"RSA-32768 integration check: " + b"x" * key.bytes_length
        ciphertext = rsa.encrypt(key.public, message)
        self.assertEqual(len(ciphertext), 2 * key.bytes_length)
        self.assertEqual(rsa.decrypt(key, ciphertext), message)
