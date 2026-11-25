import unittest

from security_labs.core import gost3410, kuznyechik, streebog
from security_labs.core.pdf_signature import sign_pdf_bytes, verify_pdf_bytes
from security_labs.core.kuznyechik_file import decrypt_password, encrypt_password
from security_labs.core.passwords import make_password_record, verify_password


class StreebogVectors(unittest.TestCase):
    def test_standard_vector_512_and_256(self):
        message = bytes.fromhex("32313039383736353433323130393837363534333231303938373635343332" "3130393837363534333231303938373635343332313039383736353433323130")[::-1]
        self.assertEqual(streebog.streebog512(message).hex(), "1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48")
        self.assertEqual(streebog.streebog256(message).hex(), "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500")

    def test_pbkdf2_and_password(self):
        record = make_password_record("Пароль")
        self.assertTrue(verify_password("Пароль", record)); self.assertFalse(verify_password("другой", record))


class KuznyechikVectors(unittest.TestCase):
    def test_block_vector(self):
        cipher = kuznyechik.Kuznyechik(bytes.fromhex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"))
        plain = bytes.fromhex("1122334455667700ffeeddccbbaa9988")
        self.assertEqual(cipher.encrypt_block(plain).hex(), "7f679d90bebc24305a468d42b9d4edcd")
        self.assertEqual(cipher.decrypt_block(cipher.encrypt_block(plain)), plain)

    def test_ctr_vector(self):
        cipher = kuznyechik.Kuznyechik(bytes.fromhex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"))
        plain = bytes.fromhex("1122334455667700ffeeddccbbaa9988" "00112233445566778899aabbcceeff0a" "112233445566778899aabbcceeff0a00" "2233445566778899aabbcceeff0a0011")
        self.assertEqual(kuznyechik.ctr_crypt(cipher, plain, bytes.fromhex("1234567890abcef0")).hex(), "f195d8bec10ed1dbd57b5fa240bda1b8" "85eee733f6a13e5df33ce4b33c45dee4" "a5eae88be6356ed3d5e877f13564a3a5" "cb91fab1f20cbab6d1c6d15820bdba73")

    def test_password_container(self):
        packed = encrypt_password(b"binary\x00data", "secret", 2)
        self.assertEqual(decrypt_password(packed, "secret"), b"binary\x00data")
        with self.assertRaises(ValueError): decrypt_password(packed, "wrong")
        with self.assertRaises(ValueError): decrypt_password(b"not a container", "secret")


class SignatureVectors(unittest.TestCase):
    def test_rfc7091_signing_example(self):
        curve = gost3410.TEST_256
        secret = 0x7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28
        digest = 0x2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5
        nonce = 0x77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3
        self.assertEqual(gost3410.multiply(curve, secret, gost3410.base_point(curve)), (0x7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B,0x26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA))
        self.assertEqual(gost3410.sign_hash(curve, digest, secret, nonce), (0x41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493,0x01456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40))

    def test_sign_and_verify(self):
        secret, public = gost3410.generate_keypair(); signature = gost3410.sign(b"signed", secret)
        self.assertTrue(gost3410.verify(b"signed", signature, public)); self.assertFalse(gost3410.verify(b"altered", signature, public))

    def test_pdf_trailer_signature_detects_all_changes(self):
        secret, public = gost3410.generate_keypair()
        # Минимальные PDF-байты достаточны для проверки побайтной подписи.
        source = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"
        signed = sign_pdf_bytes(source, secret, gost3410.DEFAULT_CURVE)
        self.assertTrue(verify_pdf_bytes(signed, gost3410.DEFAULT_CURVE, public))
        self.assertFalse(verify_pdf_bytes(signed.replace(b"endobj", b"endObj"), gost3410.DEFAULT_CURVE, public))
        self.assertFalse(verify_pdf_bytes(signed + b"tampered", gost3410.DEFAULT_CURVE, public))
        _, other_public = gost3410.generate_keypair()
        self.assertFalse(verify_pdf_bytes(signed, gost3410.DEFAULT_CURVE, other_public))
