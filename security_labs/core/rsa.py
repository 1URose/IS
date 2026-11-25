"""Самостоятельная реализация RSA с PKCS#1 v1.5 для учебной работы."""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Union

from .number_theory import inverse_mod, is_probable_prime, mod_pow

DEFAULT_BITS = 32768
PUBLIC_EXPONENT = 65537


@dataclass(frozen=True)
class PublicKey:
    n: int
    e: int = PUBLIC_EXPONENT

    @property
    def bytes_length(self) -> int:
        return (self.n.bit_length() + 7) // 8


@dataclass(frozen=True)
class PrivateKey:
    n: int
    e: int
    d: int
    p: int
    q: int
    dp: int
    dq: int
    q_inverse: int

    @property
    def public(self) -> PublicKey:
        return PublicKey(self.n, self.e)

    @property
    def bytes_length(self) -> int:
        return (self.n.bit_length() + 7) // 8


def generate_prime(bits: int, e: int = PUBLIC_EXPONENT, rounds: int = 32) -> int:
    if bits < 16:
        raise ValueError("длина простого должна быть не менее 16 бит")
    while True:
        # Две старшие единицы гарантируют полную длину произведения p*q.
        candidate = secrets.randbits(bits) | (3 << (bits - 2)) | 1
        if (candidate - 1) % e and is_probable_prime(candidate, rounds):
            return candidate


def from_primes(p: int, q: int, e: int = PUBLIC_EXPONENT) -> PrivateKey:
    if p == q or p <= 2 or q <= 2:
        raise ValueError("требуются два различных нечётных простых")
    phi = (p - 1) * (q - 1)
    d = inverse_mod(e, phi)
    return PrivateKey(p * q, e, d, p, q, d % (p - 1), d % (q - 1), inverse_mod(q, p))


def generate_keypair(bits: int = DEFAULT_BITS, e: int = PUBLIC_EXPONENT) -> PrivateKey:
    if bits < 512 or bits % 2:
        raise ValueError("длина RSA-ключа должна быть чётной и не менее 512 бит")
    p = generate_prime(bits // 2, e)
    q = generate_prime(bits // 2, e)
    while q == p:
        q = generate_prime(bits // 2, e)
    return from_primes(p, q, e)


def encrypt_integer(key: PublicKey, message: int) -> int:
    if not 0 <= message < key.n:
        raise ValueError("сообщение должно быть в диапазоне [0, n)")
    return mod_pow(message, key.e, key.n)


def decrypt_integer(key: PrivateKey, cipher: int) -> int:
    """CRT уменьшает две степени примерно в четыре раза против c**d mod n."""
    if not 0 <= cipher < key.n:
        raise ValueError("шифртекст должен быть в диапазоне [0, n)")
    m_p = mod_pow(cipher, key.dp, key.p)
    m_q = mod_pow(cipher, key.dq, key.q)
    correction = (key.q_inverse * (m_p - m_q)) % key.p
    return m_q + key.q * correction


def _pad_pkcs1_v15(payload: bytes, block_size: int) -> bytes:
    padding_size = block_size - len(payload) - 3
    if padding_size < 8:
        raise ValueError("блок слишком велик для PKCS#1 v1.5")
    padding = bytearray()
    while len(padding) < padding_size:
        padding.extend(byte for byte in secrets.token_bytes(padding_size - len(padding)) if byte)
    return b"\x00\x02" + bytes(padding[:padding_size]) + b"\x00" + payload


def _unpad_pkcs1_v15(encoded: bytes) -> bytes:
    if len(encoded) < 11 or encoded[:2] != b"\x00\x02":
        raise ValueError("неверное PKCS#1 v1.5 дополнение")
    delimiter = encoded.find(b"\x00", 2)
    if delimiter < 10:
        raise ValueError("неверное PKCS#1 v1.5 дополнение")
    return encoded[delimiter + 1:]


def encrypt(key: PublicKey, data: bytes) -> bytes:
    block_size = key.bytes_length
    payload_size = block_size - 11
    chunks = [data[index:index + payload_size] for index in range(0, len(data), payload_size)] or [b""]
    return b"".join(encrypt_integer(key, int.from_bytes(_pad_pkcs1_v15(chunk, block_size), "big")).to_bytes(block_size, "big") for chunk in chunks)


def decrypt(key: PrivateKey, ciphertext: bytes) -> bytes:
    block_size = key.bytes_length
    if not ciphertext or len(ciphertext) % block_size:
        raise ValueError("шифртекст должен содержать целое число блоков RSA")
    restored = []
    for index in range(0, len(ciphertext), block_size):
        value = int.from_bytes(ciphertext[index:index + block_size], "big")
        restored.append(_unpad_pkcs1_v15(decrypt_integer(key, value).to_bytes(block_size, "big")))
    return b"".join(restored)


def _write_json(path: Union[str, Path], content: dict[str, str], private: bool) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(content, indent=2) + "\n", encoding="utf-8")
    if private:
        os.chmod(target, 0o600)


def save_private(path: Union[str, Path], key: PrivateKey) -> None:
    _write_json(path, {name: format(value, "x") for name, value in asdict(key).items()}, True)


def save_public(path: Union[str, Path], key: PublicKey) -> None:
    _write_json(path, {"n": format(key.n, "x"), "e": format(key.e, "x")}, False)


def load_public(path: Union[str, Path]) -> PublicKey:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    key = PublicKey(int(raw["n"], 16), int(raw["e"], 16))
    if key.n <= 3 or key.n % 2 == 0 or not 1 < key.e < key.n:
        raise ValueError("некорректный открытый RSA-ключ")
    return key


def load_private(path: Union[str, Path]) -> PrivateKey:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    names = {field.name for field in PrivateKey.__dataclass_fields__.values()}
    # The reference project calls the equivalent CRT coefficient ``qinv``.
    # Accept it so its saved RSA-32768 key can be verified without regeneration.
    if "qinv" in raw and "q_inverse" not in raw:
        raw["q_inverse"] = raw.pop("qinv")
    if set(raw) != names:
        raise ValueError("некорректный формат закрытого RSA-ключа")
    key = PrivateKey(**{name: int(raw[name], 16) for name in names})
    expected = from_primes(key.p, key.q, key.e)
    if key != expected:
        raise ValueError("несогласованные параметры закрытого RSA-ключа")
    return key
