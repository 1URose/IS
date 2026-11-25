"""Файловый контейнер Кузнечика: CTR + PBKDF2 + HMAC-Стрибог."""

from __future__ import annotations

import hmac
import secrets
import struct

from .kuznyechik import Kuznyechik, ctr_crypt
from .streebog import hmac512, pbkdf2

MAGIC = b"KZC1"


def encrypt_password(data: bytes, password: str, iterations: int = 200) -> bytes:
    if iterations < 1:
        raise ValueError("число итераций должно быть положительным")
    salt, iv = secrets.token_bytes(16), secrets.token_bytes(8)
    material = pbkdf2(password.encode("utf-8"), salt, iterations, 64)
    header = MAGIC + struct.pack(">I", iterations) + salt + iv
    encrypted = ctr_crypt(Kuznyechik(material[:32]), data, iv)
    return header + encrypted + hmac512(material[32:], header + encrypted)


def decrypt_password(container: bytes, password: str) -> bytes:
    if len(container) < 4 + 4 + 16 + 8 + 64 or container[:4] != MAGIC:
        raise ValueError("это не контейнер KZC1")
    iterations = struct.unpack(">I", container[4:8])[0]
    salt, iv = container[8:24], container[24:32]
    header, encrypted, tag = container[:32], container[32:-64], container[-64:]
    material = pbkdf2(password.encode("utf-8"), salt, iterations, 64)
    if not hmac.compare_digest(hmac512(material[32:], header + encrypted), tag):
        raise ValueError("неверный пароль либо повреждённый файл")
    return ctr_crypt(Kuznyechik(material[:32]), encrypted, iv)
