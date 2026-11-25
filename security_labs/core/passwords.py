"""Хранение паролей через PBKDF2-HMAC-Стрибог с солью."""

from __future__ import annotations

import hmac
import secrets

from .streebog import pbkdf2


def make_password_record(password: str, iterations: int = 200) -> str:
    if iterations < 1:
        raise ValueError("число итераций должно быть положительным")
    salt = secrets.token_bytes(16)
    digest = pbkdf2(password.encode("utf-8"), salt, iterations, 64)
    return f"pbkdf2-streebog512${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, record: str) -> bool:
    try:
        label, text_iterations, text_salt, text_digest = record.split("$")
        if label != "pbkdf2-streebog512":
            return False
        expected = bytes.fromhex(text_digest)
        received = pbkdf2(password.encode("utf-8"), bytes.fromhex(text_salt), int(text_iterations), len(expected))
        return hmac.compare_digest(received, expected)
    except (ValueError, TypeError):
        return False
