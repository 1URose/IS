"""Учебная подпись PDF для лабораторной 4.

Это не PAdES/CMS. Запись с подписью добавляется PDF-комментарием после %%EOF,
поэтому обычный просмотрщик продолжает открывать исходный документ. Проверка
всегда требует отдельно переданный доверенный открытый ключ.
"""

from __future__ import annotations

import base64
import json

from . import gost3410 as gost

MARKER = b"\n% SECURITY-LABS-GOST-SIGNATURE "


def sign_pdf_bytes(document: bytes, secret: int, curve: gost.Curve) -> bytes:
    """Подписывает исходные байты PDF и добавляет учебный trailer-комментарий."""
    if not document.startswith(b"%PDF-"):
        raise ValueError("ожидается файл PDF")
    public = gost.multiply(curve, secret, gost.base_point(curve))
    if public is None:
        raise ValueError("не удалось получить открытый ключ")
    payload = {
        "format": "security-labs-gost-trailer-v1",
        "curve": curve.name,
        "public": {"x": f"{public[0]:x}", "y": f"{public[1]:x}"},
        "signature": gost.sign(document, secret, curve).hex(),
    }
    encoded = base64.b64encode(json.dumps(payload, separators=(",", ":")).encode("ascii"))
    return document + MARKER + encoded + b"\n"


def verify_pdf_bytes(signed_document: bytes, trusted_curve: gost.Curve, trusted_public: gost.Point) -> bool:
    """Проверяет подпись, ключ и отсутствие данных после контейнера подписи."""
    document, marker, encoded = signed_document.rpartition(MARKER)
    if not marker or not encoded.endswith(b"\n"):
        return False
    try:
        payload = json.loads(base64.b64decode(encoded[:-1], validate=True).decode("ascii"))
        if payload.get("format") != "security-labs-gost-trailer-v1":
            return False
        curve = gost.CURVES[payload["curve"]]
        public = (int(payload["public"]["x"], 16), int(payload["public"]["y"], 16))
        signature = bytes.fromhex(payload["signature"])
    except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    return curve == trusted_curve and public == trusted_public and gost.verify(document, signature, trusted_public, curve)
