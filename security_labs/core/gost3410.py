"""ГОСТ Р 34.10-2012: подпись на эллиптических кривых TC26."""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple, Union

from .number_theory import inverse_mod
from .streebog import streebog256, streebog512

Point = Optional[Tuple[int, int]]


@dataclass(frozen=True)
class Curve:
    name: str; p: int; a: int; b: int; q: int; gx: int; gy: int
    @property
    def coordinate_size(self) -> int: return 64 if self.q.bit_length() > 256 else 32


TEST_256 = Curve("gost-test-256", 0x8000000000000000000000000000000000000000000000000000000000000431, 7, 0x5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E, 0x8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3, 2, 0x08E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8)
TC26_512_A = Curve("tc26-512-A", 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4, 0xE8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275, 3, 0x7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4)
CURVES = {curve.name: curve for curve in (TEST_256, TC26_512_A)}
DEFAULT_CURVE = TC26_512_A


def base_point(curve: Curve) -> Point: return curve.gx, curve.gy

def is_on_curve(curve: Curve, point: Point) -> bool:
    return point is None or (0 <= point[0] < curve.p and 0 <= point[1] < curve.p and (point[1] * point[1] - point[0] ** 3 - curve.a * point[0] - curve.b) % curve.p == 0)


def add(curve: Curve, first: Point, second: Point) -> Point:
    if first is None: return second
    if second is None: return first
    x1, y1 = first; x2, y2 = second
    if x1 == x2 and (y1 + y2) % curve.p == 0: return None
    if first == second:
        slope = (3 * x1 * x1 + curve.a) * inverse_mod(2 * y1, curve.p) % curve.p
    else:
        slope = (y2 - y1) * inverse_mod(x2 - x1, curve.p) % curve.p
    x3 = (slope * slope - x1 - x2) % curve.p
    return x3, (slope * (x1 - x3) - y1) % curve.p


def multiply(curve: Curve, scalar: int, point: Point) -> Point:
    if scalar < 0 or not is_on_curve(curve, point): raise ValueError("некорректная точка или множитель")
    result = None
    while scalar:
        if scalar & 1: result = add(curve, result, point)
        point = add(curve, point, point)
        scalar >>= 1
    return result


def generate_keypair(curve: Curve = DEFAULT_CURVE) -> tuple[int, Point]:
    secret = secrets.randbelow(curve.q - 1) + 1
    return secret, multiply(curve, secret, base_point(curve))


def _hash_number(curve: Curve, data: bytes) -> int:
    digest = streebog512(data) if curve.coordinate_size == 64 else streebog256(data)
    return int.from_bytes(digest, "little")


def sign_hash(curve: Curve, hash_number: int, secret: int, nonce: Optional[int] = None) -> Tuple[int, int]:
    if not 0 < secret < curve.q: raise ValueError("закрытый ключ вне диапазона")
    e = hash_number % curve.q or 1
    while True:
        k = nonce if nonce is not None else secrets.randbelow(curve.q - 1) + 1
        point = multiply(curve, k, base_point(curve)); assert point is not None
        r = point[0] % curve.q
        s = (r * secret + k * e) % curve.q
        if r and s: return r, s
        if nonce is not None: raise ValueError("фиксированный nonce дал нулевой компонент")


def sign(data: bytes, secret: int, curve: Curve = DEFAULT_CURVE) -> bytes:
    r, s = sign_hash(curve, _hash_number(curve, data), secret)
    width = curve.coordinate_size
    return r.to_bytes(width, "big") + s.to_bytes(width, "big")


def verify(data: bytes, signature: bytes, public: Point, curve: Curve = DEFAULT_CURVE) -> bool:
    width = curve.coordinate_size
    if len(signature) != width * 2 or public is None or not is_on_curve(curve, public) or multiply(curve, curve.q, public) is not None: return False
    r, s = int.from_bytes(signature[:width], "big"), int.from_bytes(signature[width:], "big")
    if not (0 < r < curve.q and 0 < s < curve.q): return False
    e = _hash_number(curve, data) % curve.q or 1
    inv = inverse_mod(e, curve.q)
    point = add(curve, multiply(curve, s * inv % curve.q, base_point(curve)), multiply(curve, -r * inv % curve.q % curve.q, public))
    return point is not None and point[0] % curve.q == r


def save_private(path: Union[str, Path], curve: Curve, secret: int) -> None:
    target = Path(path); target.parent.mkdir(parents=True, exist_ok=True); target.write_text(json.dumps({"curve":curve.name,"d":f"{secret:x}"}, indent=2), encoding="utf-8"); os.chmod(target, 0o600)

def save_public(path: Union[str, Path], curve: Curve, public: Point) -> None:
    assert public is not None
    target = Path(path); target.parent.mkdir(parents=True, exist_ok=True); target.write_text(json.dumps({"curve":curve.name,"x":f"{public[0]:x}","y":f"{public[1]:x}"}, indent=2), encoding="utf-8")

def load_private(path: Union[str, Path]) -> Tuple[Curve, int]:
    raw = json.loads(Path(path).read_text(encoding="utf-8")); curve = CURVES[raw["curve"]]; secret = int(raw["d"], 16)
    if not 0 < secret < curve.q: raise ValueError("некорректный закрытый ключ")
    return curve, secret

def load_public(path: Union[str, Path]) -> Tuple[Curve, Point]:
    raw = json.loads(Path(path).read_text(encoding="utf-8")); curve = CURVES[raw["curve"]]; point = int(raw["x"],16), int(raw["y"],16)
    if not is_on_curve(curve, point) or multiply(curve, curve.q, point) is not None: raise ValueError("некорректный открытый ключ")
    return curve, point
