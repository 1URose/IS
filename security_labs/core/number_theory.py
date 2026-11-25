"""Минимальный набор арифметики для RSA и эллиптических кривых."""

from __future__ import annotations

import secrets


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Возвращает gcd(a, b) и коэффициенты Безу."""
    old_r, r, old_x, x, old_y, y = a, b, 1, 0, 0, 1
    while r:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_x, x = x, old_x - quotient * x
        old_y, y = y, old_y - quotient * y
    return old_r, old_x, old_y


def inverse_mod(value: int, modulus: int) -> int:
    gcd, inverse, _ = extended_gcd(value % modulus, modulus)
    if gcd != 1:
        raise ValueError("обратный элемент не существует")
    return inverse % modulus


def mod_pow(base: int, exponent: int, modulus: int) -> int:
    """Собственное двоичное возведение в степень по модулю."""
    if modulus <= 0 or exponent < 0:
        raise ValueError("некорректные параметры степени")
    result = 1 % modulus
    base %= modulus
    while exponent:
        if exponent & 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent >>= 1
    return result


_SMALL_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
                 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109,
                 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
                 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241,
                 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313,
                 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389,
                 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461,
                 463, 467, 479, 487, 491, 499)


def is_probable_prime(candidate: int, rounds: int = 32) -> bool:
    """Тест Миллера-Рабина; ошибка для составного <= 4**-rounds."""
    if candidate < 2:
        return False
    for prime in _SMALL_PRIMES:
        if candidate == prime:
            return True
        if candidate % prime == 0:
            return False
    odd = candidate - 1
    shifts = 0
    while not odd & 1:
        odd >>= 1
        shifts += 1
    # Фиксированное основание ускоряет отбрасывание большинства составных.
    bases = [2] + [secrets.randbelow(candidate - 3) + 2 for _ in range(rounds - 1)]
    for base in bases:
        x = mod_pow(base, odd, candidate)
        if x in (1, candidate - 1):
            continue
        for _ in range(shifts - 1):
            x = (x * x) % candidate
            if x == candidate - 1:
                break
        else:
            return False
    return True
