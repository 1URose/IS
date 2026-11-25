"""CLI лабораторной 1: RSA-32768."""

from __future__ import annotations

import argparse
from pathlib import Path

from .core import rsa


def _input_bytes(args: argparse.Namespace) -> bytes:
    if args.text is not None:
        return args.text.encode("utf-8")
    return Path(args.input).read_bytes()


def demo(_: argparse.Namespace) -> None:
    key = rsa.from_primes(61, 53, 17)
    cipher = rsa.encrypt_integer(key.public, 65)
    print("RSA: p=61, q=53, e=17")
    print(f"n={key.n}; d={key.d}; 65 -> {cipher} -> {rsa.decrypt_integer(key, cipher)}")
    # 512 бит выбраны только для защиты: требуемая команда keygen по умолчанию
    # остаётся RSA-32768, но её генерация может длиться долго.
    quick_key = rsa.generate_keypair(512)
    payload = "Демонстрация PKCS#1 v1.5".encode("utf-8")
    encrypted = rsa.encrypt(quick_key.public, payload)
    print(f"Быстрый демонстрационный RSA-{quick_key.n.bit_length()}: ",
          rsa.decrypt(quick_key, encrypted) == payload)
    print("Для полноценной генерации: keygen --bits 32768")


def keygen(args: argparse.Namespace) -> None:
    key = rsa.generate_keypair(args.bits)
    base = Path(args.out)
    rsa.save_private(base.with_suffix(".private.json"), key)
    rsa.save_public(base.with_suffix(".public.json"), key.public)
    print(f"Создан RSA-{key.n.bit_length()}: {base}.private.json и {base}.public.json")


def encrypt(args: argparse.Namespace) -> None:
    result = rsa.encrypt(rsa.load_public(args.key), _input_bytes(args))
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_bytes(result)
    print(f"Зашифровано {len(result)} байт: {args.out}")


def decrypt(args: argparse.Namespace) -> None:
    result = rsa.decrypt(rsa.load_private(args.key), Path(args.input).read_bytes())
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_bytes(result)
        print(f"Расшифровано {len(result)} байт: {args.out}")
    else:
        print(result.decode("utf-8", errors="replace"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Лабораторная 1 - RSA-32768")
    commands = parser.add_subparsers(dest="command", required=True)
    item = commands.add_parser("demo"); item.set_defaults(handler=demo)
    item = commands.add_parser("keygen"); item.add_argument("--bits", type=int, default=rsa.DEFAULT_BITS); item.add_argument("--out", default="results/keys/rsa32768"); item.set_defaults(handler=keygen)
    for command, handler in (("encrypt", encrypt), ("decrypt", decrypt)):
        item = commands.add_parser(command); item.add_argument("--key", required=True); item.add_argument("--in", dest="input"); item.add_argument("--text")
        if command == "encrypt": item.add_argument("--out", required=True)
        else: item.add_argument("--out")
        item.set_defaults(handler=handler)
    args = parser.parse_args()
    if args.command == "encrypt" and bool(args.input) == bool(args.text is not None):
        parser.error("для encrypt укажите ровно один из --in и --text")
    if args.command == "decrypt" and not args.input:
        parser.error("для decrypt обязателен --in")
    args.handler(args)


if __name__ == "__main__":
    main()
