"""CLI лабораторной 3: Стрибог и безопасное хранение паролей."""

from __future__ import annotations

import argparse
import getpass
from pathlib import Path

from .core.passwords import make_password_record, verify_password
from .core.streebog import streebog256, streebog512


def hash_value(args: argparse.Namespace) -> None:
    data = args.text.encode("utf-8") if args.text is not None else Path(args.file).read_bytes()
    digest = streebog512(data) if args.bits == 512 else streebog256(data)
    print(digest.hex())


def password(_: argparse.Namespace) -> None:
    first, second = getpass.getpass("Пароль: "), getpass.getpass("Повторите пароль: ")
    if first != second: raise ValueError("пароли не совпадают")
    print(make_password_record(first))


def check(args: argparse.Namespace) -> None:
    print("Пароль верный" if verify_password(getpass.getpass("Пароль: "), args.stored) else "Пароль неверный")


def demo(_: argparse.Namespace) -> None:
    sample = b"012345678901234567890123456789012345678901234567890123456789012"
    print("Стрибог-512:", streebog512(sample).hex())
    print("Стрибог-256:", streebog256(sample).hex())
    print("512-битный вектор в записи стандарта начинается с:", streebog512(sample)[::-1].hex()[:20])


def main() -> None:
    parser = argparse.ArgumentParser(description="Лабораторная 3 - Стрибог")
    commands = parser.add_subparsers(dest="command", required=True)
    item = commands.add_parser("demo"); item.set_defaults(handler=demo)
    item = commands.add_parser("hash"); item.add_argument("--bits", type=int, choices=(256,512), default=512); item.add_argument("--text"); item.add_argument("--file"); item.set_defaults(handler=hash_value)
    item = commands.add_parser("password"); item.set_defaults(handler=password)
    item = commands.add_parser("check"); item.add_argument("--stored", required=True); item.set_defaults(handler=check)
    args = parser.parse_args()
    if args.command == "hash" and bool(args.text is not None) == bool(args.file): parser.error("задайте ровно один из --text и --file")
    args.handler(args)


if __name__ == "__main__": main()
