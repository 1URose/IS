
"""CLI лабораторной работы №2.

Шифрование алгоритмом «Кузнечик» в режиме CTR,
работа с парольным контейнером и демонстрация ГОСТ.
"""

from __future__ import annotations

import argparse
import getpass
from pathlib import Path
from typing import Optional

from .core.kuznyechik import Kuznyechik
from .core.kuznyechik_file import decrypt_password, encrypt_password


def _password(value: Optional[str]) -> str:
    """Вернуть переданный пароль или запросить его у пользователя."""
    return value if value is not None else getpass.getpass("Пароль: ")


def demo(_: argparse.Namespace) -> None:
    """Продемонстрировать шифрование на контрольном примере ГОСТ."""

    key = bytes.fromhex(
        "8899aabbccddeeff0011223344556677"
        "fedcba98765432100123456789abcdef"
    )

    plain = bytes.fromhex(
        "1122334455667700ffeeddccbbaa9988"
    )

    cipher = Kuznyechik(key).encrypt_block(plain)

    print("ГОСТ Р 34.12-2015:", plain.hex(), "->", cipher.hex())
    print(
        "Ожидаемый контрольный шифртекст: "
        "7f679d90bebc24305a468d42b9d4edcd"
    )


def encrypt(args: argparse.Namespace) -> None:
    """Зашифровать текст или файл и сохранить парольный контейнер.

    Args:
        args: Аргументы командной строки, содержащие исходные
            данные, пароль, количество итераций и путь вывода.
    """

    data = (
        args.text.encode("utf-8")
        if args.text is not None
        else Path(args.input).read_bytes()
    )

    out = encrypt_password(
        data,
        _password(args.password),
        args.iterations
    )

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_bytes(out)

    print(f"Кузнечик-CTR: {len(data)} -> {len(out)} байт, {args.out}")


def decrypt(args: argparse.Namespace) -> None:
    """Расшифровать парольный контейнер.

    Сохранить восстановленные данные в файл или вывести их
    в консоль, если путь вывода не указан.

    Args:
        args: Аргументы командной строки, содержащие путь
            к контейнеру, пароль и необязательный путь вывода.
    """

    data = decrypt_password(
        Path(args.input).read_bytes(),
        _password(args.password)
    )

    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_bytes(data)

        print(f"Расшифровано {len(data)} байт: {args.out}")
    else:
        print(data.decode("utf-8", errors="replace"))


def main() -> None:
    """Обработать аргументы и запустить выбранную команду.

    Поддерживаемые команды:
        demo: демонстрация контрольного примера ГОСТ.
        encrypt: шифрование текста или файла.
        decrypt: расшифрование парольного контейнера.
    """

    parser = argparse.ArgumentParser(
        description="Лабораторная 2 - Кузнечик CTR"
    )

    commands = parser.add_subparsers(
        dest="command",
        required=True
    )

    item = commands.add_parser("demo")
    item.set_defaults(handler=demo)

    for name, handler in (
        ("encrypt", encrypt),
        ("decrypt", decrypt)
    ):
        item = commands.add_parser(name)

        item.add_argument("--password")
        item.add_argument("--in", dest="input")
        item.add_argument("--text")

        if name == "encrypt":
            item.add_argument(
                "--iterations",
                type=int,
                default=200
            )
            item.add_argument("--out", required=True)
        else:
            item.add_argument("--out")

        item.set_defaults(handler=handler)

    args = parser.parse_args()

    if (
        args.command == "encrypt"
        and bool(args.input) == bool(args.text is not None)
    ):
        parser.error("задайте ровно один из --in и --text")

    if args.command == "decrypt" and not args.input:
        parser.error("для decrypt нужен --in")

    args.handler(args)


if __name__ == "__main__":
    main()
