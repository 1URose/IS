"""CLI лабораторной 4: ГОСТ ЭЦП и учебная подпись PDF."""

from __future__ import annotations

import argparse
from pathlib import Path

from .core import gost3410 as gost
from .core.pdf_signature import sign_pdf_bytes, verify_pdf_bytes

def keygen(args: argparse.Namespace) -> None:
    secret, public = gost.generate_keypair(); base = Path(args.out)
    gost.save_private(base.with_suffix(".private.json"), gost.DEFAULT_CURVE, secret); gost.save_public(base.with_suffix(".public.json"), gost.DEFAULT_CURVE, public)
    print(f"Создана пара ключей: {base}.private.json, {base}.public.json")

def sign_file(args: argparse.Namespace) -> None:
    curve, secret = gost.load_private(args.key); signature = gost.sign(Path(args.file).read_bytes(), secret, curve); Path(args.sig).parent.mkdir(parents=True, exist_ok=True); Path(args.sig).write_bytes(signature); print(f"Подпись ({len(signature)} байт) записана в {args.sig}")

def verify_file(args: argparse.Namespace) -> None:
    curve, public = gost.load_public(args.key); valid = gost.verify(Path(args.file).read_bytes(), Path(args.sig).read_bytes(), public, curve); print("Подпись верна" if valid else "Подпись НЕВЕРНА")

def sign_pdf(args: argparse.Namespace) -> None:
    original = Path(args.file).read_bytes()
    curve, secret = gost.load_private(args.key)
    signed = sign_pdf_bytes(original, secret, curve)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True); Path(args.out).write_bytes(signed); print(f"Подписанный PDF: {args.out}")

def verify_pdf(args: argparse.Namespace) -> None:
    curve, trusted_public = gost.load_public(args.key)
    valid = verify_pdf_bytes(Path(args.file).read_bytes(), curve, trusted_public)
    print("Подпись PDF верна" if valid else "Подпись PDF НЕВЕРНА")

def demo(_: argparse.Namespace) -> None:
    d, q = gost.generate_keypair(); message=b"Demonstration"; signature=gost.sign(message,d); print("ЭЦП ГОСТ Р 34.10-2012:", "верна" if gost.verify(message,signature,q) else "ошибка")

def main() -> None:
    parser=argparse.ArgumentParser(description="Лабораторная 4 - ЭЦП ГОСТ") ; commands=parser.add_subparsers(dest="command",required=True)
    item=commands.add_parser("demo");item.set_defaults(handler=demo)
    item=commands.add_parser("keygen");item.add_argument("--out",default="results/keys/user");item.set_defaults(handler=keygen)
    for name, handler in (("sign",sign_file),("verify",verify_file),("sign-pdf",sign_pdf),("verify-pdf",verify_pdf)):
        item=commands.add_parser(name);item.add_argument("--key",required=True);item.add_argument("--file",required=True)
        if name=="sign":item.add_argument("--sig",required=True)
        if name=="verify":item.add_argument("--sig",required=True)
        if name=="sign-pdf":item.add_argument("--out",required=True)
        item.set_defaults(handler=handler)
    args=parser.parse_args();args.handler(args)

if __name__=="__main__":main()
