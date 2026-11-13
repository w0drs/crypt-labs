import argparse
import sys

from ..algorithms import CaesarCipher, PermutationCipher, VigenereCipher
from ..tools.validation import remove_spaces


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Classical ciphers (educational use only).")
    parser.add_argument("algorithm", choices=["caesar", "vigenere", "permutation"])
    parser.add_argument("action", choices=["encrypt", "decrypt", "check"])
    parser.add_argument("--text", help="Text; prompted for if omitted.")
    parser.add_argument("--key", help="Integer, keyword, or permutation such as 3,1,4,2.")
    parser.add_argument("--alphabet", choices=["en", "ru"], default="en")
    parser.add_argument("--original-length", type=int, help="Length without spaces before permutation padding.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        text = args.text if args.text is not None else input("Text: ")
        raw_key = args.key if args.key is not None else input("Key: ")
        if args.algorithm == "caesar":
            cipher = CaesarCipher(args.alphabet)
            key = int(raw_key)
        elif args.algorithm == "vigenere":
            cipher = VigenereCipher(args.alphabet)
            key = raw_key
        else:
            cipher = PermutationCipher()
            key = [int(number) for number in raw_key.replace(",", " ").split()]

        if args.original_length is not None and not (
            args.algorithm == "permutation" and args.action == "decrypt"
        ):
            raise ValueError("Параметр --original-length используется только при расшифровании перестановочным шифром.")

        if args.action == "encrypt":
            print(cipher.encrypt(text, key))
        elif args.action == "decrypt":
            if isinstance(cipher, PermutationCipher):
                print(cipher.decrypt(text, key, original_length=args.original_length))
            else:
                print(cipher.decrypt(text, key))
        else:
            encrypted = cipher.encrypt(text, key)
            if isinstance(cipher, PermutationCipher):
                expected = remove_spaces(text)
                decrypted = cipher.decrypt(encrypted, key, original_length=len(expected))
            else:
                expected = text
                decrypted = cipher.decrypt(encrypted, key)
            print(f"Encrypted: {encrypted}")
            print(f"Decrypted: {decrypted}")
            print(f"Dk(Ek(m)) == m: {decrypted == expected}")
            if isinstance(cipher, PermutationCipher):
                print(f"Compared without spaces; original length: {len(expected)}")
            return 0 if decrypted == expected else 1
    except (ValueError, EOFError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    return 0
