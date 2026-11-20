import argparse
import sys

from ..algorithms import CaesarCipher, FeistelCipher, PermutationCipher, VigenereCipher
from ..tools.validation import remove_spaces


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Classical ciphers (educational use only).")
    parser.add_argument("algorithm", choices=["caesar", "vigenere", "permutation", "feistel"])
    parser.add_argument("action", choices=["encrypt", "decrypt", "check", "avalanche"])
    parser.add_argument("--text", help="Text; prompted for if omitted.")
    parser.add_argument("--key", help="Integer, keyword, or permutation; Feistel: 0..65535 or 0x1234.")
    parser.add_argument("--rounds", type=int, help="Feistel rounds (at least 4; default: 8).")
    parser.add_argument("--block", help="16-bit block for avalanche, e.g. 0x1234 (default: 0x1234).")
    parser.add_argument("--alphabet", choices=["en", "ru"], default="en")
    parser.add_argument("--original-length", type=int, help="Length without spaces before permutation padding.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.action == "avalanche" and args.algorithm != "feistel":
            raise ValueError("Исследование лавинного эффекта доступно только для feistel")
        if args.rounds is not None and args.algorithm != "feistel":
            raise ValueError("Параметр --rounds используется только для feistel")
        if args.block is not None and args.action != "avalanche":
            raise ValueError("Параметр --block используется только для avalanche")
        if args.original_length is not None and not (
            args.algorithm == "permutation" and args.action == "decrypt"
        ):
            raise ValueError("Параметр --original-length используется только при расшифровании перестановочным шифром.")

        text = "" if args.action == "avalanche" else (
            args.text if args.text is not None else input("Text: ")
        )
        raw_key = args.key if args.key is not None else input("Key: ")
        if args.algorithm == "caesar":
            cipher = CaesarCipher(args.alphabet)
            key = int(raw_key)
        elif args.algorithm == "feistel":
            cipher = FeistelCipher(rounds=args.rounds if args.rounds is not None else 8)
            key = int(raw_key, 16) if raw_key.lower().startswith("0x") else int(raw_key)
        elif args.algorithm == "vigenere":
            cipher = VigenereCipher(args.alphabet)
            key = raw_key
        else:
            cipher = PermutationCipher()
            key = [int(number) for number in raw_key.replace(",", " ").split()]

        if args.action == "avalanche":
            raw_block = args.block if args.block is not None else "0x1234"
            block = int(raw_block, 16) if raw_block.lower().startswith("0x") else int(raw_block)
            rows = cipher.avalanche_experiment(block, key)
            print(f"Block: {block:04x}; key: {key:04x}; rounds: {cipher.rounds}")
            print("Changed  Bit  Block  Key   Cipher  Changed  Different bits")
            for row in rows:
                print(f"{row['target']:7}  {row['bit']:2}   {row['changed_block']:04x}   "
                      f"{row['changed_key']:04x}  {row['ciphertext']:04x}    "
                      f"{row['changed_ciphertext']:04x}     {row['different_bits']:2}/16")
            for target in ("block", "key"):
                counts = [row["different_bits"] for row in rows if row["target"] == target]
                average = sum(counts) / len(counts)
                print(f"Average ({target}): {average:.2f}/16 ({average / 16:.2%})")
            return 0

        if args.action == "encrypt":
            encrypted = cipher.encrypt(text, key)
            print(encrypted)
            if isinstance(cipher, FeistelCipher):
                decrypted = cipher.decrypt(encrypted, key)
                print(f"Decrypted: {decrypted}")
                print(f"Dk(Ek(m)) == m: {decrypted == text}")
                return 0 if decrypted == text else 1
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
