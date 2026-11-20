import contextlib
import io
import unittest

from src import EncoderDecoderClass, FeistelCipher
from src.console.app import main


class FeistelCipherTests(unittest.TestCase):
    def test_base_class(self):
        self.assertIsInstance(FeistelCipher(), EncoderDecoderClass)

    def test_round_trip_messages(self):
        for rounds in (4, 8, 12):
            cipher = FeistelCipher(rounds=rounds)
            for key in (0, 1, 0xBEEF, 0xFFFF):
                for text in ("", "A", "AB", "Hello, world!", "Привет, мир!", "\x00x\x01\x02", "🙂"):
                    with self.subTest(rounds=rounds, key=key, text=text):
                        encrypted = cipher.encrypt(text, key)
                        self.assertEqual(len(encrypted) % 4, 0)
                        self.assertEqual(cipher.decrypt(encrypted, key), text)
                        self.assertEqual(cipher.decrypt(encrypted.upper(), key), text)

    def test_padding_sizes(self):
        cipher = FeistelCipher()
        for text, byte_length in (("", 2), ("A", 2), ("AB", 4), ("ABC", 4)):
            self.assertEqual(len(bytes.fromhex(cipher.encrypt(text, 0))), byte_length)

    def test_single_round_by_hand(self):
        cipher = FeistelCipher(rounds=4)
        # F(0x34, 0x12): (0x26 + 0x34) = 0x5a, ROL8(0x5a, 3) = 0xd2.
        self.assertEqual(cipher._round_function(0x34, 0x12), 0xD2)
        self.assertEqual(cipher._transform_block(0x1234, [0x12], decrypt=False), 0x34C0)
        self.assertEqual(cipher._transform_block(0x34C0, [0x12], decrypt=True), 0x1234)

    def test_key_schedule(self):
        cipher = FeistelCipher()
        self.assertEqual(cipher._round_keys(0xBEEF), [108, 205, 78, 170, 34, 216, 128, 54])
        self.assertEqual(cipher.encrypt_block(0x1234, 0xBEEF), 0x9509)
        self.assertEqual(cipher.encrypt("AB", 0xBEEF), "81bbc4bb")

    def test_all_blocks_are_reversible(self):
        cipher = FeistelCipher()
        keys = cipher._round_keys(0xBEEF)
        ciphertexts = set()
        for block in range(65536):
            encrypted = cipher._transform_block(block, keys, decrypt=False)
            self.assertEqual(cipher._transform_block(encrypted, keys, decrypt=True), block)
            ciphertexts.add(encrypted)
        self.assertEqual(len(ciphertexts), 65536)

    def test_invalid_rounds(self):
        for rounds in (True, 3, 0, -1, 4.0, "8", None):
            with self.subTest(rounds=rounds), self.assertRaises(ValueError):
                FeistelCipher(rounds=rounds)

    def test_invalid_keys_and_blocks(self):
        cipher = FeistelCipher()
        for value in (-1, 65536, True, "secret", 1.5, None):
            for operation in (
                lambda: cipher.encrypt("test", value),
                lambda: cipher.decrypt("0000", value),
                lambda: cipher.encrypt_block(0, value),
                lambda: cipher.decrypt_block(0, value),
                lambda: cipher.encrypt_block(value, 0),
                lambda: cipher.decrypt_block(value, 0),
            ):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    operation()

    def test_invalid_text(self):
        cipher = FeistelCipher()
        for text in (None, 123, b"text"):
            for operation in (cipher.encrypt, cipher.decrypt):
                with self.subTest(text=text), self.assertRaises(ValueError):
                    operation(text, 0)
        with self.assertRaisesRegex(ValueError, "UTF-8"):
            cipher.encrypt("\ud800", 0)
        for text in ("", "0", "001", "000000", "zzzz", "00 0", "\n0000"):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, "hex"):
                cipher.decrypt(text, 0)

    def test_invalid_padding_and_utf8(self):
        cipher = FeistelCipher()
        for block, message in ((0x4100, "дополнение"), (0x4102, "дополнение"), (0xFF01, "UTF-8")):
            encrypted = f"{cipher.encrypt_block(block, 0xBEEF):04x}"
            with self.subTest(block=block), self.assertRaisesRegex(ValueError, message):
                cipher.decrypt(encrypted, 0xBEEF)

    def test_avalanche(self):
        cipher = FeistelCipher()
        rows = cipher.avalanche_experiment(0x1234, 0xBEEF)
        self.assertEqual(len(rows), 32)
        for row in rows:
            self.assertEqual((row["block"] ^ row["changed_block"]).bit_count()
                             + (row["key"] ^ row["changed_key"]).bit_count(), 1)
            actual = cipher.encrypt_block(row["changed_block"], row["changed_key"])
            self.assertEqual(actual, row["changed_ciphertext"])
            self.assertEqual(row["different_bits"], (row["ciphertext"] ^ actual).bit_count())


class ConsoleTests(unittest.TestCase):
    def run_app(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(list(args))
        return code, stdout.getvalue(), stderr.getvalue()

    def test_feistel_encrypt_automatically_checks(self):
        code, output, error = self.run_app("feistel", "encrypt", "--text", "Привет", "--key", "0xBEEF")
        self.assertEqual(code, 0, error)
        self.assertIn("Decrypted: Привет", output)
        self.assertIn("Dk(Ek(m)) == m: True", output)
        encrypted = output.splitlines()[0]
        code, output, error = self.run_app("feistel", "decrypt", "--text", encrypted, "--key", "48879")
        self.assertEqual((code, output, error), (0, "Привет\n", ""))

    def test_feistel_check_empty_and_four_rounds(self):
        code, output, error = self.run_app("feistel", "check", "--text", "", "--key", "0", "--rounds", "4")
        self.assertEqual(code, 0, error)
        self.assertIn("Dk(Ek(m)) == m: True", output)

    def test_avalanche(self):
        code, output, error = self.run_app("feistel", "avalanche", "--block", "0x1234", "--key", "0xBEEF")
        self.assertEqual(code, 0, error)
        self.assertIn("Average (block)", output)
        self.assertIn("Average (key)", output)

    def test_invalid_arguments(self):
        cases = [
            ("feistel", "check", "--rounds", "3"),
            ("feistel", "decrypt"),
            ("caesar", "avalanche"),
            ("caesar", "check", "--rounds", "8"),
            ("caesar", "check", "--block", "1"),
            ("feistel", "check", "--original-length", "1"),
        ]
        for args in cases:
            with self.subTest(args=args):
                code, _, error = self.run_app(*args, "--text", "bad", "--key", "1")
                self.assertEqual(code, 2)
                self.assertIn("Error:", error)
        for key in ("secret", "-1", "65536"):
            code, _, error = self.run_app("feistel", "encrypt", "--text", "test", "--key", key)
            self.assertEqual(code, 2)
            self.assertIn("Error:", error)

    def test_existing_ciphers(self):
        for algorithm, key in (("caesar", "3"), ("vigenere", "key"), ("permutation", "3,1,4,2")):
            code, output, error = self.run_app(algorithm, "check", "--text", "hello world", "--key", key)
            self.assertEqual(code, 0, error)
            self.assertIn("Dk(Ek(m)) == m: True", output)


if __name__ == "__main__":
    unittest.main()
