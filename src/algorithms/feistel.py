from dataclasses import dataclass

from ..base import EncoderDecoderClass
from ..tools.validation import validate_text


@dataclass
class FeistelCipher(EncoderDecoderClass):
    """Учебная сеть Фейстеля: блок 16 бит, ключ 16 бит, текст в UTF-8

    Блоки обрабатываются независимо (ECB), шифротекст возвращается в hex
    """

    rounds: int = 8

    def __post_init__(self) -> None:
        if type(self.rounds) is not int or self.rounds < 4:
            raise ValueError("Число раундов должно быть целым числом не меньше 4")

    @staticmethod
    def _validate_word(value: int, name: str) -> None:
        if type(value) is not int or not 0 <= value <= 0xFFFF:
            raise ValueError(f"{name} должен быть целым числом от 0 до 65535")

    def _round_keys(self, key: int) -> list[int]:
        self._validate_word(key, "Ключ")
        keys = []
        state = key
        for index in range(self.rounds):
            # Циклический сдвиг 16-битного ключа влево на три бита
            state = ((state << 3) | (state >> 13)) & 0xFFFF
            keys.append((state & 0xFF) ^ ((17 * (index + 1)) & 0xFF))
        return keys

    @staticmethod
    def _round_function(right: int, subkey: int) -> int:
        # Сложение по модулю 256 добавляет переносы между битами
        value = ((right ^ subkey) + right) & 0xFF
        return ((value << 3) | (value >> 5)) & 0xFF

    def _transform_block(self, block: int, round_keys: list[int], *, decrypt: bool) -> int:
        left = block >> 8
        right = block & 0xFF
        if decrypt:
            for subkey in reversed(round_keys):
                left, right = right ^ self._round_function(left, subkey), left
        else:
            for subkey in round_keys:
                left, right = right, left ^ self._round_function(right, subkey)
        # Дополнительной финальной перестановки половин нет
        return (left << 8) | right

    def encrypt_block(self, block: int, key: int) -> int:
        """Шифрует ровно 16 бит без кодирования текста и дополнения"""
        self._validate_word(block, "Блок")
        return self._transform_block(block, self._round_keys(key), decrypt=False)

    def decrypt_block(self, block: int, key: int) -> int:
        """Расшифровывает ровно 16 бит без удаления дополнения"""
        self._validate_word(block, "Блок")
        return self._transform_block(block, self._round_keys(key), decrypt=True)

    def encrypt(self, text: str, key: int) -> str:
        validate_text(text)
        round_keys = self._round_keys(key)
        try:
            data = text.encode("utf-8")
        except UnicodeEncodeError as error:
            raise ValueError("Текст должен корректно кодироваться в UTF-8") from error

        # PKCS#7: всегда добавляем 1 или 2 байта, даже к полному блоку
        padding_size = 2 - len(data) % 2
        data += bytes([padding_size]) * padding_size
        result = bytearray()
        for start in range(0, len(data), 2):
            block = int.from_bytes(data[start:start + 2], "big")
            encrypted = self._transform_block(block, round_keys, decrypt=False)
            result.extend(encrypted.to_bytes(2, "big"))
        return result.hex()

    def decrypt(self, text: str, key: int) -> str:
        validate_text(text)
        round_keys = self._round_keys(key)
        if not text or len(text) % 4 or any(char not in "0123456789abcdefABCDEF" for char in text):
            raise ValueError("Шифротекст должен быть непустой hex-строкой длины, кратной 4")

        data = bytes.fromhex(text)
        result = bytearray()
        for start in range(0, len(data), 2):
            block = int.from_bytes(data[start:start + 2], "big")
            decrypted = self._transform_block(block, round_keys, decrypt=True)
            result.extend(decrypted.to_bytes(2, "big"))

        padding_size = result[-1]
        if padding_size not in (1, 2) or result[-padding_size:] != bytes([padding_size]) * padding_size:
            raise ValueError("Некорректное дополнение: проверьте ключ, число раундов и шифротекст")
        try:
            return result[:-padding_size].decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("Результат не является UTF-8: проверьте ключ, число раундов и шифротекст") from error

    def avalanche_experiment(self, block: int, key: int) -> list[dict[str, int | str]]:
        """Меняет каждый из 16 бит блока и ключа; бит 0 — младший

        Эксперимент проводится без дополнения, на одном 16-битном блоке
        """
        original_ciphertext = self.encrypt_block(block, key)
        rows = []
        for target in ("block", "key"):
            for bit in range(16):
                changed_block = block ^ (1 << bit) if target == "block" else block
                changed_key = key ^ (1 << bit) if target == "key" else key
                changed_ciphertext = self.encrypt_block(changed_block, changed_key)
                rows.append({
                    "target": target,
                    "bit": bit,
                    "block": block,
                    "key": key,
                    "changed_block": changed_block,
                    "changed_key": changed_key,
                    "ciphertext": original_ciphertext,
                    "changed_ciphertext": changed_ciphertext,
                    "different_bits": (original_ciphertext ^ changed_ciphertext).bit_count(),
                })
        return rows
