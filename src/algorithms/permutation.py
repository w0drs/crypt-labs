from dataclasses import dataclass

from ..base import EncoderDecoderClass
from ..tools.validation import remove_spaces, validate_permutation, validate_text


@dataclass
class PermutationCipher(EncoderDecoderClass):
    padding: str = "x"

    def __post_init__(self) -> None:
        if not isinstance(self.padding, str) or len(self.padding) != 1 or self.padding == " ":
            raise ValueError("Заполнитель должен состоять из одного символа, отличного от пробела")

    def encrypt(self, text: str, key) -> str:
        order = validate_permutation(key)
        text = remove_spaces(text)
        block_size = len(order)

        # Дополняем неполный блок, если блок полный, добавляем ноль символов
        text += self.padding * (-len(text) % block_size)
        result = []
        for start in range(0, len(text), block_size):
            block = text[start:start + block_size]
            print(f"- блок: {block}")
            # Ключ задаёт позиции от 1, а индексы строки начинаются с 0
            result.extend(block[position - 1] for position in order)
        return "".join(result)

    def decrypt(self, text: str, key, *, original_length = None) -> str:
        """Восстанавливает текст, исходная длина позволяет убрать заполнитель"""
        validate_text(text)
        order = validate_permutation(key)
        block_size = len(order)
        if len(text) % block_size:
            raise ValueError("Длина шифротекста должна быть кратна размеру блока")

        result = []
        for start in range(0, len(text), block_size):
            block = [""] * block_size
            # Возвращаем каждый символ на его исходное место в блоке
            for index, position in enumerate(order):
                block[position - 1] = text[start + index]
            result.extend(block)
        plaintext = "".join(result)

        if original_length is not None:
            if type(original_length) is not int:
                raise ValueError("Исходная длина должна быть целым числом")
            if not 0 <= original_length <= len(plaintext):
                raise ValueError("Исходная длина должна быть от 0 до длины расшифрованного текста")

            padding_count = len(plaintext) - original_length
            if padding_count >= block_size:
                raise ValueError("Дополнение должно быть короче одного блока")

            padding_text = plaintext[original_length:]
            if padding_text != self.padding * padding_count:
                raise ValueError("После исходного текста должен находиться только заполнитель")

            # Не используем rstrip: настоящий текст тоже может заканчиваться на x
            plaintext = plaintext[:original_length]
        return plaintext
