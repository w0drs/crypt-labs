from dataclasses import dataclass

from ..base import EncoderDecoderClass
from ..tools.alphabets import get_alphabet
from ..tools.validation import validate_text


@dataclass
class CaesarCipher(EncoderDecoderClass):
    alphabet: str = "en"

    def __post_init__(self) -> None:
        get_alphabet(self.alphabet)

    def _shift_letter(self, letter: str, shift: int, alphabet: str) -> str:
        lower = letter.lower()

        # Пробелы, цифры и символы вне алфавита оставляем без изменений
        if lower not in alphabet:
            return letter

        # Остаток от деления замыкает сдвиг в пределах алфавита
        new_index = (alphabet.index(lower) + shift) % len(alphabet)
        result = alphabet[new_index]
        # Возвращаем букве исходный регистр
        return result.upper() if letter.isupper() else result

    def _transform(self, text: str, key: int, direction: int) -> str:
        validate_text(text)
        letters = get_alphabet(self.alphabet)

        if type(key) is not int or not 1 <= key < len(letters):
            raise ValueError(f'Ключ должен быть числом с 1 до {len(letters) - 1}')

        # При шифровании сдвигаем вперёд, при расшифровании - назад
        return "".join(self._shift_letter(char, direction * key, letters) for char in text)

    def encrypt(self, text: str, key: int) -> str:
        return self._transform(text, key, 1)

    def decrypt(self, text: str, key: int) -> str:
        return self._transform(text, key, -1)
