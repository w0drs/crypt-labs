from dataclasses import dataclass

from ..base import EncoderDecoderClass
from ..tools.alphabets import get_alphabet
from ..tools.validation import validate_text


@dataclass
class VigenereCipher(EncoderDecoderClass):
    alphabet: str = "en"

    def __post_init__(self) -> None:
        get_alphabet(self.alphabet)

    def _shift_letter(self, letter: str, shift: int, alphabet: str) -> str:
        lower = letter.lower()
        # Сдвигаем по кругу, не выходя за границы алфавита
        new_index = (alphabet.index(lower) + shift) % len(alphabet)
        result = alphabet[new_index]
        # Сохраняем регистр исходной буквы
        return result.upper() if letter.isupper() else result

    def _transform(self, text: str, key: str, direction: int) -> str:
        validate_text(text)
        letters = get_alphabet(self.alphabet)

        if not isinstance(key, str) or not key:
            raise ValueError("Ключ должен быть непустой строкой")

        key = key.lower()
        if any(char not in letters for char in key):
            raise ValueError("Ключ должен содержать только буквы из нужного алфавита")

        result = []
        j = 0
        for char in text:
            if char.lower() in letters:
                # Остаток от деления повторяет ключ с начала после его последней буквы
                shift = letters.index(key[j % len(key)])
                # Знак направления меняет шифрование на расшифрование
                result.append(self._shift_letter(char, direction * shift, letters))
                # Только буквы выбранного алфавита продвигают позицию ключа
                j += 1
            else:
                result.append(char)
        return "".join(result)

    def encrypt(self, text: str, key: str) -> str:
        return self._transform(text, key, 1)

    def decrypt(self, text: str, key: str) -> str:
        return self._transform(text, key, -1)
