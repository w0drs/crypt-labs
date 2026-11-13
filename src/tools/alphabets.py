ENGLISH = "abcdefghijklmnopqrstuvwxyz"
RUSSIAN = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя"
ALPHABETS = {"en": ENGLISH, "ru": RUSSIAN}


def get_alphabet(name: str) -> str:
    if name not in ALPHABETS:
        raise ValueError("Доступные языки: 'en', 'ru'.")
    return ALPHABETS[name]
