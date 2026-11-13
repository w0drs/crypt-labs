def validate_text(text: str) -> None:
    if not isinstance(text, str):
        raise ValueError("Текст должен быть python строкой")


def validate_permutation(key):
    if not isinstance(key, (list, tuple)) or not key:
        raise ValueError("Перестановка должна быть непустым списком или кортежем")
    if any(type(number) is not int for number in key):
        raise ValueError("Элементы перестановки должны быть целыми числами")
    if sorted(key) != list(range(1, len(key) + 1)):
        raise ValueError("Перестановка должна содержать все числа от 1 до n без повторов")
    return tuple(key)


def remove_spaces(text: str) -> str:
    """Убирает пробелы"""
    validate_text(text)
    return text.replace(" ", "")
