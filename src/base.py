from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class EncoderDecoderClass(ABC):
    """
    Базовый класс для алгоритма шифрования.
    Нужно реализовать функцию шифрования и расшифрования
    """

    @abstractmethod
    def encrypt(self, text: str, key: object) -> str:
        raise NotImplementedError

    @abstractmethod
    def decrypt(self, text: str, key: object) -> str:
        raise NotImplementedError
