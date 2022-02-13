import base64
from .settings import ApiSettings


def generate_key_by_length(data, key):
    while len(data) > len(key):
        key = key + key

    key = key[0 : len(data)]

    return key


class ApiCrypto:
    __KEY = ApiSettings.X_OR_KEY

    @classmethod
    def encode(cls, text):
        if not isinstance(text, bytes):
            text = bytes(text, "UTF-8")
        result = cls.__xor(text)
        return base64.b64encode(result)

    @classmethod
    def decode(cls, text, as_bytes=False):
        text = base64.b64decode(text)
        return str(cls.__xor(text), "UTF-8") if not as_bytes else cls.__xor(text)

    @classmethod
    def xor(cls, text):
        if not isinstance(text, bytes):
            text = bytes(text, "UTF-8")
        return str(cls.__xor(text), "UTF-8")

    @classmethod
    def __xor(cls, data, key=None):
        return bytes(
            [
                a ^ b
                for a, b in zip(
                    data, generate_key_by_length(data, key if key else cls.__KEY)
                )
            ]
        )
