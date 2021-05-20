import base64
from .settings import ApiSettings


def test(data, key):
    while len(data) > len(key):
        key = key + key

    key = key[0:len(data)]

    return key


class ApiCrypto:
    __KEY = ApiSettings

    @classmethod
    def encode(cls, text):
        text = bytes(text, 'UTF-8')
        result = cls.__xor(text)
        return base64.b64encode(result)

    @classmethod
    def decode(cls, text):
        text = base64.b64decode(text)
        return str(cls.__xor(text), 'UTF-8')

    @classmethod
    def xor(cls, text):
        text = bytes(text, 'UTF-8')
        return str(cls.__xor(text), 'UTF-8')

    @classmethod
    def __xor(cls, data):
        return bytes([a ^ b for a, b in zip(data, test(data, cls.__KEY))])
