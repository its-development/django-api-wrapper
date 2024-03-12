import base64
from itertools import cycle, islice

from .settings import ApiSettings


class ApiCrypto:
    __KEY = ApiSettings.X_OR_KEY

    @classmethod
    def encode(cls, content):
        if isinstance(content, str):
            content = content.encode()

        result = cls.__xor(content)
        return base64.b64encode(result)

    @classmethod
    def decode(cls, content, as_bytes=False):
        try:
            content = base64.b64decode(content)
        except:
            pass

        return cls.__xor(content).decode() if not as_bytes else cls.__xor(content)

    @classmethod
    def xor(cls, content):
        if isinstance(content, str):
            content = content.encode()

        return cls.__xor(content)

    @classmethod
    def __xor(cls, data, key=None):
        if not isinstance(data, bytes):
            data = bytes(str(data).encode())
        real_key = bytes(islice(cycle(key or cls.__KEY), len(data)))
        return bytes([b ^ real_key[i % len(real_key)] for i, b in enumerate(data)])
