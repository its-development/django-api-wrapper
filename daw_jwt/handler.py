import jwt
import datetime
from django.conf import settings
from django.utils.crypto import get_random_string
from django.utils import timezone


def create_jwt(payload, expire_delta=timezone.timedelta(days=1)):
    """
    Create a JWT token from a payload.
    """
    payload["exp"] = datetime.datetime.utcnow() + expire_delta
    payload["bfp"] = get_random_string(128)
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
    return token


def decode_jwt(token):
    """
    Decode a JWT token and return the payload.
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise jwt.ExpiredSignatureError("Token has expired")
    except jwt.InvalidTokenError:
        raise jwt.InvalidTokenError("Invalid token")
