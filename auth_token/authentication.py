from django.utils import timezone
from django.conf import settings
from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed

from api.helpers import ApiHelpers
from api.exceptions import *

from .models import ExpiringToken
from .settings import custom_settings


class ExpiringTokenAuthentication(TokenAuthentication):

    @classmethod
    def is_time_expired(cls, time) -> bool:
        return timezone.now() > time

    @classmethod
    def is_token_expired(cls, token) -> bool:
        return cls.is_time_expired(token.expires) or cls.is_time_expired(token.valid_until)

    @classmethod
    def regenerate(cls, old_token: ExpiringToken, user: settings.AUTH_USER_MODEL, ip_addr: str) -> ExpiringToken:
        if old_token:
            old_token.delete()

        return ExpiringToken.objects.create(user=user, ip_addr=ip_addr)

    @classmethod
    def expire_handler(cls, token) -> (bool, ExpiringToken):
        is_expired = cls.is_token_expired(token)

        if is_expired:
            token.delete()

        return is_expired, token

    def authenticate(self, request):
        user, token = super().authenticate(request)

        if not token.ip_addr or token.ip_addr != ApiHelpers.get_client_ip(request):
            token.delete()
            raise ApiValueError('IP MISSMATCH')

        return user, token

    def authenticate_credentials(self, key):
        try:
            token = ExpiringToken.objects.get(key=key)
        except ExpiringToken.DoesNotExist:
            raise AuthenticationFailed("Invalid Token")

        if not token.user.is_active:
            raise AuthenticationFailed("User is not active")

        is_expired, token = self.expire_handler(token)

        if is_expired:
            raise AuthenticationFailed("The Token is expired")

        token.expires = timezone.now() + custom_settings.EXPIRING_TOKEN_DURATION
        token.save()

        return token.user, token
