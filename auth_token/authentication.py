import datetime
from django.conf import settings
from django.utils import timezone
from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed

from api.helpers import ApiHelpers
from api.exceptions import *

from .settings import custom_settings


class ExpiringTokenAuthentication(TokenAuthentication):
    model = None
    keyword = "token"

    def authenticate(self, request):
        res = super().authenticate(request)

        if not res:
            raise ApiAuthFailed()

        user, token = res

        if not token:
            raise ApiAuthFailed()

        if not token.ip_addr or token.ip_addr != ApiHelpers.get_client_ip(request):
            token.delete()
            raise ApiValueError("IP missmatch")

        return user, token

    def authenticate_credentials(self, key):
        try:
            token = self.model.objects.get(access_token=key)
        except self.model.DoesNotExist:
            raise ApiAuthInvalid()

        if not token.user.is_active:
            raise AuthenticationFailed("User is not active")

        if token.is_access_token_expired:
            raise ApiAuthExpired()

        if token.is_refresh_token_expired:
            token.delete()
            raise AuthenticationFailed("The Refresh Token is expired")

        token.refresh_token_expires = (
            timezone.now() + custom_settings.EXPIRING_REFRESH_TOKEN_DURATION
        )
        token.save()

        return token.user, token
