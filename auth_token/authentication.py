import datetime

from django.utils import timezone
from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed

from api.helpers import ApiHelpers
from api.exceptions import *

from .models import ExpiringToken
from .settings import custom_settings


class ExpiringTokenAuthentication(TokenAuthentication):
    keyword = 'Token'

    def authenticate(self, request):
        user, token = super().authenticate(request)

        if not token:
            raise ApiAuthFailed()

        if not token.ip_addr or token.ip_addr != ApiHelpers.get_client_ip(request):
            token.delete()
            raise ApiValueError('IP missmatch')

        return user, token

    def authenticate_credentials(self, key):
        try:
            token = ExpiringToken.objects.get(token=key)
        except ExpiringToken.DoesNotExist:
            raise AuthenticationFailed("Invalid Token")

        if not token.user.is_active:
            raise AuthenticationFailed("User is not active")

        if token.is_access_token_expired:
            raise AuthenticationFailed("The Token is expired")

        if token.is_refresh_token_expired:
            token.delete()
            raise AuthenticationFailed("The Token is expired")

        token.access_token_expires = timezone.now() + custom_settings.EXPIRING_TOKEN_DURATION
        token.refresh_token_expires = timezone.now() + custom_settings.EXPIRING_REFRESH_TOKEN_DURATION
        token.save()

        return token.user, token
