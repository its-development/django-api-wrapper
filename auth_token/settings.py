"""
Provides access to settings.
Returns defaults if not set.
"""
from datetime import timedelta

from django.conf import settings


class CustomSettings(object):
    """Provides settings as defaults for working with tokens."""

    @property
    def EXPIRING_TOKEN_DURATION(self):
        """
        Return the allowed lifespan of a token as a TimeDelta object.
        Defaults to 30 minutes.
        """
        try:
            val = settings.EXPIRING_TOKEN_DURATION
        except AttributeError:
            val = timedelta(minutes=5)

        return val

    @property
    def EXPIRING_REFRESH_TOKEN_DURATION(self):
        """
        Return the allowed lifespan of a token as a TimeDelta object.
        Defaults to 30 minutes.
        """
        try:
            val = settings.EXPIRING_REFRESH_TOKEN_DURATION
        except AttributeError:
            val = timedelta(days=7)

        return val

    @property
    def EXPIRING_TOKEN_MAX_LIFETIME(self):
        """
        Return the maximum allowed lifetime for a token
        Defaults to 1 day
        """
        try:
            val = settings.EXPIRING_TOKEN_MAX_LIFETIME
        except AttributeError:
            val = timedelta(days=1)

        return val

    @property
    def EXPIRING_REFRESH_TOKEN_MAX_LIFETIME(self):
        """
        Return the maximum allowed lifetime for a token
        Defaults to 1 day
        """
        try:
            val = settings.EXPIRING_REFRESH_TOKEN_MAX_LIFETIME
        except AttributeError:
            val = timedelta(days=7)

        return val

    @property
    def EXPIRING_TOKEN_LENGTH(self):
        """

        :return:
        """
        try:
            val = settings.EXPIRING_TOKEN_LENGTH
        except AttributeError:
            val = 128

        if val > 255:
            val = 255

        return val

    @property
    def EXPIRING_TOKEN_MAX_SESSIONS(self):
        """

        :return:
        """
        try:
            val = settings.EXPIRING_TOKEN_MAX_SESSIONS
        except AttributeError:
            val = 5

        return val


custom_settings = CustomSettings()
