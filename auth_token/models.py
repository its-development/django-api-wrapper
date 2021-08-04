import binascii
import datetime
import os

from django.conf import settings
from django.db import models
from django.utils import timezone

from .settings import custom_settings


def is_time_expired(time) -> bool:
    return timezone.now() > time

def generate_key():
    return str(binascii.hexlify(
        os.urandom(custom_settings.EXPIRING_TOKEN_LENGTH)
    ).decode()[0:custom_settings.EXPIRING_TOKEN_LENGTH])


class ExpiringToken(models.Model):
    class Meta:
        db_table = 'auth_expiry_tokens'
        verbose_name = "Token"
        verbose_name_plural = "Tokens"

    id = models.AutoField(primary_key=True)

    access_token = models.CharField(default=generate_key, max_length=1024, unique=True)
    access_token_expires = models.DateTimeField(default=timezone.now)
    access_token_valid_until = models.DateTimeField(default=timezone.now)

    refresh_token = models.CharField(default=generate_key, max_length=1024)
    refresh_token_expires = models.DateTimeField(default=timezone.now)
    refresh_token_valid_until = models.DateTimeField(default=timezone.now)

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, related_name='auth_tokens',
        on_delete=models.CASCADE, verbose_name="User"
    )

    ip_addr = models.GenericIPAddressField(default=None, null=True)
    user_agent = models.CharField(max_length=1024)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def is_access_token_expired(self):
        return is_time_expired(self.access_token_expires) or is_time_expired(self.access_token_valid_until)

    @property
    def is_refresh_token_expired(self):
        return is_time_expired(self.refresh_token_expires) or is_time_expired(self.refresh_token_valid_until)

    def save(self, *args, **kwargs):

        if not self.ip_addr:
            raise ValueError('IP Address missing')

        if not self.user:
            raise ValueError('User missing')

        user_active_sessions = self.__class__.objects.filter(user=self.user)
        if user_active_sessions.count() >= custom_settings.EXPIRING_TOKEN_MAX_SESSIONS:
            user_active_sessions.order_by('created_at').last().delete()

        if not self.access_token:
            self.access_token = self.generate_key()

        if not self.refresh_token:
            self.refresh_token = self.generate_key()

        if not self.access_token_expires:
            self.access_token_expires = timezone.now() + custom_settings.EXPIRING_TOKEN_DURATION()

        if not self.refresh_token_expires:
            self.refresh_token_expires = timezone.now() + custom_settings.EXPIRING_REFRESH_TOKEN_DURATION()

        if not self.access_token_valid_until:
            self.access_token_valid_until = timezone.now() + custom_settings.EXPIRING_TOKEN_MAX_LIFETIME()

        if not self.refresh_token_valid_until:
            self.refresh_token_valid_until = timezone.now() + custom_settings.EXPIRING_REFRESH_TOKEN_MAX_LIFETIME()

        return super(ExpiringToken, self).save(*args, **kwargs)

    def delete_expired(self, user):
        for token in self.__class__.objects.filter(user=user):
            if token.is_access_token_expired or token.is_refresh_token_expired:
                token.delete()

    def regenerate(self):
        self.token = self.generate_key()
        self.refresh_token = self.generate_key()
        self.save()

    def generate_key(self):
        return generate_key()

    def __str__(self):
        return self.access_token[:30]
