import binascii
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


def get_default_access_token_expiry():
    return timezone.now() + custom_settings.EXPIRING_TOKEN_DURATION


def get_default_access_token_validity():
    return timezone.now() + custom_settings.EXPIRING_TOKEN_MAX_LIFETIME


def get_default_refresh_token_expiry():
    return timezone.now() + custom_settings.EXPIRING_REFRESH_TOKEN_DURATION


def get_default_refresh_token_validity():
    return timezone.now() + custom_settings.EXPIRING_REFRESH_TOKEN_MAX_LIFETIME


class ExpiringToken(models.Model):
    class Meta:
        abstract = True
        db_table = 'auth_expiry_tokens'
        verbose_name = "Token"
        verbose_name_plural = "Tokens"

    id = models.AutoField(primary_key=True)

    access_token = models.CharField(default=generate_key, max_length=254, unique=True)
    access_token_expires = models.DateTimeField(default=get_default_access_token_expiry)
    access_token_valid_until = models.DateTimeField(default=get_default_access_token_validity)

    refresh_token = models.CharField(default=generate_key, max_length=254)
    refresh_token_expires = models.DateTimeField(default=get_default_refresh_token_expiry)
    refresh_token_valid_until = models.DateTimeField(default=get_default_refresh_token_validity)

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, related_name='auth_tokens',
        on_delete=models.CASCADE, verbose_name="User"
    )

    ip_addr = models.GenericIPAddressField(default=None, null=True)
    user_agent = models.CharField(max_length=1024, null=True, default=None)

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
            self.access_token = generate_key()

        if not self.refresh_token:
            self.refresh_token = generate_key()

        return super(ExpiringToken, self).save(*args, **kwargs)

    @classmethod
    def delete_expired(cls, user):
        for token in cls.objects.filter(user=user):
            if token.is_access_token_expired or token.is_refresh_token_expired:
                token.delete()

    def regenerate(self):
        self.access_token = generate_key()
        self.access_token_expires = get_default_access_token_expiry()
        self.access_token_valid_until = get_default_access_token_validity()

        self.refresh_token = generate_key()
        self.refresh_token_expires = get_default_refresh_token_expiry()
        self.refresh_token_valid_until = get_default_refresh_token_validity()

        self.save()

    def __str__(self):
        return self.access_token[:30]
