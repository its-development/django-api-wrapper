import binascii
import os

from django.conf import settings
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext as _

from .settings import custom_settings


class ExpiringToken(models.Model):

    class Meta:
        db_table = 'auth_expiry_tokens'
        verbose_name = "Token"
        verbose_name_plural = "Tokens"

    key = models.CharField("Key", max_length=255, primary_key=True)
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, related_name='auth_token',
        on_delete=models.CASCADE, verbose_name="User"
    )
    ip_addr = models.GenericIPAddressField(default=None, null=True)
    created = models.DateTimeField("Created", auto_now_add=True)
    expires = models.DateTimeField("Expires in", )
    valid_until = models.DateTimeField("Valid until", )

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = self.generate_key()

        self.expires = timezone.now() + custom_settings.EXPIRING_TOKEN_DURATION

        if not self.valid_until:
            self.valid_until = timezone.now() + custom_settings.EXPIRING_TOKEN_MAX_LIFETIME

        return super(ExpiringToken, self).save(*args, **kwargs)

    def generate_key(self):
        return binascii.hexlify(
            os.urandom(custom_settings.EXPIRING_TOKEN_LENGTH)
        ).decode()[0:custom_settings.EXPIRING_TOKEN_LENGTH]

    def __str__(self):
        return self.key
