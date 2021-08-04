from rest_framework import serializers

from .models import ExpiringToken


class ExpiringTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = ExpiringToken
        fields = [
            'access_token',
            'access_token_expires',
            'access_token_valid_until',
            'refresh_token',
            'refresh_token_expires',
            'refresh_token_valid_until',
        ]
