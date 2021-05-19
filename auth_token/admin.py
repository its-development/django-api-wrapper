from django.contrib import admin

from .models import ExpiringToken


@admin.register(ExpiringToken)
class TokenAdmin(admin.ModelAdmin):
    list_display = ('key', 'user', 'created', 'expires', 'valid_until')
    fields = ('user', 'expires', 'valid_until')
    ordering = ('-valid_until',)
