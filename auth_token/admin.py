from django.contrib import admin

from .models import ExpiringToken


@admin.register(ExpiringToken)
class TokenAdmin(admin.ModelAdmin):
    pass
