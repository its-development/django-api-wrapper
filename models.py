import uuid

from django.contrib.auth.models import AbstractUser
from django.db import models
from .manager import ApiWrapperModelManager


class ApiWrapperModel(models.Model):
    objects = ApiWrapperModelManager

    id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False, unique=True
    )
    is_active = models.BooleanField(default=True)

    class Meta:
        abstract = True

    def check_obj_perm(self, request):
        return False

    def check_add_perm(self, request):
        return False

    def check_view_perm(self, request):
        return False

    def check_change_perm(self, request):
        return False

    def check_delete_perm(self, request):
        return False


class ApiWrapperAbstractUser(AbstractUser):
    id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False, unique=True
    )

    class Meta:
        abstract = True
