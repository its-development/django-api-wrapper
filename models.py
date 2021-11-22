import uuid

from django.contrib.auth.models import AbstractUser
from django.db import models
from .manager import ApiWrapperModelManager


class ApiWrapperModel(models.Model):
    objects = ApiWrapperModelManager

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)

    class Meta:
        abstract = True


class ApiWrapperAbstractUser(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)

    class Meta:
        abstract = True
