from django.contrib.auth.models import AbstractUser
from django.db import models
from .manager import ApiWrapperModelManager


class ApiWrapperModel(models.Model):
    objects = ApiWrapperModelManager

    class Meta:
        abstract = True


class ApiWrapperAbstractUser(AbstractUser):

    class Meta:
        abstract = True
