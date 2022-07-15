import uuid

from django.contrib.auth.models import AbstractUser
from django.db import models
from .manager import ApiWrapperModelManager


class ApiWrapperQuerySet(models.QuerySet):
    @classmethod
    def property_annotate(cls, queryset):
        return queryset

    def get(self, *args, **kwargs):
        # TODO: Find better solution here, annotate before get is not possible
        res = self.__class__.property_annotate(super()).filter(*args, **kwargs)
        raise self.model.DoesNotExist() if not res else self.model.MultipleObjectsReturned()
        return res[0]

    def get_queryset(self):
        return self.__class__.property_annotate(super().get_queryset())


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

    email = models.EmailField(
        blank=True,
        unique=True,
    )

    class Meta:
        abstract = True
