import uuid

from django.contrib.auth.models import AbstractUser
from django.db import models
from .manager import ApiWrapperModelManager, ApiWrapperUserManager


class AnnotatedProperty(object):
    """
    Property for already annotated values, e.g. from a queryset. But it can also be used on instances.
    """

    def __init__(self, fget=None):
        self.fget = fget

    def __get__(self, obj, objtype=None):
        if self.fget is None:
            raise AttributeError("unreadable attribute")

        # Check if the object's dictionary already has the attribute
        if self.fget.__name__ in obj.__dict__:
            return obj.__dict__[self.fget.__name__]

        # If not, calculate it using fget
        return self.fget(obj)


class ApiWrapperModel(models.Model):
    objects = ApiWrapperModelManager()

    id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False, unique=True
    )
    is_active = models.BooleanField(default=True)

    class Meta:
        base_manager_name = "objects"
        abstract = True

    @property
    def _reference_hash(self):
        return f"{self.__class__.__name__}:{self.id}"

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

    def check_export_perm(self, request):
        return False


class ApiWrapperAbstractUser(AbstractUser):
    objects = ApiWrapperUserManager()
    id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False, unique=True
    )

    full_name = models.CharField(max_length=255, default="N/A")

    email = models.EmailField(
        blank=True,
        unique=True,
    )

    class Meta:
        base_manager_name = "objects"
        abstract = True

    def save(self, *args, **kwargs):
        self.full_name = f"{self.first_name} {self.last_name}"
        super().save(*args, **kwargs)
