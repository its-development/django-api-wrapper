from django.apps import apps
from django.contrib.auth.models import Permission
from rest_framework.test import APITestCase

from django.conf import settings

auth_model = apps.get_model(*settings.AUTH_USER_MODEL.split("."))


class ApiTestCase(APITestCase):
    perms = []

    def setUpData(self):
        self.init_users()
        self.init_clients()

    def init_clients(self):
        self.client, self.client_perm, self.client_admin = (
            self.client_class(),
            self.client_class(),
            self.client_class(),
        )
        self.client.force_authenticate(self.user)
        self.client_perm.force_authenticate(self.user_perm)
        self.client_admin.force_authenticate(self.user_admin)

        self.CLIENTS = [self.client, self.client_perm, self.client_admin]

        return self.CLIENTS

    def init_users(self):
        self.user = auth_model.objects.create(
            username="unit_test",
            first_name="Unit",
            last_name="Test",
            email="ut@test.te",
        )
        self.user_perm = auth_model.objects.create(
            username="unit_test_perm",
            first_name="Unit",
            last_name="Test",
            email="ut@test.te",
        )
        self.user_admin = auth_model.objects.create(
            username="unit_test_admin",
            first_name="Unit",
            last_name="Test",
            email="ut@test.te",
            is_superuser=True,
        )

        for perm in self.perms:
            self.user_perm.user_permissions.add(Permission.objects.get(codename=perm))

        self.USERS = [self.user, self.user_perm, self.user_admin]

        return self.USERS
