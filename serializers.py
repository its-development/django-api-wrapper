from rest_framework import serializers

from api.exceptions import ApiPermissionError, ApiSerializerActionNotProvidedError
from api.helpers import ApiHelpers
from api.models import ApiWrapperModel
from api.settings import ApiSettings
from django.db import models


class ApiWrapperModelSerializer(serializers.ModelSerializer):
    __model__ = serializers.SerializerMethodField("get__model__")

    def get__model__(self, obj):
        return self.Meta.model.__name__

    @classmethod
    def get_accessible_fields(cls, request, check_field_permission=False):
        res = [*cls.Meta.fields]

        if not check_field_permission:
            return res

        if not request:
            if ApiSettings.DEBUG:
                print("ApiWrapperModelSerializer: No request provided.")
            return res

        current_user = request.user
        if not current_user:
            if ApiSettings.DEBUG:
                print("ApiWrapperModelSerializer: No user found in request")
            return res

        accessible_fields = []

        for i, field_name in enumerate(res):
            real_field_name = field_name
            if "__" in field_name:
                real_field_name = ApiHelpers.list_get(field_name.split("__"), 0, None)

            if not real_field_name:
                continue

            if current_user.has_perm(
                "%s.view_%s_%s"
                % (
                    cls.Meta.model._meta.app_label,
                    cls.Meta.model._meta.model_name,
                    real_field_name,
                )
            ):
                accessible_fields.append(field_name)

        return accessible_fields

    def to_representation(self, request_data):
        ret = super(ApiWrapperModelSerializer, self).to_representation(request_data)
        if not self.context.get("check_field_permission", False):
            return ret

        accessible_fields = self.__class__.get_accessible_fields(
            self.context.get("request"),
            self.context.get("check_field_permission", False),
        )

        for field_name, field_value in sorted(ret.items()):
            if field_name not in accessible_fields:
                ret.pop(field_name)

        return ret

    def run_validators(self, value):
        """
        Checking object permission on related fields.
        """
        for field_name, field_value in value.items():
            if isinstance(field_value, (ApiWrapperModel, models.Model)):
                if not field_value.check_view_perm(self.context.get("request")):
                    raise ApiPermissionError()

        super().run_validators(value)

    class Meta:
        fields = ["__model__"]
