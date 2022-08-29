from rest_framework import serializers

from api.exceptions import ApiPermissionError
from api.helpers import ApiHelpers
from api.models import ApiWrapperModel
from api.settings import ApiSettings
from django.db import models


class ApiWrapperModelSerializer(serializers.ModelSerializer):
    __model__ = serializers.SerializerMethodField("get__model__")

    def get__model__(self, obj):
        return self.Meta.model.__name__

    def to_representation(self, request_data):
        ret = super(ApiWrapperModelSerializer, self).to_representation(request_data)
        if not self.context.get("check_field_permission", False):
            return ret

        request = self.context.get("request")
        if not request:
            if ApiSettings.get("DEBUG"):
                print("ApiWrapperModelSerializer: No request found in context")
            return ret

        current_user = request.user
        if not current_user:
            if ApiSettings.get("DEBUG"):
                print("ApiWrapperModelSerializer: No user found in request")
            return ret

        for field_name, field_value in sorted(ret.items()):
            real_field_name = field_name
            if "__" in field_name:
                real_field_name = ApiHelpers.list_get(field_name.split("__"), 0, None)

            if not real_field_name:
                continue

            if not current_user.has_perm(
                "%s.view_%s_%s"
                % (
                    self.Meta.model._meta.app_label,
                    self.Meta.model._meta.model_name,
                    real_field_name,
                )
            ):
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
