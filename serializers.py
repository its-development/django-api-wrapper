from rest_framework import serializers


class ApiWrapperModelSerializer(serializers.ModelSerializer):
    __model__ = serializers.SerializerMethodField("get__model__")

    def get__model__(self, obj):
        return self.Meta.model.__name__

    class Meta:
        fields = ["__model__"]
