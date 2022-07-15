from django.db import models


class ApiWrapperModelManager(models.Manager):
    def property_annotate(self, queryset):
        return queryset

    def get_queryset(self):
        return self.property_annotate(super().get_queryset())
