import sys
from uuid import UUID
from django.contrib.contenttypes.models import ContentType
from django.conf import settings


def compare_fields(db_item, request_item, assert_method):
    # Get the content type for the Item model
    content_type = ContentType.objects.get_for_model(db_item.__class__)

    # Get a list of all related fields for the Item model
    related_fields = [
        f.name for f in content_type.model_class()._meta.get_fields() if f.is_relation
    ]

    for field, value in request_item.items():
        if field in related_fields:
            assert_method(getattr(db_item, field + "_id"), UUID(value))
        else:
            assert_method(getattr(db_item, field), value)


def skip(condition, reason=""):
    def decorator(func):
        def wrapper(*args, **kwargs):
            if condition:
                print(f"Skipping {func.__name__} because {reason}")
            else:
                return func(*args, **kwargs)

        return wrapper

    return decorator


def skip_if_in_django_test_command(func):
    def wrapper(*args, **kwargs):
        if len(sys.argv) >= 2 and sys.argv[1:2] == ["test"]:
            print(
                f"Skipping {func.__name__} because it is run in a django test command"
            ) if settings.DEBUG else None
        else:
            return func(*args, **kwargs)

    return wrapper
