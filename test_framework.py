import sys


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
        if sys.argv[1:2] == ["test"]:
            print(
                "Skipping function execution because it's being run within a manage.py test command."
            )
        else:
            return func(*args, **kwargs)

    return wrapper
