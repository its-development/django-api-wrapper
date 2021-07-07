# django-api-wrapper
**A smart wrapper to build blazing fast restful api's**

## Introduction

django-api-wrapper is build to keep common rest functionalities as simple as possible.


## Custom View's

To improve speed we've added most common view functionalities to our custom views.

Supporting:
* CustomListView
* CustomGetView
* CustomCreateView
* CustomUpdateView
* CustomDeleteView
* CustomExportView

as simple as:

~~~python
from api.custom_views import CustomListView
from api.helpers import ApiHelpers

class List(CustomListView):
    object_class = YOUR_MODEL_HERE
    return_serializer_class = YOUR_SERIALIZER_HERE

    authentication_classes = []
    permission_classes = [
        ApiHelpers.permission_required('YOUR_PERMISSION_NAME', raise_exception=True)
    ]
~~~

## Encryption

Since we dont want to depend on to much libraries, we've added a simple but effective XOR-Encryption.

The encryption is also bytes-capable and allows file encryption.

as simple as:
~~~python
from api.cryptor import ApiCrypto

plain_text = "django-api-wrapper"
encrypted_text = ApiCrypto.encode(plain_text)
decrypted_text = ApiCrypto.decode(encrypted_text)
~~~

## License

There is no license yet.

### Contact Information

For help or issues using the django-api-wrapper, please submit a GitHub issue.

For other communications related to the django-api-wrapper, please contact us (`mail@its-development.de`).

