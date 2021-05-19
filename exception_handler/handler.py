from rest_framework.views import exception_handler
from api.context import ApiContext


def custom_exception_handler(exc, context):
    """
    TODO: Add Mailing and Error API here.
    :param exc:
    :param context:
    :return: Error Response
    """

    # Call REST framework's default exception handler first,
    # to get the standard error response.
    response = exception_handler(exc, context)
    messages = []

    if response is not None:

        if response.data is not None:

            if 'detail' in response.data:
                messages.append(
                    {
                        'type': 1,
                        'message': response.data.pop('detail')
                    }
                )

        response.data = ApiContext.default()
        response.data.update(
            {
                'status': response.status_code,
                'messages': messages
            }
        )

    return response
