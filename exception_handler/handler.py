from rest_framework.views import exception_handler
from api.context import ApiContext
from api.custom_views import CustomAPIView
from api.settings import ApiSettings


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

    try:
        request = context.get("view")
        if isinstance(request, CustomAPIView):
            messages.extend(request.context.get("messages", []))
    except:
        pass

    if response is not None:

        if response.data is not None:

            if "detail" in response.data:
                details = response.data.pop("detail")
                messages.append(
                    {
                        "type": response.status_code,
                        "message": details,
                        "code": details.code,
                    }
                )

        response.data = ApiContext.default()
        response.data.update({"status": response.status_code, "messages": messages})

    return response
