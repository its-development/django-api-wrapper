from django.db import transaction
from rest_framework import status

from api.context import ApiContext
from api.custom_views import CustomAPIView
from api.daw_jwt.handler import create_jwt
from api.exceptions import ApiAuthInvalid
from api.helpers import ApiHelpers
from api.cryptor import ApiCrypto


class ObtainJWT(CustomAPIView):
    authentication_classes = []
    permission_classes = []
    return_serializer_class = None
    user_serializer = None

    def __init__(self, *args, **kwargs):
        self.context = ApiContext.get()
        super().__init__(*args, **kwargs)

    def _auth_method(self, username, password) -> (object, any):
        raise NotImplementedError

    def generate_jwt_token(self, user, payload=None):
        encoded_user_id = ApiCrypto.encode(str(user.id)).decode()

        return create_jwt(
            {
                "user_id": encoded_user_id,
                "ip_addr": ApiHelpers.get_client_ip(self.request),
                "user_agent": ApiHelpers.get_client_user_agent(self.request),
            }
        )

    def handler(self):
        username = self.request_data.get("username", None)
        password = self.request_data.get("password", None)

        user, data = self._auth_method(username, password)

        if not user:
            raise ApiAuthInvalid()

        self.request.user = user

        jwt_token = self.generate_jwt_token(user, payload=data)

        self.context.update(
            {
                "results": {
                    "access_token": jwt_token,
                },
            }
        )

    def process(self):
        self.get_rest_request_content()
        self.get_rest_content_flags()
        self.get_request_content_data()

        try:
            self.handler()
        except Exception as e:
            self.pre_handle_exception(e)

        self.add_user_to_context()

        self.context.update(
            {
                "success": True,
            }
        )

        return self.respond(status.HTTP_200_OK)

    def post(self, request):
        if self.transactional:
            with transaction.atomic():
                return self.process()

        return self.process()
