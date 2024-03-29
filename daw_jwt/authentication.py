import logging
import traceback

from django.contrib.auth import get_user_model
from rest_framework.authentication import BaseAuthentication

from api.crypto import ApiCrypto
from .handler import decode_jwt
from ..exceptions import ApiAuthInvalid
from ..helpers import ApiHelpers


class DAWJWTAuthentication(BaseAuthentication):
    """
    This Class should be threatened as an abstract class.
    """

    check_ip = True
    check_user_agent = True
    request_header = "HTTP_AUTHORIZATION"
    request_header_key = "Bearer"
    user_model = get_user_model()

    def check_request_ip(self, request, payload):
        ip_addr = payload.get("ip_addr", None)
        if ip_addr != ApiHelpers.get_client_ip(request):
            raise ApiAuthInvalid()

    def check_request_user_agent(self, request, payload):
        user_agent = payload.get("user_agent", None)
        if user_agent != ApiHelpers.get_client_user_agent(request):
            raise ApiAuthInvalid()

    def get_user_from_payload(self, request, payload):
        user_id = payload.get("user_id", None)

        if not user_id:
            return None

        user_id = ApiCrypto.decode(user_id)

        if self.check_ip:
            self.check_request_ip(request, payload)

        if self.check_user_agent:
            self.check_request_user_agent(request, payload)

        return self.user_model.objects.get(id=user_id)

    def authenticate(self, request):
        auth_header = request.META.get(self.request_header, "")

        if not auth_header.startswith(f"{self.request_header_key} "):
            return None

        try:
            token = auth_header.split(" ")[1]
            payload = self.get_payload_from_token(token)
            user = self.get_user_from_payload(request, payload)

            return user, None

        except Exception as e:
            traceback.print_exc()
            logging.getLogger("django").error(traceback.format_exc())

        raise ApiAuthInvalid()

    def get_payload_from_token(self, token):
        return decode_jwt(token)
