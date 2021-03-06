from rest_framework.exceptions import APIException
from rest_framework import status


class ApiValueError(APIException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR


class ApiPermissionError(APIException):
    status_code = status.HTTP_403_FORBIDDEN


class ApiError(APIException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR


class ApiTypeError(APIException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR


class ApiAuthFailed(APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = "ApiAuthFailed"
    default_code = "api_auth_failed"


class ApiAuthExpired(APIException):
    status_code = status.HTTP_423_LOCKED
    default_detail = "ApiAuthExpired"
    default_code = "api_auth_expired"


class ApiAuthInvalid(APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = "ApiAuthInvalid"
    default_code = "api_auth_invalid"


class ApiExpiringTokenNotFound(APIException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = "ApiExpiringTokenNotFound"
    default_code = "api_expiring_token_not_found"


class ApiExpiringTokenIsExpired(APIException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = "ApiExpiringTokenIsExpired"
    default_code = "api_expiring_token_is_expired"


class ApiSerializerInvalid(APIException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = "ApiSerializerInvalid"
    default_code = "api_serializer_invalid"


class ApiContentDataNotProvided(APIException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = "ApiContentDataNotProvided"
    default_code = "api_content_data_not_provided"


class ApiContentFilterNotProvided(APIException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = "ApiContentFilterNotProvided"
    default_code = "api_content_filter_not_provided"


class ApiContentFilterWrongFormat(APIException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = "ApiContentFilterWrongFormat"
    default_code = "api_content_filter_wrong_format"


class ApiContentOrderNotProvided(APIException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = "ApiContentOrderNotProvided"
    default_code = "api_content_order_not_provided"


class ApiContentPaginationNotProvided(APIException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = "ApiContentPaginationNotProvided"
    default_code = "api_content_pagination_not_provided"


class ApiPaginationError(APIException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = "api.pagination::paginate"
    default_code = "api_pagination_paginate_unsufficient_data_provided"


class ApiContentDataPkNotProvided(APIException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = "ApiContentDataPkNotProvided"
    default_code = "api_content_data_pk_not_provided"


class ApiObjectNotFound(APIException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = "ApiObjectNotFound"
    default_code = "api_object_not_found"


class ApiAuthUsernameOrPasswordNotProvided(APIException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = "ApiAuthUsernameOrPasswordNotProvided"
    default_code = "api_auth_username_or_password_not_provided"
