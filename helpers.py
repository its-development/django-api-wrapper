import binascii
import functools
import json
import os

from rest_framework import permissions
from rest_framework import exceptions

from api.exceptions import *
from api.cryptor import ApiCrypto


class ApiHelpers:

    @staticmethod
    def rgetattr(obj, attr, *args):
        def _getattr(obj, attr):
            return getattr(obj, attr, *args)

        return functools.reduce(_getattr, [obj] + attr.split('.'))

    @staticmethod
    def get_client_ip(request):

        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')

        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]

        else:
            ip = request.META.get('REMOTE_ADDR')

        return ip    \

    @staticmethod
    def get_client_user_agent(request):

        user_agent = request.META.get('HTTP_USER_AGENT')

        if not user_agent:
            raise ApiValueError("HTTP_USER_AGENT missing.")

        return user_agent

    @staticmethod
    def permission_required(permission_name, raise_exception=False):

        class PermissionRequired(permissions.BasePermission):

            def has_permission(self, request, view):

                if not request.user.has_perm(permission_name):

                    if raise_exception:
                        raise exceptions.PermissionDenied("Permission denied. Required: " + permission_name)

                    return False

                return True

        return PermissionRequired

    @staticmethod
    def get_rest_request_content(request):
        """
        deprecated

        :param request:
        :return request.content:
        """
        content = []
        if request:
            if request.method == 'GET':
                content = request.GET

            elif request.method == 'PUT':
                content = request.data

            elif request.method == 'DELETE':
                content = request.data

            elif request.method == 'POST':
                content = request.data

            elif request.method == 'PATCH':
                content = request.data

        if not content:
            content = []

        return content

    @staticmethod
    def get_request_content_data(content):
        data = {}

        if 'data' not in content:
            raise ApiContentDataNotProvided()

        data = content['data']

        return data

    @staticmethod
    def get_rest_content_filter(content):
        filter = {}

        if 'filter' not in content:
            raise ApiContentFilterNotProvided()

        filter = content['filter']

        return filter

    @staticmethod
    def get_rest_content_order(content):
        order = []

        if 'order' not in content:
            raise ApiContentOrderNotProvided()

        order = content.get('order')

        return order

    @staticmethod
    def get_rest_content_pagination(content):
        pagination = {}

        if 'pagination' not in content:
            raise ApiContentPaginationNotProvided()

        pagination = content['pagination']

        return pagination

    @staticmethod
    def encrypt_context(context):
        context.update(
            {
                str(binascii.hexlify(
                    os.urandom(150)
                ).decode()[0:150]): binascii.hexlify(
                    os.urandom(150)
                ).decode()[0:150]
            }
        )
        return {'data': ApiCrypto.encode(json.dumps(context, sort_keys=True, indent=1))}
