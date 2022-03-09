import binascii
import functools
import json
import os
from datetime import timedelta

from django.db.models import Q
from django.db.models.functions import Lower, Upper
from rest_framework import permissions
from rest_framework import exceptions

from api.exceptions import *
from api.cryptor import ApiCrypto

import ast
import operator as op


def eval_(node):
    operators = {
        ast.Add: op.add,
        ast.Sub: op.sub,
        ast.Mult: op.mul,
        ast.Div: op.truediv,
        ast.Pow: op.pow,
        ast.BitXor: op.xor,
        ast.USub: op.neg,
        ast.BitAnd: op.and_,
        ast.BitOr: op.or_,
    }

    if isinstance(node, ast.Num):
        return node.n
    elif isinstance(node, ast.BinOp):
        return operators[type(node.op)](eval_(node.left), eval_(node.right))
    elif isinstance(node, ast.UnaryOp):
        return operators[type(node.op)](eval_(node.operand))
    elif isinstance(node, ast.Call):
        if node.func.id == "Q":
            return Q(**{node.keywords[0].arg: node.keywords[0].value.value})
        elif node.func.id == "Lower":
            return Lower(node.args[0].value)
        elif node.func.id == "Upper":
            return Upper(node.args[0].value)
        else:
            raise ApiValueError("eval_ does not support this function. Hi exploiter :)")
    elif isinstance(node, ast.Constant):
        return node.value
    elif isinstance(node, ast.Tuple):
        return [eval_(elt) for elt in node.elts]
    else:
        raise ApiTypeError("eval_ does not support this node. Hi exploiter :)")


class ApiHelpers:
    @staticmethod
    def parse_string(val, template_vars):
        import re

        res = val

        matches = re.finditer(r"\[(.*?)\]", val)

        for match in matches:
            var = re.search("(?<=\[%).+?(?=\%])", match.group(0)).group(0)
            res = res.replace(match.group(0), template_vars[var])

        return res

    @staticmethod
    def eval_expr(expr):
        return eval_(ast.parse(expr, mode="eval").body)

    @staticmethod
    def daterange(date1, date2):
        for n in range(int((date2 - date1).days) + 1):
            yield date1 + timedelta(n)

    @staticmethod
    def rgetattr(obj, attr, *args):
        def _getattr(obj, attr):
            return getattr(obj, attr, *args)

        return functools.reduce(_getattr, [obj] + attr.split("."))

    @staticmethod
    def get_client_ip(request):

        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")

        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0]

        else:
            ip = request.META.get("REMOTE_ADDR")

        return ip

    @staticmethod
    def get_client_user_agent(request):

        user_agent = request.META.get("HTTP_USER_AGENT")

        if not user_agent:
            raise ApiValueError("HTTP_USER_AGENT missing.")

        return user_agent

    @staticmethod
    def permission_required(permission_name, raise_exception=False):
        class PermissionRequired(permissions.BasePermission):
            def has_permission(self, request, view):

                if not request.user.has_perm(permission_name):

                    if raise_exception:
                        raise exceptions.PermissionDenied(
                            "Permission denied. Required: " + permission_name
                        )

                    return False

                return True

        return PermissionRequired

    @staticmethod
    def encrypt_context(context):
        context.update(
            {
                str(
                    binascii.hexlify(os.urandom(150)).decode()[0:150]
                ): binascii.hexlify(os.urandom(150)).decode()[0:150]
            }
        )
        return {"data": ApiCrypto.encode(json.dumps(context, sort_keys=True, indent=1))}

    @staticmethod
    def round_float(value, precision) -> str:
        return ("%." + str(precision) + "f") % (value,)
