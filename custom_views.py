from django.http import HttpResponse
from django.db.models import Q

from rest_framework.renderers import JSONRenderer
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .models import ApiWrapperModel, ApiWrapperAbstractUser
from .settings import ApiSettings
from .helpers import ApiHelpers
from .pagination import ApiPaginator
from .context import ApiContext
from .exceptions import *

import csv
import re


class CustomAPIView(APIView):
    object_class = None
    return_serializer_class = None
    user_serializer = None
    serializer_class = None
    enhanced_filters = False
    check_object_permission = True

    def __init__(self, *args, **kwargs):
        self.request_content = {}
        self.request_data = {}
        self.request_filter = {}
        self.request_order = {}
        self.request_flags = {}

        super().__init__(*args, **kwargs)

    def check_serializer_field_perm(self, serializer):
        for _, obj in serializer.validated_data.items():
            if isinstance(obj, (ApiWrapperModel, ApiWrapperAbstractUser)):
                if not obj.check_obj_perm(self.request):
                    return False

        return True

    def add_user_to_context(self, ctx, request):
        if not request.user:
            return

        if not self.user_serializer:
            return

        ctx.update({"user": self.user_serializer(instance=request.user).data})

    def hook_request_data(self, data):
        return data

    def get_rest_content_flags(self):
        self.request_flags = self.request_content.get("flags", {})
        return self.request_flags

    def get_rest_request_content(self):
        """

        :param request:
        :return request.data:
        """
        content = {}

        if self.request:
            if self.request.method == "GET":
                content = self.request.GET

            elif self.request.method == "PUT":
                content = self.request.data

            elif self.request.method == "DELETE":
                content = self.request.data

            elif self.request.method == "POST":
                content = self.request.data

            elif self.request.method == "PATCH":
                content = self.request.data

        self.request_content = content

    def get_request_content_data(self):
        """

        :return self.request_content.data:
        """

        data = self.request_content.get("data", {})

        self.request_data = self.hook_request_data(data)

        return self.request_data

    def parse_filter(self, request_filter):
        if type(request_filter) not in [list, dict, str]:
            if ApiSettings.DEBUG:
                print(type(request_filter))
            raise ApiContentFilterWrongFormat()

        if type(request_filter) in [str] and not self.enhanced_filters:
            raise ApiContentFilterWrongFormat("Enhanced filters are disabled.")

        if self.enhanced_filters and isinstance(request_filter, str):
            request_filter = ApiHelpers.eval_expr(request_filter)

        return request_filter

    def get_rest_content_filter(self):
        """

        :return:
        """
        return self.parse_filter(self.request_content.get("filter", None))

    @staticmethod
    def generate_enhanced_filters(request_filter=None):
        """
        :param request_filter:
        :return generated filter expression:
        """
        generated_filter = []

        for i, re_filter in enumerate(request_filter):
            op = "&"
            open_group = ""
            close_group = ""

            #  Remove any characters not allowed in variables
            for key in re_filter["expr"]:
                if isinstance(re_filter["expr"][key], str):
                    clean_val = str(
                        re.sub(r"([^A-z0-9\- ]*)", "", str(re_filter["expr"][key]))
                    )

                else:
                    clean_val = re_filter["expr"][key]

                clean_key = re.sub(r"([^A-z0-9\-]*)", "", key)
                break

            if "open" in re_filter:
                open_group = "("

            elif "close" in re_filter:
                close_group = ")"

            if i > 0:

                if "operator" in re_filter:
                    if re_filter["operator"] == "or":
                        op = "|"

                    elif re_filter["operator"] == "and":
                        op = "&"

                    else:
                        raise ApiValueError("unknown operator")

                    generated_filter.append(op)
                    generated_filter.append(
                        "%sQ(%s='%s')%s"
                        % (open_group, clean_key, clean_val, close_group)
                    )

                else:
                    raise ApiValueError("Filter operator not provided")

            else:
                generated_filter.append(
                    "%sQ(%s='%s')%s" % (open_group, clean_key, clean_val, close_group)
                )

        generated_filter = " ".join(generated_filter)

        return ApiHelpers.eval_expr(generated_filter) if generated_filter else None

    def get_rest_content_order(self):
        """
        :return self.request_content.filter:
        """

        if "order" not in self.request_content:
            raise ApiContentOrderNotProvided()

        return [*self.request_content.get("order"), ""]

    def get_rest_content_pagination(self):

        if "pagination" not in self.request_content:
            raise ApiContentPaginationNotProvided()

        return self.request_content.get("pagination")

    def filter_queryset(self, manager, fil=None):

        if fil:
            if isinstance(fil, dict):
                objects = manager.filter(**fil)
            elif isinstance(fil, Q):
                objects = manager.filter(fil)
            else:
                if ApiSettings.DEBUG:
                    print(type(fil))
                raise ApiContentFilterWrongFormat()

            objects = objects

        else:
            objects = manager.all()

        if self.distinct_query:
            objects = objects.distinct()

        return objects

    def get_queryset(self, manager, fil=None):
        if fil:
            if isinstance(fil, dict):
                obj = manager.get(**fil)
            elif isinstance(fil, Q):
                obj = manager.get(fil)
            else:
                if ApiSettings.DEBUG:
                    print(type(fil))
                raise ApiContentFilterWrongFormat()

        else:
            raise ApiContentFilterNotProvided()

        if not obj:
            raise self.object_class.DoesNotExist()

        return obj

    def handler(self, request, context):
        raise NotImplementedError()

    def process(self, request):
        context = ApiContext.default()
        request, context = self.handler(request, context)

        return Response(
            ApiHelpers.encrypt_context(context)
            if self.request_content.get("encrypt") is True
            else context,
        )


class CustomListView(CustomAPIView):
    renderer_classes = [JSONRenderer]
    distinct_query = False

    def __init__(self, *args, **kwargs):
        self.request_filter = {}
        self.request_pagination = {}
        self.request_order = []

        super().__init__(*args, **kwargs)

    def handler(self, request, context):
        objects = self.filter_queryset(
            self.object_class.objects,
            self.request_filter,
        )
        objects = objects.order_by(
            *ApiHelpers.eval_expr("(%s)" % (", ".join(self.request_order)))
        )

        paginator = ApiPaginator(self.request_pagination)

        result_set = paginator.paginate(
            objects=objects,
            request=request,
            check_object_permission=self.check_object_permission,
        )

        paginator.update_context(context)

        result_set = [
            self.return_serializer_class(instance=result).data for result in result_set
        ]

        context.update(
            {
                "results": result_set,
                "columns": [*self.return_serializer_class.Meta.fields],
            }
        )

        return request, context

    def process(self, request):
        context = ApiContext.list()

        self.get_rest_request_content()
        self.request_filter = self.get_rest_content_filter()
        self.request_pagination = self.get_rest_content_pagination()
        self.request_order = self.get_rest_content_order()

        request, context = self.handler(request, context)

        self.add_user_to_context(context, request)

        context.update(
            {
                "success": True,
                "status": status.HTTP_200_OK,
            }
        )

        return Response(
            ApiHelpers.encrypt_context(context)
            if self.request_content.get("encrypt") is True
            else context,
        )

    def post(self, request):
        return self.process(request)


class CustomValueListView(CustomAPIView):
    renderer_classes = [JSONRenderer]
    distinct_query = False

    def __init__(self, *args, **kwargs):
        self.request_filter = {}
        self.request_pagination = {}
        self.request_order = []
        self.request_data = {}

        super().__init__(*args, **kwargs)

    def handler(self, request, context):
        objects = self.filter_queryset(
            self.object_class.objects,
            self.request_filter,
        )
        objects = objects.order_by(
            *ApiHelpers.eval_expr("(%s)" % (", ".join(self.request_order)))
        )

        paginator = ApiPaginator(self.request_pagination)

        result_set = paginator.paginate(
            objects=objects,
            request=request,
            check_object_permission=self.check_object_permission,
        )
        paginator.update_context(context)

        result_set = [
            ApiHelpers.rgetattr(result, self.request_data.get("value"))
            for result in result_set
        ]

        context.update(
            {
                "results": result_set,
                "columns": [self.request_data.get("value")],
            }
        )

        return request, context

    def process(self, request):
        context = ApiContext.list()

        self.get_rest_request_content()
        self.get_request_content_data()

        self.request_filter = self.get_rest_content_filter()
        self.request_pagination = self.get_rest_content_pagination()
        self.request_order = self.get_rest_content_order()

        request, context = self.handler(request, context)

        self.add_user_to_context(context, request)

        context.update(
            {
                "success": True,
                "status": status.HTTP_200_OK,
            }
        )

        return Response(
            ApiHelpers.encrypt_context(context)
            if self.request_content.get("encrypt") is True
            else context,
        )

    def post(self, request):
        return self.process(request)


class CustomGetView(CustomAPIView):
    renderer_classes = [JSONRenderer]

    def __init__(self, *args, **kwargs):
        self.request_data = {}

        super().__init__(*args, **kwargs)

    def handler(self, request, context):
        obj = self.get_queryset(
            self.object_class.objects,
            self.request_filter,
        )

        if self.check_object_permission and not obj.check_view_perm(request):
            raise ApiPermissionError("Object permission denied.")

        context.update({"result": self.return_serializer_class(obj).data})

        return request, context

    def process(self, request):
        context = ApiContext.get()

        self.get_rest_request_content()
        self.request_filter = self.get_rest_content_filter()
        self.get_rest_content_flags()
        self.get_request_content_data()

        request, context = self.handler(request, context)

        self.add_user_to_context(context, request)

        context.update(
            {
                "success": True,
            }
        )

        return Response(
            ApiHelpers.encrypt_context(context)
            if self.request_content.get("encrypt") is True
            else context,
        )

    def post(self, request):
        return self.process(request)


class CustomCreateView(CustomAPIView):
    renderer_classes = [JSONRenderer]

    def __init__(self, *args, **kwargs):
        self.request_data = {}

        super().__init__(*args, **kwargs)

    def hook_after_creation(self, obj):
        pass

    def hook_before_creation(self, tmp_obj):
        pass

    def handler(self, request, context):
        serializer = self.serializer_class(
            data=self.request_data, context={"request": request}
        )

        if not serializer.is_valid():
            if ApiSettings.DEBUG:
                print(serializer.errors)
            raise ApiSerializerInvalid()

        if not self.check_serializer_field_perm(serializer):
            raise ApiPermissionError()

        tmp_object = self.object_class(**serializer.validated_data)
        self.hook_before_creation(tmp_object)

        if self.check_object_permission and not tmp_object.check_add_perm(request):
            raise ApiPermissionError()

        tmp_object.save()

        self.hook_after_creation(tmp_object)

        context.update(
            {"result": self.return_serializer_class(instance=tmp_object).data}
        )

        return request, context

    def process(self, request):
        context = ApiContext.create()

        self.get_rest_request_content()
        self.get_rest_content_flags()
        self.get_request_content_data()

        request, context = self.handler(request, context)

        self.add_user_to_context(context, request)

        context.update({"success": True})

        return Response(
            ApiHelpers.encrypt_context(context)
            if self.request_content.get("encrypt") is True
            else context,
            status=status.HTTP_201_CREATED,
        )

    def put(self, request):
        return self.process(request)

    def post(self, request):
        return self.process(request)


class CustomAddView(CustomCreateView):
    # Proxy class
    pass


class CustomUpdateView(CustomAPIView):
    renderer_classes = [JSONRenderer]

    def __init__(self, *args, **kwargs):
        self.request_data = {}

        super().__init__(*args, **kwargs)

    def hook_after_update(self, obj):
        pass

    def handler(self, request, context):

        if "id" not in self.request_data and "pk" not in self.request_data:
            raise ApiContentDataPkNotProvided()

        pk = (
            self.request_data.get("id")
            if self.request_data.get("id")
            else self.request_data.get("pk")
        )

        object_to_update = self.object_class.objects.get(pk=pk)

        if not object_to_update:
            raise ApiObjectNotFound()

        if not object_to_update.check_change_perm(request):
            raise ApiPermissionError("Object permission denied.")

        serializer = self.serializer_class(
            instance=object_to_update, data=self.request_data, partial=True
        )

        if not serializer.is_valid():
            if ApiSettings.DEBUG:
                print(serializer.errors)
            raise ApiSerializerInvalid()

        updated_object = serializer.save()

        self.hook_after_update(updated_object)

        context.update(
            {"result": self.return_serializer_class(instance=updated_object).data}
        )

        return request, context

    def process(self, request):
        context = ApiContext.update()

        self.get_rest_request_content()
        self.get_request_content_data()
        self.get_rest_content_flags()

        request, context = self.handler(request, context)

        self.add_user_to_context(context, request)

        context.update({"success": True})

        return Response(
            ApiHelpers.encrypt_context(context)
            if self.request_content.get("encrypt") is True
            else context,
        )

    def patch(self, request):
        return self.process(request)


class CustomChangeView(CustomUpdateView):
    # Proxy class
    pass


class CustomDeleteView(CustomAPIView):
    renderer_classes = [JSONRenderer]

    def __init__(self, *args, **kwargs):
        self.request_data = {}

        super().__init__(*args, **kwargs)

    def handler(self, request, context):

        if "id" not in self.request_data and "pk" not in self.request_data:
            raise ApiContentDataPkNotProvided()

        pk = (
            self.request_data.get("id")
            if self.request_data.get("id")
            else self.request_data.get("pk")
        )

        obj_to_delete = self.object_class.objects.get(pk=pk)

        if not obj_to_delete:
            raise ApiObjectNotFound()

        if not obj_to_delete.check_delete_perm(request):
            raise ApiPermissionError("Object permission denied.")

        obj_to_delete.delete()

        return request, context

    def process(self, request):
        context = ApiContext.remove()

        self.get_rest_request_content()
        self.get_request_content_data()
        self.get_rest_content_flags()

        request, context = self.handler(request, context)

        self.add_user_to_context(context, request)

        context.update({"status": 200, "success": True})

        return Response(
            ApiHelpers.encrypt_context(context)
            if self.request_content.get("encrypt") is True
            else context,
        )

    def post(self, request):
        return self.process(request)


class CustomExportView(CustomAPIView):
    renderer_classes = [JSONRenderer]

    def post(self, request):
        self.get_rest_request_content()
        self.get_request_content_data()
        self.request_filter = self.get_rest_content_filter()

        file_type = self.request_data.get("file_type")

        if not file_type:
            raise ApiValueError("file_type not provided.")

        fields = self.request_data.get("fields")

        if not fields:
            fields = [field.name for field in self.object_class._meta.get_fields()]

        fields_translation = self.request_data.get("header")

        if not fields_translation:
            fields_translation = fields

        if fields_translation and len(fields_translation) != len(fields):
            raise ApiValueError("Header count is unequal to fields count.")

        header = {}

        for i, field in enumerate(fields):
            header.update({str(field): str(fields_translation[i])})

        collection = self.object_class.objects.filter(**self.request_filter)

        for obj in collection:
            if not obj.check_export_perm(request):
                collection = collection.exclude(pk=obj.pk)

        if file_type == "csv":
            delimiter = self.request_data.get("delimiter")

            if not delimiter:
                raise ApiValueError("delimiter not provided")

            response = HttpResponse(content_type="text/csv")
            response["Content-Disposition"] = 'attachment; filename="export.csv"'

            writer = csv.DictWriter(response, fieldnames=header, delimiter=delimiter)

            if header:
                writer.writerow(header)

            else:
                writer.writeheader(fields)

            for row in collection:
                row_data = {}
                for field in fields:
                    row_data[field] = ApiHelpers.rgetattr(row, field)

                writer.writerow(row_data)

        else:
            raise ApiError("No matching file_type.")

        return response


class BasicPasswordAuth(CustomAPIView):
    authentication_classes = []
    permission_classes = []

    model = None
    model_serializer = None

    def _auth_method(self, username, password):
        raise NotImplemented()

    def process(self, request):
        context = ApiContext.auth()

        self.get_rest_request_content()
        self.get_request_content_data()
        self.get_rest_content_flags()

        if "username" not in self.request_data or "password" not in self.request_data:
            raise ApiAuthUsernameOrPasswordNotProvided()

        user = self._auth_method(
            username=self.request_data["username"],
            password=self.request_data["password"],
        )
        user_ip = ApiHelpers.get_client_ip(request)
        user_user_agent = ApiHelpers.get_client_user_agent(request)

        if not user:
            raise ApiAuthFailed()

        token = self.model.objects.create(
            user=user, ip_addr=user_ip, user_agent=user_user_agent
        )

        context.update(
            {
                "success": True,
                "status": 200,
                "results": {
                    "user": self.serializer_class(instance=user).data,
                    "token": self.model_serializer(instance=token).data,
                },
            }
        )

        return Response(
            context,
        )

    def post(self, request):
        return self.process(request)


class BasicTokenRefresh(CustomAPIView):
    authentication_classes = []
    permission_classes = []

    model = None
    model_serializer = None

    def _auth_method(self, username, password):
        raise NotImplemented()

    def handler(self, request, context):
        from django.utils import timezone

        refresh_token = self.request_data.get("refresh_token")

        if not refresh_token:
            raise ApiValueError("refresh_token not provided")

        try:
            token = self.model.objects.get(refresh_token=refresh_token)
        except self.model.DoesNotExist:
            raise ApiValueError("refresh_token_does_not_exist")

        if token.is_refresh_token_expired:
            token.delete()
            raise ApiValueError("refresh_token expired")

        if token.is_access_token_expired:
            if token.updated_at + timezone.timedelta(seconds=10) < timezone.now():
                token.regenerate()

        context.update(
            {"result": {"token": self.model_serializer(instance=token).data}}
        )

        return request, context

    def process(self, request):
        context = ApiContext.get()

        self.get_rest_request_content()
        self.get_request_content_data()
        self.get_rest_content_flags()

        request, context = self.handler(request, context)

        context.update({"success": True})

        return Response(
            ApiHelpers.encrypt_context(context)
            if self.request_content.get("encrypt") is True
            else context,
        )

    def post(self, request):
        return self.process(request)
