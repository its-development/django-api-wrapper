import json
import csv
import logging
import os
import traceback

from django.db import transaction, IntegrityError, NotSupportedError
from django.http import HttpResponse, FileResponse
from django.db.models import Q, ProtectedError
from rest_framework.parsers import MultiPartParser, FormParser

from rest_framework.renderers import JSONRenderer
from rest_framework.views import APIView
from rest_framework.response import Response

from .serializers import ApiWrapperModelSerializer
from .settings import ApiSettings
from .helpers import ApiHelpers
from .pagination import ApiPaginator
from .context import ApiContext
from .exceptions import *
from .throttles import BasicPasswordAuthThrottle, BasicTokenRefreshThrottle

logger = logging.getLogger(os.environ.get("DJANGO_API_WRAPPER_LOGGER", "django"))


class CustomAPIView(APIView):
    transactional = True

    object_class = None
    return_serializer_class = None
    user_serializer = None
    serializer_class = None
    enhanced_filters = False
    check_object_permission = True
    check_serializer_field_permission = True
    encryption = False
    session_data = {}

    def __init__(self, *args, **kwargs):
        self.request_content = {}
        self.request_data = {}
        self.request_filter = {}
        self.request_order = {}
        self.request_flags = {}

        super().__init__(*args, **kwargs)

    def respond(self, http_code=status.HTTP_200_OK):
        return Response(
            ApiHelpers.encrypt_context(self.context)
            if self.encryption
            else self.context,
            status=http_code,
        )

    def add_user_to_context(self):
        if not self.request.user:
            return

        if not self.user_serializer:
            return

        self.context.update(
            {
                "user": self.user_serializer(instance=self.request.user).data,
            }
        )

    def pre_handle_exception(self, e):
        if ApiSettings.DEBUG:
            logger.error(traceback.format_exc())
            traceback.print_exc()
        if not isinstance(e, APIException):
            raise ApiError(e)
        raise e

    def handle_invalid_serializer(self, serializer):
        if ApiSettings.DEBUG:
            print(serializer.errors)
            logger.error(serializer.errors)

        field = ApiHelpers.list_get(list(serializer.errors.keys()), 0, None)
        if not field:
            raise ApiSerializerInvalid()

        err_type = ApiHelpers.list_get(serializer.errors.get(field), 0, None)
        if not err_type:
            raise ApiSerializerInvalid()

        for field in serializer.errors:
            err_code = ApiHelpers.list_get(serializer.errors.get(field), 0, "None")
            self.context.update(
                {
                    "messages": self.context.get("messages", [])
                    + [
                        {
                            "type": "SerializerError",
                            "field": field,
                            "code": err_code.code,
                        }
                    ]
                }
            )

        raise ApiSerializerInvalid()

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

        if not self.request:
            raise ApiEmptyRequestError()

        if self.request.method == "GET":
            self.request_content = self.request.GET

        elif self.request.method == "PUT":
            self.request_content = self.request.data

        elif self.request.method == "DELETE":
            self.request_content = self.request.data

        elif self.request.method == "POST":
            self.request_content = self.request.data

        elif self.request.method == "PATCH":
            self.request_content = self.request.data

        else:
            raise ApiMethodNotSupportedError()

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

    def get_queryset(self):
        raise NotImplementedError()

    def annotate_queryset(self, objects):
        return objects

    def handler(self):
        raise NotImplementedError()


class CustomListView(CustomAPIView):
    renderer_classes = [JSONRenderer]
    distinct_query = False

    def __init__(self, *args, **kwargs):
        self.context = ApiContext.list()
        self.request_filter = {}
        self.request_pagination = {}
        self.request_order = []

        super().__init__(*args, **kwargs)

    def get_queryset(self):
        objects = self.filter_queryset(
            self.annotate_queryset(self.object_class.objects),
            self.request_filter,
        )
        objects = objects.order_by(
            *ApiHelpers.eval_expr("(%s)" % (", ".join(self.request_order)))
        )

        return objects

    def hook_before_serializer(self, result_set):
        return

    def handler(self):
        objects = self.get_queryset()

        paginator = ApiPaginator(self.request_pagination, distinct=self.distinct_query)

        result_set = paginator.paginate(
            objects=objects,
            request=self.request,
            check_object_permission=self.check_object_permission,
        )

        paginator.update_context(self.context)

        self.hook_before_serializer(result_set)

        result_set = [
            self.return_serializer_class(
                instance=result,
                context={
                    "request": self.request,
                    "check_field_permission": self.check_serializer_field_permission,
                    "action": "view",
                },
            ).data
            for result in result_set
        ]

        self.context.update(
            {
                "results": result_set,
            }
        )

    def process(self):
        self.get_rest_request_content()
        self.request_filter = self.get_rest_content_filter()
        self.request_pagination = self.get_rest_content_pagination()
        self.get_rest_content_flags()
        self.request_order = self.get_rest_content_order()

        try:
            self.handler()
        except Exception as e:
            self.pre_handle_exception(e)

        self.add_user_to_context()

        if self.return_serializer_class:
            self.context.update(
                {
                    "columns": self.return_serializer_class.get_accessible_fields(
                        self.request, self.check_serializer_field_permission
                    )
                    if issubclass(
                        self.return_serializer_class, ApiWrapperModelSerializer
                    )
                    else [*self.return_serializer_class.Meta.fields],
                }
            )

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


class CustomValueListView(CustomAPIView):
    renderer_classes = [JSONRenderer]
    distinct_query = True

    def __init__(self, *args, **kwargs):
        self.request_filter = {}
        self.request_pagination = {}
        self.request_order = []
        self.request_data = {}

        super().__init__(*args, **kwargs)

    def get_queryset(self):
        objects = self.filter_queryset(
            self.object_class.objects,
            self.request_filter,
        )
        objects = objects.order_by(
            *ApiHelpers.eval_expr("(%s)" % (", ".join(self.request_order)))
        )

        return objects

    def handler(self):
        objects = self.get_queryset()

        paginator = ApiPaginator(self.request_pagination)

        result_set = paginator.paginate(
            objects=objects,
            request=self.request,
            check_object_permission=self.check_object_permission,
        )
        paginator.update_context(self.context)

        result_set = [
            ApiHelpers.rgetattr(result, self.request_data.get("value"))
            for result in result_set
        ]

        self.context.update(
            {
                "results": result_set,
            }
        )

    def process(self):
        self.get_rest_request_content()
        self.get_request_content_data()

        self.request_filter = self.get_rest_content_filter()
        self.request_pagination = self.get_rest_content_pagination()
        self.request_order = self.get_rest_content_order()

        try:
            self.handler()
        except Exception as e:
            self.pre_handle_exception(e)

        self.add_user_to_context()

        self.context.update(
            {
                "success": True,
                "status": status.HTTP_200_OK,
                "columns": [self.request_data.get("value")],
            }
        )

        return self.respond(status.HTTP_200_OK)

    def post(self, request):
        if self.transactional:
            with transaction.atomic():
                return self.process()

        return self.process()


class CustomGetView(CustomAPIView):
    renderer_classes = [JSONRenderer]

    def __init__(self, *args, **kwargs):
        self.context = ApiContext.get()
        self.request_data = {}

        super().__init__(*args, **kwargs)

    def get_queryset(self):
        if self.request_filter:
            if isinstance(self.request_filter, dict):
                try:
                    obj = self.annotate_queryset(self.object_class.objects).get(
                        **self.request_filter
                    )
                except self.object_class.DoesNotExist:
                    raise ApiObjectNotFound()
            elif isinstance(self.request_filter, Q):
                try:
                    obj = self.annotate_queryset(self.object_class.objects).get(
                        self.request_filter
                    )
                except self.object_class.DoesNotExist:
                    raise ApiObjectNotFound()
            else:
                if ApiSettings.DEBUG:
                    print(type(self.request_filter))
                raise ApiContentFilterWrongFormat()

        else:
            raise ApiContentFilterNotProvided()

        if not obj:
            raise self.object_class.DoesNotExist()

        return obj

    def hook_before_serializer(self, obj):
        return

    def handler(self):
        obj = self.get_queryset()

        if self.check_object_permission and not obj.check_view_perm(self.request):
            err_msg = "%s: You don't have permission to view this object" % (
                obj.__class__.__name__
            )
            raise ApiPermissionError(err_msg)

        self.hook_before_serializer(obj)

        self.context.update(
            {
                "result": self.return_serializer_class(
                    instance=obj,
                    context={
                        "request": self.request,
                        "check_field_permission": self.check_serializer_field_permission,
                        "action": "view",
                    },
                ).data
            }
        )

    def process(self):
        self.get_rest_request_content()
        self.request_filter = self.get_rest_content_filter()
        self.get_rest_content_flags()
        self.get_request_content_data()

        try:
            self.handler()
        except Exception as e:
            self.pre_handle_exception(e)

        if isinstance(self.context, HttpResponse):
            return self.context

        self.add_user_to_context()

        if self.return_serializer_class:
            self.context.update(
                {
                    "fields": self.return_serializer_class.get_accessible_fields(
                        self.request, self.check_serializer_field_permission
                    )
                    if issubclass(
                        self.return_serializer_class, ApiWrapperModelSerializer
                    )
                    else [*self.return_serializer_class.Meta.fields],
                }
            )

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


class CustomCreateView(CustomAPIView):
    renderer_classes = [JSONRenderer]

    def __init__(self, *args, **kwargs):
        self.context = ApiContext.create()
        self.request_data = {}

        super().__init__(*args, **kwargs)

    def hook_after_creation(self, obj):
        pass

    def hook_before_creation(self, tmp_obj):
        pass

    def handler(self):
        serializer = self.serializer_class(
            data=self.request_data,
            context={
                "request": self.request,
                "check_field_permission": self.check_serializer_field_permission,
                "action": "add",
            },
        )

        if not serializer.is_valid():
            self.handle_invalid_serializer(serializer)

        tmp_object = self.object_class(**serializer.validated_data)
        self.hook_before_creation(tmp_object)

        if self.check_object_permission and not tmp_object.check_add_perm(self.request):
            raise ApiPermissionError()

        tmp_object.save()

        self.hook_after_creation(tmp_object)

        self.context.update(
            {
                "result": self.return_serializer_class(
                    instance=tmp_object,
                    context={
                        "request": self.request,
                        "check_field_permission": self.check_serializer_field_permission,
                        "action": "view",
                    },
                ).data
            }
        )

    def process(self):
        if hasattr(self, "get_serializer_class"):
            self.serializer_class = self.get_serializer_class()

        self.get_rest_request_content()
        self.get_rest_content_flags()
        self.get_request_content_data()

        try:
            self.handler()
        except Exception as e:
            self.pre_handle_exception(e)

        self.add_user_to_context()

        if self.return_serializer_class:
            self.context.update(
                {
                    "fields": self.return_serializer_class.get_accessible_fields(
                        self.request, self.check_serializer_field_permission
                    )
                    if issubclass(
                        self.return_serializer_class, ApiWrapperModelSerializer
                    )
                    else [*self.return_serializer_class.Meta.fields],
                }
            )

        self.context.update(
            {
                "success": True,
            }
        )

        return self.respond(status.HTTP_201_CREATED)

    def put(self, request):
        return self.process()

    def post(self, request):
        if self.transactional:
            with transaction.atomic():
                return self.process()

        return self.process()


class CustomAddView(CustomCreateView):
    # Proxy class
    pass


class CustomUpdateView(CustomAPIView):
    renderer_classes = [JSONRenderer]

    def __init__(self, *args, **kwargs):
        self.context = ApiContext.update()
        self.request_data = {}

        super().__init__(*args, **kwargs)

    def hook_before_update(self, obj):
        pass

    def hook_after_update(self, obj):
        pass

    def handler(self):
        if "id" not in self.request_data and "pk" not in self.request_data:
            raise ApiContentDataPkNotProvided()

        pk = (
            self.request_data.get("id")
            if self.request_data.get("id")
            else self.request_data.get("pk")
        )

        try:
            object_to_update = self.object_class.objects.select_for_update().get(pk=pk)
        except NotSupportedError:
            object_to_update = self.object_class.objects.get(pk=pk)

        if not object_to_update:
            raise ApiObjectNotFound()

        if self.check_object_permission and not object_to_update.check_change_perm(
            self.request
        ):
            raise ApiPermissionError("Object permission denied.")

        self.hook_before_update(object_to_update)

        serializer = self.serializer_class(
            instance=object_to_update,
            data=self.request_data,
            partial=True,
            context={
                "request": self.request,
                "check_field_permission": self.check_serializer_field_permission,
                "action": "change",
            },
        )

        if not serializer.is_valid():
            self.handle_invalid_serializer(serializer)

        updated_object = serializer.save()

        self.hook_after_update(updated_object)

        self.context.update(
            {
                "result": self.return_serializer_class(
                    instance=updated_object,
                    context={
                        "request": self.request,
                        "check_field_permission": self.check_serializer_field_permission,
                        "action": "view",
                    },
                ).data
            }
        )

    def process(self):
        if hasattr(self, "get_serializer_class"):
            self.serializer_class = self.get_serializer_class()

        self.get_rest_request_content()
        self.get_request_content_data()
        self.get_rest_content_flags()

        try:
            self.handler()
        except Exception as e:
            self.pre_handle_exception(e)

        self.add_user_to_context()

        if self.return_serializer_class:
            self.context.update(
                {
                    "fields": self.return_serializer_class.get_accessible_fields(
                        self.request, self.check_serializer_field_permission
                    )
                    if issubclass(
                        self.return_serializer_class, ApiWrapperModelSerializer
                    )
                    else [*self.return_serializer_class.Meta.fields],
                }
            )

        self.context.update(
            {
                "success": True,
            }
        )

        return self.respond(status.HTTP_200_OK)

    def patch(self, request):
        if self.transactional:
            with transaction.atomic():
                return self.process()

        return self.process()


class CustomChangeView(CustomUpdateView):
    # Proxy class
    pass


class CustomDeleteView(CustomAPIView):
    renderer_classes = [JSONRenderer]

    def __init__(self, *args, **kwargs):
        self.context = ApiContext.remove()
        self.request_data = {}

        super().__init__(*args, **kwargs)

    def hook_before_delete(self, obj):
        pass

    def hook_after_delete(self):
        pass

    def handler(self):
        if (
            "id" not in self.request_data
            and "pk" not in self.request_data
            and "id_set" not in self.request_data
            and "pk_set" not in self.request_data
        ):
            raise ApiContentDataPkNotProvided()

        pk = (
            self.request_data.get("id")
            if self.request_data.get("id")
            else self.request_data.get("pk")
        )

        pk_set = (
            self.request_data.get("id_set", [])
            if self.request_data.get("id_set", [])
            else self.request_data.get("pk_set", [])
        )

        if len(pk_set) > 0:
            for _pk in pk_set:
                obj_to_delete = self.object_class.objects.get(pk=_pk)

                if not obj_to_delete:
                    raise ApiObjectNotFound()

                if not obj_to_delete.check_delete_perm(self.request):
                    continue

                self.hook_before_delete(obj_to_delete)
                obj_to_delete.delete()
                self.hook_after_delete()

        elif pk:
            obj_to_delete = self.object_class.objects.get(pk=pk)

            if not obj_to_delete:
                raise ApiObjectNotFound()

            if not obj_to_delete.check_delete_perm(self.request):
                raise ApiPermissionError("Object permission denied.")

            self.hook_before_delete(obj_to_delete)
            obj_to_delete.delete()
            self.hook_after_delete()

    def process(self):
        self.get_rest_request_content()
        self.get_request_content_data()
        self.get_rest_content_flags()

        try:
            self.handler()
        except ProtectedError as e:
            raise ApiDeleteProtectedError()
        except IntegrityError as e:
            raise ApiDeleteIntegrityError()
        except Exception as e:
            self.pre_handle_exception(e)

        self.add_user_to_context()

        self.context.update({"status": 200, "success": True})

        return self.respond(status.HTTP_200_OK)

    def post(self, request):
        if self.transactional:
            with transaction.atomic():
                return self.process()

        return self.process()


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
    throttle_classes = [BasicPasswordAuthThrottle]

    model = None
    model_serializer = None

    def __init__(self, *args, **kwargs):
        self.context = ApiContext.get()
        self.request_data = {}

        super().__init__(*args, **kwargs)

    def _auth_method(self, username, password):
        raise NotImplemented()

    def hook_context(self):
        pass

    def process(self):
        if hasattr(self, "get_serializer_class"):
            self.serializer_class = self.get_serializer_class()

        self.get_rest_request_content()
        self.get_request_content_data()
        self.get_rest_content_flags()

        if "username" not in self.request_data or "password" not in self.request_data:
            raise ApiAuthUsernameOrPasswordNotProvided()

        user, token = self._auth_method(
            username=self.request_data["username"],
            password=self.request_data["password"],
        )

        self.request.user = user

        try:
            # Delete expired tokens
            self.model.delete_expired(user)
        except:
            pass

        self.context.update(
            {
                "success": True,
                "status": 200,
                "results": {
                    "user": self.serializer_class(
                        instance=user,
                        context={
                            "request": self.request,
                            "check_field_permission": self.check_serializer_field_permission,
                            "action": "view",
                        },
                    ).data,
                    "token": self.model_serializer(
                        instance=token,
                        context={
                            "request": self.request,
                            "check_field_permission": self.check_serializer_field_permission,
                            "action": "view",
                        },
                    ).data,
                },
            }
        )

        self.hook_context()

        return self.respond(status.HTTP_200_OK)

    def post(self, request):
        return self.process()


class BasicTokenRefresh(CustomAPIView):
    authentication_classes = []
    permission_classes = []
    throttle_classes = [BasicTokenRefreshThrottle]

    model = None
    model_serializer = None

    def __init__(self):
        self.context = ApiContext.get()
        self.request_data = {}

        super().__init__()

    def _auth_method(self, username, password):
        raise NotImplemented()

    def hook_context(self, context):
        pass

    def handler(self):
        refresh_token = self.request_data.get("refresh_token")

        if not refresh_token:
            raise ApiValueError("refresh_token not provided")

        try:
            token = self.model.objects.get(refresh_token=refresh_token)
        except self.model.DoesNotExist:
            raise ApiExpiringRefreshTokenNotFound()

        if token.is_refresh_token_expired:
            token.delete()
            raise ApiExpiringRefreshTokenIsExpired()

        if token.is_access_token_expired:
            token.regenerate()

        self.context.update(
            {
                "result": {
                    "token": self.model_serializer(
                        instance=token,
                        context={
                            "request": self.request,
                            "check_field_permission": self.check_serializer_field_permission,
                            "action": "view",
                        },
                    ).data
                }
            }
        )

        self.hook_context()

    def process(self):
        if hasattr(self, "get_serializer_class"):
            self.serializer_class = self.get_serializer_class()

        self.get_rest_request_content()
        self.get_request_content_data()
        self.get_rest_content_flags()

        self.handler()

        self.context.update({"success": True})

        return self.respond(status.HTTP_200_OK)

    def post(self, request):
        return self.process()


class CustomFileUploadView(CustomAPIView):
    parser_classes = [MultiPartParser, FormParser]

    def __init__(self, *args, **kwargs):
        self.context = ApiContext.create()
        self.request_data = {}
        super().__init__(*args, **kwargs)

    def hook_file_instance(self, obj, file):
        pass

    def handler(self):
        if "id" not in self.request_data and "pk" not in self.request_data:
            raise ApiContentDataPkNotProvided()

        pk = (
            self.request_data.get("id")
            if self.request_data.get("id")
            else self.request_data.get("pk")
        )

        try:
            model_instance = self.object_class.objects.select_for_update().get(pk=pk)
        except NotSupportedError:
            model_instance = self.object_class.objects.get(pk=pk)

        if not model_instance.check_change_perm(self.request):
            raise ApiPermissionError("Object permission denied.")

        uploaded_file = self.request.FILES.get("uploaded_file")

        if not uploaded_file:
            raise ApiContentDataFileNotProvided()

        self.hook_file_instance(model_instance, uploaded_file)

        model_instance.save()

        self.context.update(
            {
                "success": True,
                "result": self.return_serializer_class(
                    instance=model_instance,
                    context={
                        "request": self.request,
                        "check_field_permission": self.check_serializer_field_permission,
                        "action": "view",
                    },
                ).data,
            }
        )

    def process(self):
        try:
            self.get_rest_request_content()
            self.get_request_content_data()

            if isinstance(self.request_data, str):
                self.request_data = json.loads(self.request_data)

            self.request_data = {**self.request_data, **self.request.FILES}
            self.get_rest_content_flags()
            self.handler()
        except Exception as e:
            self.pre_handle_exception(e)

        return self.respond(status.HTTP_201_CREATED)

    def post(self, request):
        if self.transactional:
            with transaction.atomic():
                return self.process()

        return self.process()


class CustomFileDownloadView(CustomAPIView):
    def __init__(self, *args, **kwargs):
        self.request_data = {}
        super().__init__(*args, **kwargs)

    def get_file(self, obj):
        # This method can be overridden to perform some action on the file instance before downloading
        raise NotImplementedError()

    def handler(self):
        if "id" not in self.request_data and "pk" not in self.request_data:
            raise ApiContentDataPkNotProvided()

        pk = (
            self.request_data.get("id")
            if self.request_data.get("id")
            else self.request_data.get("pk")
        )

        try:
            model_instance = self.object_class.objects.select_for_update().get(pk=pk)
        except NotSupportedError:
            model_instance = self.object_class.objects.get(pk=pk)

        if not model_instance.check_change_perm(self.request):
            raise ApiPermissionError("Object permission denied.")

        file_instance = self.get_file(model_instance)

        if not file_instance:
            raise ApiContentDataFileNotProvided()

        return FileResponse(
            file_instance, as_attachment=True, filename=file_instance.name
        )

    def process(self):
        try:
            self.get_rest_request_content()
            self.get_request_content_data()

            return self.handler()

        except Exception as e:
            self.pre_handle_exception(e)
            return self.respond(status.HTTP_400_BAD_REQUEST)

    def post(self, request):
        if self.transactional:
            with transaction.atomic():
                return self.process()

        return self.process()
