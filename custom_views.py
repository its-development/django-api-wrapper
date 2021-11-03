from django.utils import timezone

from django.http import HttpResponse
from django.db.models import Q

from rest_framework.renderers import JSONRenderer
from rest_framework.views import APIView
from rest_framework.response import Response

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

    def __init__(self, *args, **kwargs):
        self.request_content = {}
        self.request_data = {}

        super().__init__(*args, **kwargs)

    def add_user_to_context(self, ctx, request):
        if not request.user:
            return

        if not self.user_serializer:
            return

        ctx.update({
            'user': self.user_serializer(instance=request.user).data
        })

    @staticmethod
    def get_rest_request_content(request):
        """

        :param request:
        :return request.data:
        """
        content = {}

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

    def get_request_content_data(self):
        """

        :return self.request_content.data:
        """

        if 'data' not in self.request_content:
            raise ApiContentDataNotProvided()

        return self.request_content.get('data')

    def get_rest_content_filter(self):
        """

        :return:
        """
        request_filter = self.request_content.get('filter')

        if not isinstance(request_filter, list) and not isinstance(request_filter, dict):
            if ApiSettings.DEBUG:
                print(type(request_filter))
            raise ApiContentFilterWrongFormat()

        if self.enhanced_filters is True and isinstance(request_filter, list):
            request_filter = self.generate_enhanced_filters(request_filter)

        return request_filter

    @staticmethod
    def generate_enhanced_filters(request_filter=None):
        """
        :param request_filter:
        :return generated filter expression:
        """
        generated_filter = []

        for i, re_filter in enumerate(request_filter):
            op = '&'
            open_group = ''
            close_group = ''

            #  Remove any characters not allowed in variables
            for key in re_filter['expr']:
                if isinstance(re_filter['expr'][key], str):
                    clean_val = str(re.sub(r'([^A-z0-9\- ]*)', '', str(re_filter['expr'][key])))

                else:
                    clean_val = re_filter['expr'][key]

                clean_key = re.sub(r'([^A-z0-9\-]*)', '', key)
                break

            if 'open' in re_filter:
                open_group = '('

            elif 'close' in re_filter:
                close_group = ')'

            if i > 0:

                if 'operator' in re_filter:
                    if re_filter['operator'] == 'or':
                        op = '|'

                    elif re_filter['operator'] == 'and':
                        op = '&'

                    else:
                        raise ApiValueError('unknown operator')

                    generated_filter.append(op)
                    generated_filter.append("%sQ(%s='%s')%s" % (open_group, clean_key, clean_val, close_group))

                else:
                    raise ApiValueError('Filter operator not provided')

            else:
                generated_filter.append("%sQ(%s='%s')%s" % (open_group, clean_key, clean_val, close_group))

        generated_filter = ' '.join(generated_filter)

        return ApiHelpers.eval_expr(generated_filter) if generated_filter else None

    def get_rest_content_order(self):
        """
        :return self.request_content.filter:
        """

        if 'order' not in self.request_content:
            raise ApiContentOrderNotProvided()

        return self.request_content.get('order')

    def get_rest_content_pagination(self):

        if 'pagination' not in self.request_content:
            raise ApiContentPaginationNotProvided()

        return self.request_content.get('pagination')


class CustomListView(CustomAPIView):
    renderer_classes = [JSONRenderer]
    check_object_permission = True
    distinct_query = False

    def __init__(self, *args, **kwargs):
        self.request_filter = {}
        self.request_pagination = {}
        self.request_order = []

        super().__init__(*args, **kwargs)

    def handler(self, request, context):

        if self.request_filter:
            if isinstance(self.request_filter, dict):
                objects = self.object_class.objects.filter(**self.request_filter)
            elif isinstance(self.request_filter, Q):
                objects = self.object_class.objects.filter(self.request_filter)
            else:
                if ApiSettings.DEBUG:
                    print(type(self.request_filter))
                raise ApiValueError('Bad filter type')

            if self.distinct_query:
                objects = objects.distinct()

            objects = objects.order_by(*self.request_order)

        else:
            objects = self.object_class.objects.all().order_by(*self.request_order)

        paginator = ApiPaginator(self.request_pagination)

        result_set = paginator.paginate(objects=objects, request=request,
                                        check_object_permission=self.check_object_permission)

        paginator.update_context(context)

        result_set = [self.return_serializer_class(instance=result).data for result in result_set]

        context.update({
            'results': result_set
        })

        return request, context

    def process(self, request):
        context = ApiContext.list()

        self.request_content = self.get_rest_request_content(request)
        self.request_filter = self.get_rest_content_filter()
        self.request_pagination = self.get_rest_content_pagination()
        self.request_order = self.get_rest_content_order()

        request, context = self.handler(request, context)

        self.add_user_to_context(context, request)

        context.update(
            {
                'success': True,
            }
        )

        return Response(
            ApiHelpers.encrypt_context(context)
            if self.request_content.get('encrypt') is True
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

        if 'id' not in self.request_data and 'pk' not in self.request_data:
            raise ApiContentDataPkNotProvided()

        obj = self.object_class.objects.get(**self.request_data)

        if not obj.check_view_perm(request):
            raise ApiPermissionError('Object permission denied.')

        context.update(
            {
                'result': self.return_serializer_class(obj).data
            }
        )

        return request, context

    def process(self, request):
        context = ApiContext.list()

        self.request_content = self.get_rest_request_content(request)
        self.request_data = self.get_request_content_data()

        request, context = self.handler(request, context)

        self.add_user_to_context(context, request)

        context.update(
            {
                'success': True,
            }
        )

        return Response(
            ApiHelpers.encrypt_context(context)
            if self.request_content.get('encrypt') is True
            else context,
        )

    def post(self, request):
        return self.process(request)


class CustomCreateView(CustomAPIView):
    renderer_classes = [JSONRenderer]

    def __init__(self, *args, **kwargs):
        self.request_data = {}

        super().__init__(*args, **kwargs)

    def handler(self, request, context):
        serializer = self.serializer_class(data=self.request_data)

        if not serializer.is_valid():
            if ApiSettings.DEBUG:
                print(serializer.errors)
            raise ApiSerializerInvalid()

        created_object = serializer.save()

        context.update(
            {
                'result': self.return_serializer_class(instance=created_object).data
            }
        )

        return request, context

    def process(self, request):
        context = ApiContext.create()

        self.request_content = self.get_rest_request_content(request)
        self.request_data = self.get_request_content_data()

        request, context = self.handler(request, context)

        self.add_user_to_context(context, request)

        context.update({
            'success': True
        })

        return Response(
            ApiHelpers.encrypt_context(context)
            if self.request_content.get('encrypt') is True
            else context,
        )

    def put(self, request):
        return self.process(request)

    def post(self, request):
        return self.process(request)


class CustomUpdateView(CustomAPIView):
    renderer_classes = [JSONRenderer]

    def __init__(self, *args, **kwargs):
        self.request_data = {}

        super().__init__(*args, **kwargs)

    def handler(self, request, context):

        if 'pk' not in self.request_data:
            raise ApiContentDataPkNotProvided()

        object_to_update = self.object_class.objects.get(pk=self.request_data['pk'])

        if not object_to_update:
            raise ApiObjectNotFound()

        if not object_to_update.check_change_perm(request):
            raise ApiPermissionError('Object permission denied.')

        serializer = self.serializer_class(instance=object_to_update, data=self.request_data, partial=True)

        if not serializer.is_valid():
            if ApiSettings.DEBUG:
                print(serializer.errors)
            raise ApiSerializerInvalid()

        updated_object = serializer.save()

        context.update(
            {
                'result': self.return_serializer_class(instance=updated_object).data
            }
        )

        return request, context

    def process(self, request):
        context = ApiContext.update()

        self.request_content = self.get_rest_request_content(request)
        self.request_data = self.get_request_content_data()

        request, context = self.handler(request, context)

        self.add_user_to_context(context, request)

        context.update({
            'success': True
        })

        return Response(
            ApiHelpers.encrypt_context(context)
            if self.request_content.get('encrypt') is True
            else context,
        )

    def patch(self, request):
        return self.process(request)


class CustomDeleteView(CustomAPIView):
    renderer_classes = [JSONRenderer]

    def __init__(self, *args, **kwargs):
        self.request_data = {}

        super().__init__(*args, **kwargs)

    def handler(self, request, context):

        if 'pk' not in self.request_data:
            raise ApiContentDataPkNotProvided()

        obj_to_delete = self.object_class.objects.get(pk=self.request_data['pk'])

        if not obj_to_delete:
            raise ApiObjectNotFound()

        if not obj_to_delete.check_delete_perm(request):
            raise ApiPermissionError('Object permission denied.')

        obj_to_delete.delete()

        return request, context

    def process(self, request):
        context = ApiContext.remove()

        self.request_content = self.get_rest_request_content(request)
        self.request_data = self.get_request_content_data()

        request, context = self.handler(request, context)

        self.add_user_to_context(context, request)

        context.update({
            'success': True
        })

        return Response(
            ApiHelpers.encrypt_context(context)
            if self.request_content.get('encrypt') is True
            else context,
        )

    def post(self, request):
        return self.process(request)


class CustomExportView(CustomAPIView):
    renderer_classes = [JSONRenderer]

    def post(self, request):
        request_content = ApiHelpers.get_rest_request_content(request)
        request_data = ApiHelpers.get_request_content_data(request_content)
        request_filter = ApiHelpers.get_rest_content_filter(request_content)

        file_type = request_data.get('file_type')

        if not file_type:
            raise ApiValueError('file_type not provided.')

        fields = request_data.get('fields')

        if not fields:
            fields = [field.name for field in self.object_class._meta.get_fields()]

        fields_translation = request_data.get('header')

        if not fields_translation:
            fields_translation = fields

        if fields_translation and len(fields_translation) != len(fields):
            raise ApiValueError('Header count is unequal to fields count.')

        header = {}

        for i, field in enumerate(fields):
            header.update({
                str(field): str(fields_translation[i])
            })

        collection = self.object_class.objects.filter(**request_filter)

        for obj in collection:
            if not obj.check_export_perm(request):
                collection = collection.exclude(pk=obj.pk)

        if file_type == "csv":
            delimiter = request_data.get('delimiter')

            if not delimiter:
                raise ApiValueError('delimiter not provided')

            response = HttpResponse(content_type="text/csv")
            response['Content-Disposition'] = 'attachment; filename="export.csv"'

            writer = csv.DictWriter(response, fieldnames=header, delimiter=delimiter)

            if header:
                writer.writerow(header)

            else:
                writer.writeheader(fields)

            for row in collection:
                row_data = {}
                for field in fields:
                    row_data[field] = (ApiHelpers.rgetattr(row, field))

                writer.writerow(row_data)

        else:
            raise ApiError('No matching file_type.')

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

        request_content = ApiHelpers.get_rest_request_content(request)
        request_data = ApiHelpers.get_request_content_data(request_content)

        if 'username' not in request_data or 'password' not in request_data:
            raise ApiAuthUsernameOrPasswordNotProvided()

        user = self._auth_method(username=request_data['username'], password=request_data['password'])
        user_ip = ApiHelpers.get_client_ip(request)
        user_user_agent = ApiHelpers.get_client_user_agent(request)

        if not user:
            raise ApiAuthFailed()

        token = self.model.objects.create(user=user, ip_addr=user_ip, user_agent=user_user_agent)

        context.update(
            {
                'success': True,
                'results': {
                    'user': self.serializer_class(instance=user).data,
                    'token': self.model_serializer(instance=token).data
                }
            }
        )

        return Response(context, )

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
        import django.utils.timezone

        refresh_token = self.request_data.get('refresh_token')

        if not refresh_token:
            raise ApiValueError('refresh_token not provided')

        try:
            token = self.model.objects.get(refresh_token=refresh_token)
        except self.model.DoesNotExist:
            raise ApiValueError('refresh_token_does_not_exist')

        if token.is_refresh_token_expired:
            token.delete()
            raise ApiValueError('refresh_token expired')

        if token.is_access_token_expired:
            if token.updated_at + timezone.timedelta(seconds=5) < timezone.now():
                token.regenerate()

        context.update(
            {
                'result': {
                    'token': self.model_serializer(instance=token).data
                }
            }
        )

        return request, context

    def process(self, request):
        context = ApiContext.get()

        self.request_content = self.get_rest_request_content(request)
        self.request_data = self.get_request_content_data()

        request, context = self.handler(request, context)

        context.update({
            'success': True
        })

        return Response(
            ApiHelpers.encrypt_context(context)
            if self.request_content.get('encrypt') is True
            else context,
        )

    def post(self, request):
        return self.process(request)
