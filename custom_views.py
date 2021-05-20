from django.http import HttpResponse
from django.db.models import Q

from rest_framework.renderers import JSONRenderer
from rest_framework.views import APIView
from rest_framework.response import Response

from api.auth_token.models import ExpiringToken
from api.auth_token.authentication import ExpiringTokenAuthentication

from .helpers import ApiHelpers
from .pagination import ApiPaginator
from .context import ApiContext
from .exceptions import *

import csv
import re


class CustomAPIView(APIView):
    object_class = None
    return_serializer_class = None
    serializer_class = None
    enhanced_filters = False

    def __init__(self, *args, **kwargs):
        self.request_content = {}

        super().__init__(*args, **kwargs)

    @staticmethod
    def get_rest_request_content(request):
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

        if 'data' not in self.request_content:
            raise ApiContentDataNotProvided()

        return self.request_content.get('data')

    def get_rest_content_filter(self):

        request_filter = self.request_content.get('filter')

        if not request_filter:
            raise ApiContentFilterNotProvided()

        if self.enhanced_filters is True:
            request_filter = self.generate_enhanced_filters(request_filter)

        return request_filter

    @staticmethod
    def generate_enhanced_filters(request_filter=None):
        """
        TODO: Check for security issues
        """
        generated_filter = []

        for i, re_filter in enumerate(request_filter):
            op = '&'

            #  Remove any characters not allowed in variables
            for key in re_filter['expr']:
                clean_val = str(re.sub(r'([^A-z]*)', '', re_filter['expr'][key]))
                clean_key = re.sub(r'([^A-z]*)', '', key)
                break

            if i > 0:

                if 'operator' in re_filter:
                    if re_filter['operator'] == 'or':
                        op = '|'

                    elif re_filter['operator'] == 'and':
                        op = '&'

                    else:
                        raise ApiValueError('unknown operator')

                    generated_filter.append(op)
                    generated_filter.append("Q(%s='%s')" % (clean_key, clean_val))

                else:
                    raise ApiValueError('Filter operator not provided')

            else:
                generated_filter.append("Q(%s='%s')" % (clean_key, clean_val))

        generated_filter = ' '.join(generated_filter)

        return eval(generated_filter)

    def get_rest_content_order(self):

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

        if 'pk' not in self.request_data:
            raise ApiContentDataPkNotProvided()

        obj = self.object_class.objects.get(**self.request_data)

        if not obj.check_view_perm(request):
            raise ApiPermissionError('Object permission denied.')

        context.update(
            {
                'success': True,
                'result': self.return_serializer_class(obj).data
            }
        )

        return request, context

    def process(self, request):
        context = ApiContext.list()

        self.request_content = self.get_rest_request_content(request)
        self.request_data = self.get_request_content_data()

        request, context = self.handler(request, context)

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
            raise ApiSerializerInvalid()

        created_object = serializer.save()

        context.update(
            {
                'success': True,
                'result': self.return_serializer_class(instance=created_object).data
            }
        )

        return request, context

    def process(self, request):
        context = ApiContext.create()

        self.request_content = self.get_rest_request_content(request)
        self.request_data = self.get_request_content_data()

        request, context = self.handler(request, context)

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
            raise ApiSerializerInvalid()

        updated_object = serializer.save()

        context.update(
            {
                'success': True,
                'result': self.return_serializer_class(instance=updated_object).data
            }
        )

        return request, context

    def process(self, request):
        context = ApiContext.update()

        self.request_content = self.get_rest_request_content(request)
        self.request_data = self.get_request_content_data()

        request, context = self.handler(request, context)

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

        context.update(
            {
                'success': True
            }
        )

        return request, context

    def process(self, request):
        context = ApiContext.remove()

        self.request_content = self.get_rest_request_content(request)
        self.request_data = self.get_request_content_data()

        request, context = self.handler(request, context)

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

            header = fields
            writer = csv.DictWriter(response, fieldnames=header, delimiter=delimiter)

            writer.writeheader()

            for row in collection:
                row_data = {}
                for field in header:
                    row_data[field] = (getattr(row, field))

                writer.writerow(row_data)

        else:
            raise ApiError('No matching file_type.')

        return response


class BasicPasswordAuth(CustomAPIView):
    authentication_classes = []
    permission_classes = []

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

        if not user:
            raise ApiAuthFailed()

        token, action = ExpiringToken.objects.get_or_create(user=user)

        token = ExpiringTokenAuthentication.regenerate(old_token=token, user=user, ip_addr=user_ip)

        context.update(
            {
                'success': True,
                'results': {
                    'user': self.serializer_class(instance=user).data,
                    'token': token.key
                }
            }
        )

        return Response(context, )

    def post(self, request):
        return self.process(request)
