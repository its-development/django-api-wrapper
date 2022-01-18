from api.exceptions import *


class ApiPaginator:
    offset: int = 0
    limit: int = 0
    page: int = 0
    total: int = 0

    def __init__(self, request_pagination: dict):
        self.get_pagination_data(request_pagination)

    def get_pagination_data(self, request_pagination: dict = {}):
        offset = request_pagination.get('offset')
        limit = request_pagination.get('limit')
        page = request_pagination.get('page')

        self.offset = int(offset) if offset else 0
        self.limit = int(limit) if limit else 25
        self.page = int(page) if page else 0

        if self.limit is None:
            raise ApiValueError("ApiPaginator did not got a limit.")

        if self.page is not None:
            self.offset = self.page * self.limit

    def paginate(self, objects=None, request=None, check_object_permission: bool = True):
        result_set = []

        if not request:
            raise ApiPaginationError('Insufficient data provided.')

        if isinstance(objects, list):
            self.total = len(objects)
        else:
            self.total = objects.count()

        if self.total == 0:
            return []

        if self.offset >= self.total:
            raise ApiValueError('Offset bigger total count.')

        if self.limit == -1:
            self.limit = self.total

        for i, obj in enumerate(objects[self.offset:]):
            if i >= self.limit:
                break

            if check_object_permission:
                if not obj.check_view_perm(request):
                    self.limit += 1

                else:
                    result_set.append(obj)

            else:
                result_set.append(obj)

        return result_set

    def update_context(self, context):
        context.update({
            'pagination': {
                'total': self.total,
                'limit': self.limit,
                'page': int(self.offset / self.limit),
                'pages': int(self.total / self.limit),
                'offset': self.offset
            }
        })
