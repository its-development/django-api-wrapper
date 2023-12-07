from django.db.models import QuerySet

from api.exceptions import *
from api.helpers import ApiHelpers


class ApiPaginator:
    offset: int = 0
    limit: int = 0
    page: int = 0
    total: int = 0
    distinct: bool = False

    def __init__(self, request_pagination: dict, distinct: bool = False):
        self.distinct = distinct
        self.get_pagination_data(request_pagination)

    def get_pagination_data(self, request_pagination: dict = {}):
        offset = request_pagination.get("offset")
        limit = request_pagination.get("limit")
        page = request_pagination.get("page")

        self.limit = int(limit) if limit else 25

        if self.limit is None:
            raise ApiValueError("ApiPaginator: limit not provided.")

        if page:
            self.offset = int(page) * self.limit

        else:
            self.offset = int(offset) if offset else 0

    def setup(self, objects):
        if isinstance(objects, QuerySet):
            result_set = set() if self.distinct else list()
            self.total = objects.count()
        elif isinstance(objects, (list, set)):
            result_set = type(objects)() if not self.distinct else set()
            self.total = len(objects)
        else:
            raise ApiValueError()

        if self.distinct:
            result_set = set()

        return result_set

    def paginate(
        self,
        objects: list | set | QuerySet,
        request,
        check_object_permission: bool = True,
    ):
        if not check_object_permission:
            self.total = objects.count()
            return objects[self.offset : self.offset + self.limit]

        result_set = self.setup(objects)

        if self.total == 0:
            return result_set

        if self.offset >= self.total:
            raise ApiValueError("ApiPaginator: offset out of range.")

        if self.limit == -1:
            self.limit = self.total

        for i, obj in enumerate(objects[self.offset :]):
            if i >= self.limit:
                break

            if check_object_permission:
                if not obj.check_view_perm(request):
                    self.limit += 1
                    self.total -= 1
                    continue
                else:
                    if isinstance(result_set, list):
                        result_set.append(obj)
                    elif isinstance(result_set, set):
                        added = ApiHelpers.add_set(result_set, obj)
                        if not added:
                            self.limit += 1
                            self.total -= 1
                            continue
            else:
                if isinstance(result_set, list):
                    result_set.append(obj)
                elif isinstance(result_set, set):
                    added = ApiHelpers.add_set(result_set, obj)
                    if not added:
                        self.limit += 1
                        self.total -= 1
                        continue

        return result_set

    def update_context(self, context):
        context.update(
            {
                "pagination": {
                    "total": self.total,
                    "limit": self.limit,
                    "page": int(self.offset / self.limit),
                    "pages": int(self.total / self.limit),
                    "offset": self.offset,
                }
            }
        )
