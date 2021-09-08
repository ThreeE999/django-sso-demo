import json
import logging
from collections import ChainMap

from django.core.serializers.json import DjangoJSONEncoder
from django.http import HttpResponse, JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View

logger = logging.getLogger(__name__)


@method_decorator(csrf_exempt, name='dispatch')
class BaseAPIView(View):
    """
    Json格式返回基类.支持所有http请求

    Usage:

        class C(JsonpView):
            def jsonp(self, request, ...):
                ...

    'get' 已经废弃. 请使用 'json' 代替 'get' .
    """

    need_login: bool = False
    user = None
    DATA: ChainMap = ChainMap()

    def dispatch(self, request, *args, **kwargs):
        self.DATA = ChainMap(self.request.GET, self.request.POST)
        if request.user.is_authenticated:
            self.user = request.user
        if self.need_login:
            if self.user:
                # 已经登录
                res = super().dispatch(request, *args, **kwargs)
            else:
                # 未登录
                res = {'code': 1, 'msg': '用户未登录，禁止操作!', 'data': None}
        else:
            res = super().dispatch(request, *args, **kwargs)

        if isinstance(res, HttpResponse):
            return res
        elif isinstance(res, tuple):
            data = self._tuple2dict(res)
            if 'callback' in request.GET:
                # a jsonp response!
                if not isinstance(data, str):
                    data = json.dumps(data, allow_nan=False, cls=DjangoJSONEncoder)
                data = '%s(%s);' % (request.GET['callback'], data)
                return HttpResponse(data, "text/javascript;charset=utf-8")
            else:
                return JsonResponse(data, json_dumps_params={'allow_nan': False})
        elif isinstance(res, dict):
            return JsonResponse(res, json_dumps_params={'allow_nan': False})
        else:
            return JsonResponse(
                dict(code=499, msg='un support request', data=None),
                json_dumps_params={'allow_nan': False}
            )

    @staticmethod
    def _tuple2dict(param: tuple) -> dict:
        """ 故意不对value做有效性判断，请开发者自己注意！！
        :param param: tuple格式数据。
        :return:
        """
        ret: dict = {'code': 0, 'msg': '', 'data': ''}
        for index, value in enumerate(param):
            if index == 0:
                ret['code'] = int(value)
            elif index == 1:
                ret['msg'] = str(value)
            elif index == 2:
                ret['data'] = value

        return ret
