import base64
import json
import logging
from json import JSONDecodeError
from typing import Dict, Tuple

import requests
from django.conf import settings
from django.contrib.auth import logout
from django.contrib.auth.models import Permission
from django.shortcuts import redirect
# 同步密钥
from django.urls import reverse

from base_view import BaseAPIView
from users.models import UserPermission, SSOClientUser

SYNC_SECRET = settings.SECRET_KEY

logger = logging.getLogger(__name__)


def index(request):
    if request.user.is_authenticated:
        return redirect('smeeting:index')
    return redirect('users:login')


def logout_view(request):
    logout(request)
    return redirect('/')


#
# def reg(request):
#     return HttpResponse(consumer_register())


def consumer_register():
    """
    往sso 服务器注册当前client，
    post  回调函数，权限列表，secret
    :return:
    """
    ps = [dict(id=p.pk, name=p.name, content_type_id=p.content_type_id, codename=p.codename) for p in
          Permission.objects.all()]

    secret = base64.b64encode(settings.SECRET_KEY.encode('ascii'))
    secret = secret.decode('ascii')
    data: Dict = {
        'permissions': ps,
        'perm_sync_url': settings.SSO_CLIENT + reverse('users:sync_url', args=(secret,)),
        'sso_public_key': settings.SSO_PUBLIC_KEY,
        'action': 'register'
    }
    if settings.SSO_SERVER[-1] != '/':
        url = f'{settings.SSO_SERVER}/register'
    else:
        url = f'{settings.SSO_SERVER}register'

    r = requests.post(url, timeout=(5, 5), json=data)
    if r.status_code != 200:
        logger.error(f'注册失败,{r.text}')
        return 20, f'注册失败,{r.text}', None
    else:
        logger.info('注册成功！')

    try:
        info = json.loads(r.text)
    except (json.JSONDecodeError, ValueError):
        logger.warning('返回数据，json解析失败。')
        return r.text
    if not isinstance(info, dict) or 'data' not in info:
        return r.text
    return multiple_sync(info['data'])


def multiple_sync(info) -> Tuple[int, str, any]:
    """
    多条数据同步协议解析, 协议参考
    {
        "type": "multiple", # 必须
        "users": [   # 必须
            {
                "is_superuser": false, # 指明该用户缺省拥有所有权限。
                "is_staff": false, # 指明用户是否可以登录到这个管理站点。
                "is_active": true, # 指明用户是否被认为是活跃的。以反选代替删除帐号。
                "username": "admin",
                "permissions": [1,3]
            }
        ]
    }
    :param info:
    :return:
    """
    if info.get('type', None) not in ('single', 'multiple'):
        logger.warning('type数据错误!')
        return 90, 'type数据错误!', None
    if info.get('type', None) == 'single':
        return single_sync(info)
    users = info.get('users', [])
    if len(users) == 0 or not isinstance(users, list):
        logger.warning('multiple模式下，users数据为空或无效!')
        return 91, 'multiple模式下，users数据为空或无效!', None
    [single_sync(u) for u in users]
    return 200, 'success', None


def single_sync(info):
    """
    单条数据同步,协议参考
    {
        "is_superuser": false, # 可选
        "is_staff": false, # 可选
        "is_active": true,  # 可选
        "username": "admin",  # 必须
        "permissions": [1,3]  # 必须
    }
    :param info:
    :return:
    """
    if 'permissions' not in info or 'username' not in info:
        return 100, '参数错误！', None
    username = info['username']
    if len(username) == 0:
        return 110, 'username参数错误', None
    try:
        user = SSOClientUser.objects.get(username=username)
        change = False
        if 'is_superuser' in info:
            change, user.is_superuser = True, info['is_superuser']
        if 'is_staff' in info:
            change, user.is_staff = True, info['is_staff']
        if 'is_active' in info:
            change, user.is_active = True, info['is_active']
        if change:
            user.save()
    except (SSOClientUser.DoesNotExist, SSOClientUser.MultipleObjectsReturned):
        return 111, 'username参数错误, 用户不存在！', None
    user_permission_data = info['permissions']
    if not isinstance(user_permission_data, list) or len(user_permission_data) == 0:
        return 200, 'permissions为空，没有权限数据！', None

    exist_permission = UserPermission.objects.filter(user_id=user.pk)
    if exist_permission.exists():
        exist_permission.delete()  # 全删
    t = [UserPermission(user_id=user.pk, permission_id=pid) for pid in user_permission_data]
    UserPermission.objects.bulk_create(t)
    return 200, f'同步{len(user_permission_data)}条数据!', None


class SyncView(BaseAPIView):
    """
    与SSO server同步 Permission、 UserPermission接口。
    """

    def post(self, request, *args, **kwargs):
        secret = kwargs.get('secret')
        if not secret:
            return 90, 'secret error!'
        secret = base64.b64decode(secret).decode('ascii')
        if secret != settings.SECRET_KEY:
            return 91, 'secret error!'

        try:
            info = json.loads(request.body)
        except JSONDecodeError:
            return 100, 'json数据格式不正确!', None

        return multiple_sync(info)
