# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import datetime
# python 3
# noinspection PyCompatibility
import json
import logging
from collections import defaultdict
from typing import List, Dict
from urllib.parse import urlparse, urlunparse, urlencode

import django
from django.conf import settings
from django.conf.urls import url
from django.db import models
from django.http import (HttpResponseForbidden, HttpResponseBadRequest, HttpResponseRedirect, QueryDict, HttpResponse)
from django.urls import reverse, path
from django.utils import timezone
from django.views.generic.base import View
from itsdangerous import URLSafeTimedSerializer
from webservices.models import Provider
from webservices.sync import provider_for_django

from base_view import BaseAPIView
from .models import Token, Consumer, ConsumerPermissions, UserConsumerPermission

DJANGO_GTE_10 = django.VERSION >= (1, 10)

logger = logging.getLogger(__name__)


def user_is_authenticated(user):
    if DJANGO_GTE_10:
        return user.is_authenticated
    return user.is_authenticated()


class BaseProvider(Provider):
    max_age = 5

    def __init__(self, server):
        self.server = server

    def get_private_key(self, public_key):
        try:
            self.consumer = Consumer.objects.get(public_key=public_key)
        except Consumer.DoesNotExist:
            return None
        return self.consumer.private_key


class RequestTokenProvider(BaseProvider):
    def provide(self, data):
        redirect_to = data['redirect_to']
        token = Token.objects.create(consumer=self.consumer, redirect_to=redirect_to)
        return {'request_token': token.request_token}


class AuthorizeView(View):
    """
    The client get's redirected to this view with the `request_token` obtained
    by the Request Token Request by the client application beforehand.

    This view checks if the user is logged in on the server application and if
    that user has the necessary rights.

    If the user is not logged in, the user is prompted to log in.
    """
    server = None

    def get(self, request):
        request_token = request.GET.get('token', None)
        if not request_token:
            return self.missing_token_argument()
        try:
            self.token = Token.objects.select_related('consumer').get(request_token=request_token)
        except Token.DoesNotExist:
            return self.token_not_found()
        if not self.check_token_timeout():
            return self.token_timeout()
        self.token.refresh()
        if user_is_authenticated(request.user):
            return self.handle_authenticated_user()
        else:
            return self.handle_unauthenticated_user()

    def missing_token_argument(self):
        return HttpResponseBadRequest('Token missing')

    def token_not_found(self):
        return HttpResponseForbidden('Token not found')

    def token_timeout(self):
        return HttpResponseForbidden('Token timed out')

    def check_token_timeout(self):
        delta = timezone.now() - self.token.timestamp
        if delta > self.server.token_timeout:
            self.token.delete()
            return False
        else:
            return True

    def handle_authenticated_user(self):
        if self.server.has_access(self.request.user, self.token.consumer):
            return self.success()
        else:
            return self.access_denied()

    def handle_unauthenticated_user(self):
        next = '%s?%s' % (self.request.path, urlencode([('token', self.token.request_token)]))
        url = '%s?%s' % (reverse(self.server.auth_view_name), urlencode([('next', next)]))
        return HttpResponseRedirect(url)

    def access_denied(self):
        return HttpResponseForbidden("Access denied")

    def success(self):
        self.token.user = self.request.user
        self.token.save()
        serializer = URLSafeTimedSerializer(self.token.consumer.private_key)
        parse_result = urlparse(self.token.redirect_to)
        query_dict = QueryDict(parse_result.query, mutable=True)
        query_dict['access_token'] = serializer.dumps(self.token.access_token)
        url = urlunparse((parse_result.scheme, parse_result.netloc, parse_result.path, '', query_dict.urlencode(), ''))
        return HttpResponseRedirect(url)


class ConsumerRegisterView(BaseAPIView):
    """
    Consumer注册View
    """

    def post(self, request):
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            logger.error('参数解析失败！')
            return HttpResponseBadRequest('参数解析失败！')
        if settings.DEBUG:
            logger.warning(type(data))
            logger.warning(data)
        if not isinstance(data, dict):
            return HttpResponseBadRequest('参数错误, data is not json！')
        if 'permissions' not in data or 'perm_sync_url' not in data or 'action' not in data or 'sso_public_key' not in data:
            return HttpResponseBadRequest('参数错误！')
        if data['action'] != 'register':
            return HttpResponseBadRequest('不支持的action！')

        perm_sync_url: str = data['perm_sync_url']
        if not Consumer.url_validate(perm_sync_url):
            return HttpResponseBadRequest(f'perm_sync_url参数错误！,{perm_sync_url}')
        try:
            con = Consumer.objects.get(public_key=data['sso_public_key'])
            con.perm_sync_url = perm_sync_url
            con.save()
        except Consumer.DoesNotExist:
            return HttpResponseBadRequest('key无效！')

        permissions: List[Dict] = data['permissions']
        if len(permissions) == 0:
            return HttpResponse('0,success')
        code, msg, data = self.sync_data(con, permissions)
        # if code:
        #     return code, msg, data

        return self.get_user_permission_data(con)

    @staticmethod
    def sync_data(con: Consumer, permissions: List[Dict]):
        # 检查是否存在/已经注册
        qs = ConsumerPermissions.objects.filter(consumer_id=con.pk)
        has_data = qs.exists()

        if has_data:
            need_delete_cp: List[int] = []
            found_num = 0
            for cq in qs:
                found = False
                for p in permissions:
                    if cq.content_type_id == p.get('content_type_id') and cq.codename == p.get('codename'):
                        found = True
                        break
                if not found:
                    need_delete_cp.append(cq.pk)
                else:
                    found_num += 1
            if found_num == len(permissions) and found_num == qs.count():
                logger.warning(f'数据一样，不需要进行修改！')
                return 200, '数据一样，不需要进行修改！', None
            if len(need_delete_cp) > 0:
                # step 1, 删除权限数据
                ConsumerPermissions.objects.filter(pk__in=need_delete_cp).delete()
                # step 2, 删除权限与用户映射表数据
                UserConsumerPermission.user_consumer_permissions \
                    .through.objects.filter(consumerpermissions_id__in=need_delete_cp).delete()
                logger.warning(f'共删除{len(need_delete_cp)}条数据！')
            else:
                logger.warning(f'共删除0条数据！')
        else:
            logger.warning(f'没有存在的数据，不需要检查是否需要删除！！')
        need_create_cp: List[ConsumerPermissions] = []
        for p in permissions:
            ct_id, codename = p.get('content_type_id'), p.get('codename')
            name = p.get('name') if 'name' in p else codename
            if not isinstance(ct_id, int) or len(codename) == 0:
                continue
            found = False
            if has_data:
                for cq in qs:
                    if cq.content_type_id == p.get('content_type_id') and cq.codename == p.get('codename'):
                        found = True
                        break
            if not found:
                need_create_cp.append(
                    ConsumerPermissions(consumer_id=con.pk, codename=codename, content_type_id=ct_id, name=name)
                )

        if len(need_create_cp) > 0:
            ConsumerPermissions.objects.bulk_create(need_create_cp)
            logger.warning(f'共创建了{len(need_create_cp)}条数据！')
        else:
            logger.warning('共创建了0条数据！')
        return 200, 'success', None

    def get_user_permission_data(self, con: Consumer):
        through: models.Manager = UserConsumerPermission.user_consumer_permissions.through.objects
        has_through_data = through.all().count() == 0

        us = UserConsumerPermission.objects.select_related('user').filter(consumer=con)
        if not us.exists():
            return 201, 'success, 没有用户数据！', None

        username_permissions_map: Dict[int, list] = defaultdict(list)
        if has_through_data:
            for p in through.filter(userconsumerpermission_id__in=us):
                username_permissions_map[p.userconsumerpermission_id].append(p.consumerpermissions_id)
        users = [
            {
                'is_superuser': obj.is_superuser,
                'is_staff': obj.is_staff,
                'is_active': obj.is_active,
                'username': obj.user.username,
                'permissions': username_permissions_map[obj.user_id]
            } for obj in us
        ]

        data = {
            'type': 'multiple',  # 多用户条数据同步
            'users': users
        }
        return 210, 'success, 用户数据！', data


class VerificationProvider(BaseProvider, AuthorizeView):
    def provide(self, data):
        token = data['access_token']
        try:
            self.token = Token.objects.select_related('user').get(access_token=token, consumer=self.consumer)
        except Token.DoesNotExist:
            return self.token_not_found()
        if not self.check_token_timeout():
            return self.token_timeout()
        if not self.token.user:
            return self.token_not_bound()
        extra_data = data.get('extra_data', None)
        return self.server.get_user_data(
            self.token.user, self.consumer, extra_data=extra_data)

    def token_not_bound(self):
        return HttpResponseForbidden("Invalid token")


class Server(object):
    request_token_provider = RequestTokenProvider
    authorize_view = AuthorizeView
    verification_provider = VerificationProvider
    token_timeout = datetime.timedelta(minutes=5)
    auth_view_name = 'login'

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    def has_access(self, user, consumer):
        return True

    def get_user_extra_data(self, user, consumer, extra_data):
        raise NotImplementedError()

    def get_user_data(self, user, consumer, extra_data=None):
        user_data = {
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'is_staff': False,
            'is_superuser': False,
            'is_active': user.is_active,
        }
        if extra_data:
            user_data['extra_data'] = self.get_user_extra_data(
                user, consumer, extra_data)
        return user_data

    def get_urls(self):
        return [
            path('register', ConsumerRegisterView.as_view(), name='consumer-register'),
            url(r'^request-token/$', provider_for_django(self.request_token_provider(server=self)),
                name='simple-sso-request-token'),
            url(r'^authorize/$', self.authorize_view.as_view(server=self), name='simple-sso-authorize'),
            url(r'^verify/$', provider_for_django(self.verification_provider(server=self)), name='simple-sso-verify'),
        ]
