# -*- coding: utf-8 -*-
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
from django.db import models
from django.utils import timezone
from django.utils.deconstruct import deconstructible
from django.utils.translation import gettext_lazy as _

from .utils import gen_secret_key


@deconstructible
class SecretKeyGenerator(object):
    """
    Helper to give default values to Client.secret and Client.key
    """

    def __init__(self, field):
        self.field = field

    def __call__(self):
        key = gen_secret_key(64)
        while self.get_model().objects.filter(**{self.field: key}).exists():
            key = gen_secret_key(64)
        return key


class ConsumerSecretKeyGenerator(SecretKeyGenerator):
    def get_model(self):
        return Consumer


class TokenSecretKeyGenerator(SecretKeyGenerator):
    def get_model(self):
        return Token


class Consumer(models.Model):
    name = models.CharField(max_length=255, unique=True)
    private_key = models.CharField(
        max_length=64, unique=True,
        default=ConsumerSecretKeyGenerator('private_key')
    )
    public_key = models.CharField(
        max_length=64, unique=True,
        default=ConsumerSecretKeyGenerator('public_key')
    )

    perm_sync_url = models.URLField('权限回调地址',
                                    null=True, blank=True,
                                    help_text='由Client启动时上报，用户权限变更后调用这个地址把变更数据同步到Client！')

    create = models.DateTimeField(verbose_name='创建时间',auto_now=True)

    def __str__(self):
        return self.name

    def rotate_keys(self):
        self.secret = ConsumerSecretKeyGenerator('private_key')()
        self.key = ConsumerSecretKeyGenerator('public_key')()
        self.save()

    @staticmethod
    def url_validate(url) -> bool:
        try:
            validate = URLValidator(schemes=('http', 'https'))
            validate(url)
            return True
        except ValidationError:
            return False


class Token(models.Model):
    consumer = models.ForeignKey(
        Consumer,
        related_name='tokens',
        on_delete=models.CASCADE,
    )
    request_token = models.CharField(
        unique=True, max_length=64,
        default=TokenSecretKeyGenerator('request_token')
    )
    access_token = models.CharField(
        unique=True, max_length=64,
        default=TokenSecretKeyGenerator('access_token')
    )
    timestamp = models.DateTimeField(default=timezone.now)
    redirect_to = models.CharField(max_length=255)
    user = models.ForeignKey(
        getattr(settings, 'AUTH_USER_MODEL', 'auth.User'),
        null=True,
        on_delete=models.CASCADE,
    )

    def refresh(self):
        self.timestamp = timezone.now()
        self.save()


class ConsumerPermissions(models.Model):
    """
    Consumer 权限
    """
    consumer = models.ForeignKey(Consumer,
                                 models.CASCADE,
                                 verbose_name='Consumer')

    name = models.CharField('name', max_length=255)
    content_type_id = models.IntegerField('ContentTypeId', )
    codename = models.CharField('codename', max_length=100)

    create = models.DateTimeField(auto_now_add=True, verbose_name='创建时间')

    class Meta:
        verbose_name = 'ConsumerPermission'
        verbose_name_plural = 'ConsumerPermissions'

    def __str__(self):
        return f'【{self.consumer}】{self.name}'


class UserConsumerPermission(models.Model):
    """
    用户管理权限
    """
    consumer = models.ForeignKey(Consumer,
                                 models.CASCADE,
                                 null=True,
                                 verbose_name='Consumer')
    user = models.ForeignKey(
        getattr(settings, 'AUTH_USER_MODEL', 'auth.User'),
        null=True,
        on_delete=models.CASCADE,
        verbose_name='用户'
    )
    is_superuser = models.BooleanField(
        _('superuser status'),
        default=False,
        help_text=_(
            'Designates that this user has all permissions without '
            'explicitly assigning them.'
        ),
    )
    is_staff = models.BooleanField(
        _('staff status'),
        default=False,
        help_text=_('Designates whether the user can log into this admin site.'),
    )
    is_active = models.BooleanField(
        _('active'),
        default=True,
        help_text=_(
            '指明用户是否被认为是活跃的。以反选代替删除Client帐号，本系统不会删除。 '
            '如果只是需要禁止用户登录，请再用户管理中修改【有效】状态！'
        ),
    )
    user_consumer_permissions = models.ManyToManyField(
        ConsumerPermissions,
        verbose_name='Consumer Permissions',
        blank=True,
        help_text='Specific permissions for this user.',
        related_name="user_set",
        related_query_name="user",
    )

    create = models.DateTimeField(auto_now_add=True, verbose_name='创建时间')

    class Meta:
        verbose_name = 'UserConsumerPermission'
        verbose_name_plural = 'UserConsumerPermissions'
        unique_together = (('consumer', 'user'),)

    def __str__(self):
        return f'【{self.consumer}】{self.user}'
