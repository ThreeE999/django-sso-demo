import json

import requests
from django.contrib import admin, messages
from urllib3.exceptions import NewConnectionError

from .forms import UserConsumerPermissionsAdminForm
from .models import UserConsumerPermission, ConsumerPermissions, Consumer


@admin.register(Consumer)
class ConsumerAdmin(admin.ModelAdmin):
    readonly_fields = ('public_key', 'private_key', 'perm_sync_url')
    list_display = ('name', 'public_key', 'private_key', 'create')


@admin.register(UserConsumerPermission)
class UserConsumerPermissionsAdmin(admin.ModelAdmin):
    date_hierarchy = 'create'
    form = UserConsumerPermissionsAdminForm
    list_display = ('user', 'consumer', 'is_active', 'is_staff', 'is_superuser', 'create')
    readonly_fields = ('consumer',)
    list_filter = ('consumer', 'create')
    filter_horizontal = ('user_consumer_permissions',)
    fieldsets = (
        ('基本信息', {'fields': ('consumer', 'user')}),
        ('基本权限', {'fields': ('is_active', 'is_staff', 'is_superuser',)}),
        ('高级权限', {
            'fields': ('user_consumer_permissions',),
        }),
    )

    def save_model(self, request, obj: UserConsumerPermission, form, change):
        super().save_model(request, obj, form, change)
        has_ps = len(obj.user_consumer_permissions.all()) > 0

        if not has_ps:
            return
        perm_sync_url = obj.consumer.perm_sync_url
        if not Consumer.url_validate(perm_sync_url):
            return
        ps = [p.pk for p in obj.user_consumer_permissions.all()]
        data = {
            'type': 'multiple',  # 多条数据同步
            'users': [
                {
                    'is_superuser': obj.is_superuser,
                    'is_staff': obj.is_staff,
                    'is_active': obj.is_active,
                    'username': obj.user.username,
                    'permissions': ps
                },
            ]
        }

        try:
            json_data = json.dumps(data)
            r = requests.post(perm_sync_url, timeout=(5, 5), json=json_data)
            if r.status_code != 0:
                self.message_user(request, f'【{obj.consumer}】权限同步失败，错误信息：{r.text}', messages.ERROR)
            else:
                self.message_user(request, f'【{obj.consumer}】权限同步成功！')
        except (requests.ConnectionError, NewConnectionError) as e:
            self.message_user(request, f'【{obj.consumer}】权限同步失败，错误信息：{e}', messages.ERROR)


@admin.register(ConsumerPermissions)
class ConsumerPermissionsAdmin(admin.ModelAdmin):
    date_hierarchy = 'create'
    list_display = ('consumer', 'name', 'codename', 'content_type_id', 'create')
    search_fields = ('name', 'codename',)
    list_filter = ('consumer', 'create')

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def has_view_permission(self, request, obj=None):
        return super().has_view_permission(request, obj)
