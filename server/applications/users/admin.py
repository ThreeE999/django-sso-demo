from django.contrib import admin
from django.contrib.auth import admin as auth_admin
from django.utils.translation import gettext_lazy as _

from .forms import UserChangeForm
from .models import SSOServerUser


@admin.register(SSOServerUser)
class UserAdmin(auth_admin.UserAdmin):
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name', 'email')}),
        (_('Permissions'), {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    form = UserChangeForm
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff')
    # list_filter = ('event', 'is_staff', 'is_superuser', 'is_active', 'groups')
    search_fields = ('first_name', 'last_name', 'username',)
    readonly_fields = ('username', 'last_login', 'date_joined',)

    filter_horizontal = ('groups', 'user_permissions')
    list_per_page = 50

    def save_model(self, request, obj: SSOServerUser, form, change):
        if not form.instance.pk:
            if not obj.password:
                from django.utils.crypto import get_random_string
                default_password = get_random_string(8, 'abcdefABCDEFHIJKM0123456789')
                obj.set_password(default_password)
                self.message_user(request, f"您新创建的用户默认密码是：{default_password}")
            else:
                if not obj.password.startswith('pbkdf2_sha256'):
                    self.message_user(request, f"您新创建的用户默认密码是：{obj.password}")
                obj.set_password(obj.password)
        else:
            if not obj.password:
                u = SSOServerUser.objects.get(pk=form.instance.pk)
                obj.password = u.password
            else:
                obj.set_password(obj.password)
        super().save_model(request, obj, form, change)

# admin.site.unregister(Group)
