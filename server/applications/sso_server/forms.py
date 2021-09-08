from django import forms

from . import models


class UserConsumerPermissionsAdminForm(forms.ModelForm):

    def clean_user(self):
        user = self.cleaned_data.get('user', None)
        ps = self.data.get('user_consumer_permissions', None)
        if ps and not self.instance.consumer:
            consumer = models.ConsumerPermissions.objects.get(pk=ps).consumer
            if models.UserConsumerPermission.objects.filter(consumer=consumer, user=user).exists():
                raise forms.ValidationError(f'已经存在{user}在{consumer}的权限设置，请勿重复添加！')
        return user

    def clean_user_consumer_permissions(self):
        ipa: str = self.cleaned_data.get('user_consumer_permissions', [])
        return ipa

    def save(self, commit=True):
        t = super().save(commit)
        if not self.instance.consumer:
            ps = self.cleaned_data.get('user_consumer_permissions', [])
            if len(ps) > 0:
                self.instance.consumer = ps.first().consumer
        return t

    class Meta:
        model = models.UserConsumerPermission
        fields = '__all__'
