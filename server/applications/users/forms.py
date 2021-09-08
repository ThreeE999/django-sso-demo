from django import forms

from .models import SSOServerUser


class UserChangeForm(forms.ModelForm):
    class Meta:
        model = SSOServerUser
        fields = '__all__'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['password'].widget = forms.PasswordInput(attrs={
            'size': 43,
        })
        self.fields['password'].required = False

        f = self.fields.get('user_permissions', None)
        if f is not None:
            f.queryset = f.queryset.select_related('content_type')

    def clean_password(self):
        return self.cleaned_data.get('password', None)

    def clean_phone_number(self):
        phone_number = self.cleaned_data.get('phone_number', None)
        if phone_number:
            if len(phone_number) != 11:
                raise forms.ValidationError('员工手机号必须是11位数字！')
            user = SSOServerUser.objects.exclude(pk=self.instance.id).filter(phone_number=phone_number)
            if user.exists():
                raise forms.ValidationError('此手机号已经存在！')
        return phone_number

    def save(self, commit=True):
        return super().save(commit)


class LoginForm(forms.Form):
    username = forms.CharField(label='登录名', max_length=32)
    password = forms.CharField(widget=forms.PasswordInput, label='密码', max_length=32)

# class LoginForm(forms.ModelForm):
#     # username = forms.CharField(label='登录名', max_length=100)
#     # password = forms.CharField(widget=forms.PasswordInput)
#
#     class Meta:
#         model = TVUser
#         fields = ('username', 'password')
