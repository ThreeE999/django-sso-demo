from django.contrib.auth import logout
from django.contrib.auth.views import LoginView
from django.shortcuts import redirect


def index(request):
    if request.user.is_authenticated:
        return redirect('smeeting:index')
    return redirect('users:login')


def logout_view(request):
    logout(request)
    return redirect('users:login')


class SSOLoginView(LoginView):
    template_name = 'users/login.html'
