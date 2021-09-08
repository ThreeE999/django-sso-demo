from django.urls import path

from . import views

# views.consumer_register()

app_name = 'users'
urlpatterns = [
    path('sync_url/<str:secret>', views.SyncView.as_view(), name='sync_url'),
    path('logout/', views.logout_view, name='logout'),
    # path('reg/', views.reg, name='reg'),
]
