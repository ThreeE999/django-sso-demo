from .common import *

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'ft=qli@t6zh7g8yw06o4dihz3k_w^$8jrm@319=kzcydn@l320'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['*']

# Database
# https://docs.djangoproject.com/en/2.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}

SSO_PRIVATE_KEY = 'private'
SSO_PUBLIC_KEY = 'public'
SSO_SERVER = 'http://localhost:8000/server/'

# 设置当前 sso 客户端的域名, 在想sso server注册当前client时使用。
SSO_CLIENT = 'http://localhost:8001'

# 设置user model
AUTH_USER_MODEL = "users.SSOClientUser"
LOGIN_URL = 'http://localhost:8000/api/account/login/'

# Internationalization
# https://docs.djangoproject.com/en/2.2/topics/i18n/

LANGUAGE_CODE = 'zh-hans'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/2.2/howto/static-files/

STATIC_URL = '/static/'
