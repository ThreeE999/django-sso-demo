from .common import *

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'b@-#_tnwxa&@)0nvopi$o0jedduz_lef=st3)p^)!4fowu@a(@'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['*']

# INSTALLED_APPS += [
#     'silk',
# ]

# Database
# https://docs.djangoproject.com/en/2.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}
