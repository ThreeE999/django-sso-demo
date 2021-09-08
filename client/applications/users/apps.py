import logging
import os

from django.apps import AppConfig

logger = logging.getLogger(__name__)


class UsersConfig(AppConfig):
    name = 'users'
    verbose_name = '用户模块'

    def ready(self):
        # print(os.getpid())
        # print("===========ready================ 1")
        if os.environ.get('RUN_MAIN', None) != 'true':
            # 尝试解决调用2次的问题调用2次, 参考：https://stackoverflow.com/questions/33814615/
            return True
        # print("===========ready================ 2")
        from users.views import consumer_register
        ret = consumer_register()
        logger.info(ret)
