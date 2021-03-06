# Generated by Django 2.2 on 2021-09-08 02:41

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('sso_server', '0005_auto_20190823_0748'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userconsumerpermission',
            name='is_active',
            field=models.BooleanField(default=True, help_text='指明用户是否被认为是活跃的。以反选代替删除Client帐号，本系统不会删除。 如果只是需要禁止用户登录，请再用户管理中修改【有效】状态！', verbose_name='active'),
        ),
    ]
