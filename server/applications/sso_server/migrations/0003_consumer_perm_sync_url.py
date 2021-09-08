# Generated by Django 2.2.4 on 2019-08-23 01:41

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('sso_server', '0002_auto_20190823_0134'),
    ]

    operations = [
        migrations.AddField(
            model_name='consumer',
            name='perm_sync_url',
            field=models.URLField(blank=True, help_text='由Client启动时上报，用户权限变更后调用这个地址把变更数据同步到Client！', null=True, verbose_name='权限回调地址'),
        ),
    ]
