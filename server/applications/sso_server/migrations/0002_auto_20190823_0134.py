# Generated by Django 2.2.4 on 2019-08-23 01:34

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('sso_server', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='userconsumerpermissions',
            name='user',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='userconsumerpermissions',
            name='user_consumer_permissions',
            field=models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='sso_server.ConsumerPermissions', verbose_name='Consumer Permissions'),
        ),
        migrations.AddField(
            model_name='token',
            name='consumer',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='tokens', to='sso_server.Consumer'),
        ),
        migrations.AddField(
            model_name='token',
            name='user',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='consumerpermissions',
            name='consumer',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='sso_server.Consumer', verbose_name='Consumer'),
        ),
    ]
