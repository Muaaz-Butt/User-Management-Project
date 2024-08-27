# Generated by Django 5.0.7 on 2024-08-27 11:49

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user_app', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='LoginSettings',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('max_attempts', models.PositiveIntegerField(default=5)),
                ('lockout_duration', models.PositiveIntegerField(default=7)),
            ],
        ),
        migrations.CreateModel(
            name='LoginAttempt',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('successful', models.BooleanField(default=False)),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('is_locked_out', models.BooleanField(default=False)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-timestamp'],
            },
        ),
    ]