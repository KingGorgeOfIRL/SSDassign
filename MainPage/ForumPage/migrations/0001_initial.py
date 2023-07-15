# Generated by Django 4.1.3 on 2023-07-13 08:24

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='ForumRoom',
            fields=[
                ('roomName', models.CharField(max_length=50, primary_key=True, serialize=False)),
                ('roomStatus', models.CharField(choices=[('public', 'Public'), ('private', 'Private')], max_length=20)),
                ('description', models.CharField(max_length=100, null=True)),
                ('memberList', models.ManyToManyField(related_name='members', to=settings.AUTH_USER_MODEL)),
                ('roomCreator', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='creator', to=settings.AUTH_USER_MODEL)),
                ('roomModerator', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='moderator', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Comment',
            fields=[
                ('commentId', models.AutoField(primary_key=True, serialize=False)),
                ('comment', models.CharField(max_length=500)),
                ('timecreated', models.DateTimeField(auto_now_add=True)),
                ('creator', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='comment_creator', to=settings.AUTH_USER_MODEL)),
                ('room', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='ForumPage.forumroom')),
            ],
        ),
    ]
