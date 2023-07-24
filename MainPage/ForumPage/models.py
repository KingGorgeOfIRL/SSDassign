from django.db import models
from django.contrib.auth.models import AbstractUser
from django.db.models import JSONField
from django.contrib.auth import get_user_model
# Create your models here.
class User(AbstractUser):
    email = models.EmailField(unique=True,max_length=255)
    login_attempts = models.IntegerField(default=0)
    lockedout = models.BooleanField(default=False)
    REQUIRED_FIELDS = ['email']


class ForumRoom(models.Model):
    roomName = models.CharField(max_length=50, primary_key=True)
    roomStatus = models.CharField(max_length=20,choices=[('public','Public'),('private','Private')])
    description = models.CharField(max_length=100,null=True)
    roomCreator = models.ForeignKey(User, on_delete= models.SET_NULL,null=True, related_name='creator')
    roomModerator = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='moderator')
    memberList = models.ManyToManyField(User, related_name='members')

class Comment(models.Model):
    commentId = models.AutoField(primary_key=True)
    comment = models.CharField(max_length=500)
    timecreated = models.DateTimeField(auto_now_add=True)
    room = models.ForeignKey(ForumRoom,on_delete=models.SET_NULL, null=True)
    creator = models.ForeignKey(User,on_delete=models.SET_NULL,null=True,related_name='comment_creator')

class Logs(models.Model):
    logID = models.AutoField(primary_key=True)
    timelogged = models.DateTimeField(auto_now_add=True)
    user = models.CharField(max_length=50,null=True)
    actiontype = models.CharField(
        max_length=30,
        choices=[('Create','create'),('Read','read'),('Update','update'),('Delete','delete')])
    place = models.CharField(max_length=100,default='empty')
    action = JSONField()