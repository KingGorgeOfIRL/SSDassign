from django.db import models
from django.contrib.auth.models import User
# Create your models here.
class ForumRoom(models.Model):
    roomName = models.CharField(max_length=50, primary_key=True)
    roomStatus = models.CharField(max_length=20,choices=[('public','Public'),('private','Private')])
    description = models.CharField(max_length=100,null=True)
    roomCreator = models.ForeignKey(User, on_delete= models.SET_NULL,null=True, related_name='creator')
    roomModerator = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='moderator')
    memberList = models.ManyToManyField(User, related_name='members',null=True)

class Comment(models.Model):
    commentId = models.AutoField(primary_key=True)
    comment = models.CharField(max_length=500)
    timecreated = models.DateTimeField(auto_now_add=True)
    room = models.ForeignKey(ForumRoom,on_delete=models.SET_NULL, null=True)
    creator = models.ForeignKey(User,on_delete=models.SET_NULL,null=True,related_name='comment_creator')
    