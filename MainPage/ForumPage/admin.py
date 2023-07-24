from django.contrib import admin
from .models import *
admin.site.register(User)
admin.site.register(ForumRoom)
admin.site.register(Comment)
admin.site.register(Logs)
# Register your models here.
