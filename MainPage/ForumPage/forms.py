from django import forms  
from django.contrib.auth.forms import UserCreationForm  
from django.contrib.auth.models import User  
from .models import Comment, ForumRoom
from django.forms import ModelForm
class SignupForm(UserCreationForm):  
    email = forms.EmailField(max_length=200, help_text='Required')  
    class Meta:  
        model = User  
        fields = ('username', 'email', 'password1', 'password2')
    
class RoomForm(ModelForm):
    
    def __init__(self,*args, **kwargs):
        username = kwargs.pop('username')
        super(RoomForm, self).__init__(*args, **kwargs)
        self.fields['memberList'].queryset = User.objects.exclude(username__in=[username,'Guest'])
        self.fields['roomModerator'].queryset = User.objects.exclude(username__in=['Guest'])
    class Meta:
        model = ForumRoom
        fields = ('roomName','roomStatus','description','roomModerator','memberList')
    


    memberList = forms.ModelMultipleChoiceField(
        queryset= User.objects.all(),
        to_field_name = 'username',
        widget = forms.CheckboxSelectMultiple
    )

