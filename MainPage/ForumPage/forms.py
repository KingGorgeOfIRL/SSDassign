from django import forms  
from django.contrib.auth.forms import UserCreationForm  
from django.contrib.auth.models import User  
from .models import Comment, ForumRoom
from django.forms import ModelForm
from datetime import date
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

class SearchCommentForm(forms.Form):
    phrase = forms.CharField(
        label='search comment',
          widget=forms.TextInput(attrs={
              'placeholder':'enter phrase',
              'reqiured':False,
              }),
          max_length=100,
          required=False
          )
    comment_made_after = forms.CharField(
        widget= forms.TextInput(
            attrs={'type':'date'},
        ),
        initial = date(2000,1,1),
        required=False
    )
    comment_made_by = forms.ModelMultipleChoiceField(
        queryset= User.objects.exclude(username__in=['Guest']),
        to_field_name = 'username',
        required=False
    )

class SearchRoomForm(forms.Form):
    Room_Name = forms.CharField(
        label='search room name',
        widget=forms.TextInput(attrs={
            'placeholder':'enter name',
            'reqiured':False,
            }),
        max_length=50,
        required=False
        )
    Room_Description =forms.CharField(
        label='search Descriptions',
        widget=forms.TextInput(attrs={
            'placeholder':'enter phrase',
            'reqiured':False,
            }),
        max_length=100,
        required=False
        )
    Room_made_by = forms.ModelMultipleChoiceField(
        queryset= User.objects.exclude(username__in=['Guest']),
        to_field_name = 'username',
        required=False
    )