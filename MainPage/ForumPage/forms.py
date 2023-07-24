from django import forms  
from django.contrib.auth.forms import UserCreationForm  
from django.contrib.auth import get_user_model
from .models import Comment, ForumRoom
from django.forms import ModelForm
from datetime import date
from django.db import models
from django.db.models import Model
class EmailLowerField(forms.EmailField):
    def to_python(self, value):
        return value.lower()
class SignupForm(UserCreationForm):  
    email = forms.EmailField(max_length=200, help_text='Required')  
    class Meta:  
        model = get_user_model()  
        fields = ('username', 'email', 'password1', 'password2')
    email = EmailLowerField(required=True)
    
class RoomForm(ModelForm):
    
    def __init__(self,*args, **kwargs):
        username = kwargs.pop('username')
        super(RoomForm, self).__init__(*args, **kwargs)
        self.fields['memberList'].queryset = get_user_model().objects.exclude(username__in=[username,'Guest','KingGeorgeTheThird'])
    class Meta:
        model = ForumRoom
        fields = ('roomName','roomStatus','description','memberList')
    


    memberList = forms.ModelMultipleChoiceField(
        queryset= get_user_model().objects.all(),
        to_field_name = 'username',
        widget = forms.CheckboxSelectMultiple
    )

class EditRoomForm(ModelForm):
    
    def __init__(self,*args, **kwargs):
        username = kwargs.pop('username')
        super(EditRoomForm, self).__init__(*args, **kwargs)
        self.fields['memberList'].queryset = get_user_model().objects.exclude(username__in=[username,'Guest','KingGeorgeTheThird'])
        lis = []
        room = ForumRoom.objects.get(roomName = self.instance.roomName)
        lis = [member.username for member in room.memberList.all()]
        self.fields['roomModerator'].queryset = get_user_model().objects.filter(username__in= lis).exclude(username__in=['Guest','KingGeorgeTheThird'])
        self.fields['roomName'].widget.attrs['readonly'] = True
        self.fields['roomCreator'].disabled = True
    class Meta:
        model = ForumRoom
        fields = ('roomName','roomStatus','description','roomCreator','roomModerator','memberList')
    
    memberList = forms.ModelMultipleChoiceField(
        queryset= get_user_model().objects.all(),
        to_field_name = 'username',
        widget = forms.CheckboxSelectMultiple,
        required=False
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
        queryset= get_user_model().objects.exclude(username__in=['Guest']),
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
        queryset= get_user_model().objects.exclude(username__in=['Guest']),
        to_field_name = 'username',
        required=False
    )