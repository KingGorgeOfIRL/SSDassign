from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login,logout
from django.contrib.auth.models import User
from .models import ForumRoom, Comment
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login,logout
from .forms import *
from django.contrib.auth import get_user_model
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from .tokens import *
from django.core.mail import send_mail
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from django.utils.encoding import force_str
import pyotp
from datetime import datetime, timedelta
# Create your views here.

@login_required(login_url='/login')
def discover(request):
    rooms = ForumRoom.objects.filter(roomStatus = 'public').exclude(memberList = request.user,)
    htmlvar = {'rooms':rooms}
    return render(request,'discover.html',htmlvar)

@login_required(login_url='/login')
def myrooms(request):
    rooms = ForumRoom.objects.filter(memberList = request.user)
    user = get_object_or_404(User, username = request.user.username)

    htmlvar = {'rooms':rooms, 'user':user}
    return render(request,'myrooms.html',htmlvar)

@login_required(login_url='/login')
def Accountdets(request):
    htmlvar = {}
    return render(request,'AccountDets.html',htmlvar)

def room(request,pk):
    Room = get_object_or_404(ForumRoom,roomName=pk) 
    request.session['room'] = Room.roomName
    request.session['pk'] = pk
    username = request.session['username']
    user = get_object_or_404(User,username=username)
    comments = Comment.objects.filter(room=Room)
    htmlvar = {'comments':comments,'user':user, 'room':Room}
    return render(request,'room.html',htmlvar)

#room CRUD /done /not validated
def deleteRoom(request,pk):
    room = get_object_or_404(ForumRoom, roomName=pk)

    if request.method == "POST":
        room.delete()
        return redirect('myrooms')
    htmlvar = {"obj":room}
    return render(request, 'CRUD/delete.html',htmlvar)

def createRoom(request):
    user = get_object_or_404(User,username= request.session['username'])
    if request.method == 'POST':
        form = RoomForm(request.POST,username=request.user.username)
        if form.is_valid():
            room = form.save(commit=False)
            memberlist_name = request.POST.getlist("memberList")
            memberlist_name.append('Guest')
            memberlist_name.append(request.session['username'])
            memberlist = [get_object_or_404(User, username=username) for username in memberlist_name]
            room.save()
            room.memberList.set(memberlist)
            room.roomCreator = user
            room.save()
            return redirect('room', pk = form['roomName'].value())
    else:
        form = RoomForm(username=request.user.username)
    htmlvar = {'form':form}
    return render(request,'CRUD/roomform.html',htmlvar)

def leaveRoom(request,pk):
    room = get_object_or_404(ForumRoom, roomName= pk)
    user = get_object_or_404(User, username=request.user.username)    
    room.memberList.remove(user)
    return redirect('myrooms')

def joinRoom(request,pk):
    room = get_object_or_404(ForumRoom, roomName= pk)
    user = get_object_or_404(User, username=request.user.username)    
    room.memberList.add(user)
    return redirect('myrooms')

def editRoom(request,pk):
    page = 'edit'
    user = get_object_or_404(User,username= request.session['username'])
    room = get_object_or_404(ForumRoom,roomName=pk)
    form = RoomForm(instance = room, username=request.user.username)
    if request.method == "POST":
        form = RoomForm(request.POST,instance=room, username=request.user.username)
        if form.is_valid():
            room = form.save(commit=False)
            memberlist_name = request.POST.getlist("memberList")
            memberlist_name.append('Guest')
            memberlist_name.append(request.session['username'])
            memberlist = [get_object_or_404(User, username=username) for username in memberlist_name]
            room.save()
            room.memberList.set(memberlist)
            room.roomCreator = user
            room.save()
            return redirect('myrooms')
    htmlvar = {"form": form, 'room':room, 'page':page}
    return render(request,'CRUD/roomForm.html',htmlvar)

#comment CRUD /done /not validated
#read is shown in each rooms and not update function
def deleteMessage(request,pk):
    message= get_object_or_404(Comment,commentId=pk)
    roomName = request.session['room'] 
    room = get_object_or_404(ForumRoom,roomName=roomName) 
    user = get_object_or_404(User, username = request.user.username)
    if user != message.creator and (user != room.roomModerator or user != room.roomCreator):
        return messages.error(request,"user does not have permission to do this ")
 
    if request.method == "POST":
        message.delete()
        pk = request.session['pk']
        return redirect('room',pk=pk)
    htmlvar = {"obj":message}
    return render(request, 'CRUD/delete.html',htmlvar)

def addComment(request):
    roomname = request.session['room']
    room = get_object_or_404(ForumRoom,roomName=roomname) 
    username = request.session['username']
    pk = request.session['pk']
    user = get_object_or_404(User,username=username)
    if request.method == "POST":
        comment = request.POST.get('Comment')
        add = Comment.objects.create(
            comment=comment,
            creator=user,
            room=room
        )
        return  redirect('room',pk=pk)
    htmlvar = {'room':room}
    return render(request, 'comment.html', htmlvar)

#authentication /done /not validated
def loginUser(request):
    page = 'login'
    if request.user.is_authenticated:
        return redirect('myrooms')
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = get_object_or_404(User,username=username)
        user = authenticate(request,username=username,password=password)
        if user is not None:
            request.session['username'] = username
            send_otp(request)
            return redirect('otp')
        else:
            messages.error(request,'invalid username or password')
    htmlvar = {'page':page}
    return render(request,'login.html',htmlvar)

def logoutUser(request):
    logout(request)
    return redirect('login')

def registerUser(request):
    if request.method == "POST":
        form = SignupForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.save()
            current_site = get_current_site(request)
            mail_subject = 'Activate your account.'
            message = render_to_string('Email/emailVerification.html', {
                        'user': user,
                        'domain': current_site.domain,
                        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                        'token': account_activation_token.make_token(user),
                    })
            to_email = form.cleaned_data.get('email')
            send_mail(
                subject=mail_subject,
                message=message, 
                from_email='asherlee.bxl@gmail.com',
                recipient_list= [to_email]
                )
            return messages.error(request,'Please confirm your email address to complete the registration')
        else:
            messages.error(request, "An error occured during registration")
    else:
        form = SignupForm()
    htmlvar = {'form':form}
    return render(request,'login.html',htmlvar)

def OTPview(request):
    if request.method == "POST":
        otp = request.POST['OTP']
        username = request.session['username']
        otp_secret_key = request.session['otp_secret_key']
        otp_valid_until = request.session['otp_valid_date']

        if otp_secret_key and otp_valid_until is not None:
            valid_until = datetime.fromisoformat(otp_valid_until)

            if valid_until > datetime.now():
                totp = pyotp.TOTP(otp_secret_key,interval=60)
                if totp.verify(otp):
                    user = get_object_or_404(User,username=username)
                    login(request,user)
                    del request.session['otp_secret_key']
                    del request.session['otp_valid_date']
                    return redirect('myrooms')
                else:
                    messages.error(request,'invalid otp')
            else:
                messages.error(request,'OTP has expired')
        else:
            messages.error(request,'something went wrong')
    return render(request,'Email/OTP.html')

def activate(request, uidb64, token):
    User = get_user_model()
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = get_object_or_404(User,pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        login(request,user)
        return render(request,'Email/emailvalid.html')
    else:
        return messages.error(request,'Activation link is invalid!')

def send_otp(request):
    totp = pyotp.TOTP(pyotp.random_base32(),interval=60)
    otp = totp.now()
    request.session['otp_secret_key'] = totp.secret
    valid_date = datetime.now() + timedelta(minutes=1)
    request.session['otp_valid_date'] = str(valid_date)
    user = get_object_or_404(User,username=request.POST.get('username'))
    print(otp)
    message = render_to_string('Email/OTPEmail.html', {
        'user': user,
        'token': otp,
    })
    to_email = user.email
    mail_subject = 'Login OTP.'
    send_mail(
        subject=mail_subject,
        message=message, 
        from_email='asherlee.bxl@gmail.com',
        recipient_list= [to_email]
        )
    
def guestLogin(request):
    if request.user.is_authenticated:
        return redirect('myrooms')    
    if request.method == "GET":
        username = 'Guest'
        password = 'Guest@room1'

        user = get_object_or_404(User,username=username)
        user = authenticate(request,username=username,password=password)
        if user is not None:
            login(request,user)
            request.session['username'] = username
            return redirect('myrooms')
    htmlvar = {}
    return render(request,'login.html',htmlvar)