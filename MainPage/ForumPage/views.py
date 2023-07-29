from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login,logout,get_user_model
from django.contrib.sites.shortcuts import get_current_site
from django.contrib import messages
from .forms import *
from .tokens import *
from .models import *
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.mail import send_mail
from django.utils.encoding import force_bytes,force_str
from django.template.loader import render_to_string
import pyotp
from django.forms.models import model_to_dict
from datetime import datetime, timedelta
from django_ratelimit.decorators import ratelimit
from django_ratelimit.exceptions import Ratelimited
from django.http import HttpResponse, HttpResponseForbidden
# Create your views here.

@login_required(login_url='/login')
def discover(request):
    rooms = ForumRoom.objects.filter(roomStatus = 'public').exclude(memberList = request.user)
    if request.method == "POST":
        form = SearchRoomForm(request.POST)
        if form.is_valid():
            roomName = form['Room_Name'].value()
            roomDesc = form['Room_Description'].value()
            usernamelist = form['Room_made_by'].value()
            userlist = [get_object_or_404(get_user_model(),username=userName) for userName in usernamelist]
            if userlist == []:
                userlist = [user for user in get_user_model().objects.all()]
            rooms = ForumRoom.objects.filter(
                roomName__contains = roomName,
                description__contains = roomDesc,
                roomCreator__in = userlist,
                roomStatus = 'public'
            ).exclude(memberList = request.user)
        else:
            print(form.errors.as_data())
    else:
        form = SearchRoomForm()
        rooms = ForumRoom.objects.filter(roomStatus = 'public').exclude(memberList = request.user)
    htmlvar = {'rooms':rooms,'form':form}
    return render(request,'discover.html',htmlvar)

@login_required(login_url='/login')
def myrooms(request):
    rooms = ForumRoom.objects.filter(memberList = request.user)
    user = get_object_or_404(get_user_model(), username = request.user.username)

    htmlvar = {'rooms':rooms, 'user':user}
    return render(request,'myrooms.html',htmlvar)

@login_required(login_url='/login')
def room(request,pk):
    Room = get_object_or_404(ForumRoom,roomName=pk) 
    request.session['room'] = Room.roomName
    request.session['pk'] = pk
    username = request.session['username']
    user = get_object_or_404(get_user_model(),username=username)
    
    if request.method == "POST":
        form = SearchCommentForm(request.POST)
        if form.is_valid():
            cleanedPhrase = form['phrase'].value()
            #need to validate
            timeafter = form['comment_made_after'].value()
            usernamelist = form['comment_made_by'].value()
            userlist = [get_object_or_404(get_user_model(),username=userName) for userName in usernamelist]
            if userlist == []:
                userlist = [user for user in get_user_model().objects.all()]
            comments = Comment.objects.filter(
                room=Room, 
                comment__contains = cleanedPhrase,
                timecreated__gte=timeafter,
                creator__in = userlist
            )

        else:
            print(form.errors.as_data())
    else:
        form = SearchCommentForm()
        comments = Comment.objects.filter(room=Room)
    htmlvar = {'comments':comments,'user':user, 'room':Room,'form':form}
    return render(request,'room.html',htmlvar)

#room CRUD /done /not validated
def deleteRoom(request,pk):
    room = get_object_or_404(ForumRoom, roomName=pk)
    obj_dict = model_to_dict(room)
    obj_dict['memberList'] = [user.username for user in obj_dict['memberList']]
    old_dict = {k: obj_dict[k] for k in obj_dict}
    if request.method == "POST":
        room.delete()
        Logs.objects.create(
        actiontype = 'Delete',
        place = f'room/',
        action = {
            'room': old_dict
        },
        user = request.user.username
        )
        return redirect('myrooms')
    htmlvar = {"obj":room}
    return render(request, 'CRUD/delete.html',htmlvar)

def createRoom(request):
    user = get_object_or_404(get_user_model(),username= request.session['username'])
    if request.method == 'POST':
        form = RoomForm(request.POST,username=request.user.username)
        if form.is_valid():
            room = form.save(commit=False)
            memberlist_name = request.POST.getlist("memberList")
            memberlist_name.append('Guest')
            memberlist_name.append(request.session['username'])
            memberlist = [get_object_or_404(get_user_model(), username=username) for username in memberlist_name]
            room.roomCreator = user
            room.roomModerator = user
            room.roomName = str(room.roomName).replace('/',' ')
            room.save()
            room.memberList.set(memberlist)
            room.save()
            obj_dict = model_to_dict(room)
            obj_dict['memberList'] = [user.username for user in obj_dict['memberList']]
            Logs.objects.create(
                actiontype = 'Create',
                place = f'room/{room.roomName}',
                action = {
                    'room': obj_dict
                },
                user = request.user.username
                )
            return redirect('room', pk = room.roomName)
    else:
        form = RoomForm(username=request.user.username)
    htmlvar = {'form':form}
    return render(request,'CRUD/roomform.html',htmlvar)

def leaveRoom(request,pk):
    room = get_object_or_404(ForumRoom, roomName= pk)
    user = get_object_or_404(get_user_model(), username=request.user.username)    
    room.memberList.remove(user)
    return redirect('myrooms')

def joinRoom(request,pk):
    room = get_object_or_404(ForumRoom, roomName= pk)
    user = get_object_or_404(get_user_model(), username=request.user.username)
        
    room.memberList.add(user)
    return redirect('myrooms')

def editRoom(request,pk):
    page = 'edit'
    oldroom = get_object_or_404(ForumRoom,roomName=pk)
    form = EditRoomForm(instance = oldroom, username=request.user.username)
    obj_dict = model_to_dict(oldroom)
    obj_dict['memberList'] = [user.username for user in obj_dict['memberList']]
    old_dict = {k: obj_dict[k] for k in obj_dict}
    if request.method == "POST":
        form = EditRoomForm(request.POST,instance=oldroom, username=request.user.username)
        if form.is_valid():
            room = form.save(commit=False)
            memberlist_name = request.POST.getlist("memberList")
            memberlist_name.append('Guest')
            memberlist_name.append(request.session['username'])
            memberlist = [get_object_or_404(get_user_model(), username=username) for username in memberlist_name]
            room.memberList.set(memberlist)
            room.save()
            obj_dict = model_to_dict(room)
            obj_dict['memberList'] = [user.username for user in obj_dict['memberList']]
            diff = {}
            for (k,v),(k2,v2) in zip(old_dict.items(),obj_dict.items()):
                if v != v2:
                    diff[k] = (v,v2)
            Logs.objects.create(
                actiontype = 'Update',
                place = f'room/{room.roomName}',
                action = diff,
                user = request.session['username']
            )
            return redirect('myrooms')
    htmlvar = {"form": form, 'room':oldroom, 'page':page}
    return render(request,'CRUD/roomForm.html',htmlvar)

#comment CRUD /done /not validated
#read is shown in each rooms and not update function
def deleteMessage(request,pk):
    message= get_object_or_404(Comment,commentId=pk)
    roomName = request.session['room'] 
    room = get_object_or_404(ForumRoom,roomName=roomName) 
    user = get_object_or_404(get_user_model(), username = request.user.username)
    if user != message.creator and (user != room.roomModerator or user != room.roomCreator):
        return messages.error(request,"user does not have permission to do this ")
    obj_dict = model_to_dict(message)
    old_dict = {k: obj_dict[k] for k in obj_dict}
    if request.method == "POST":
        message.delete()
        pk = request.session['pk']
        Logs.objects.create(
        actiontype = 'Delete',
        place = f'room/{room.roomName}/comment',
        action = {
            'comment': old_dict
        },
        user = request.user.username
        )
        return redirect('room',pk=pk)
    htmlvar = {"obj":message}
    return render(request, 'CRUD/delete.html',htmlvar)

@ratelimit(key='post:username', rate='2/m',block=True)
def addComment(request):
    roomname = request.session['room']
    room = get_object_or_404(ForumRoom,roomName=roomname) 
    username = request.session['username']
    pk = request.session['pk']
    user = get_object_or_404(get_user_model(),username=username)
    if request.method == "POST":
        comment = request.POST.get('Comment')
        Comment.objects.create(
            comment=comment,
            creator=user,
            room=room
        )
        Logs.objects.create(
            actiontype = 'Create',
            place = f'room/{room.roomName}',
            action = {
                'comment' : comment,
                'creator': user.username
            },
            user = username
        )
        return  redirect('room',pk=pk)
    htmlvar = {'room':room}
    return render(request, 'comment.html', htmlvar)

def handler403(request, exception):
    messages.error(request,'you have exceeded the maximum number of comments per minute')
    return redirect('room',pk=request.session['pk'])

#authentication /done /not validated
def loginUser(request):
    page = 'login'
    if request.user.is_authenticated:
        return redirect('myrooms')
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        try:
            user1 =get_user_model().objects.get(username=username)

        except:
            messages.error(request,'invalid username')
            htmlvar = {'page':page}
            return render(request,'login.html',htmlvar)
        user = authenticate(request,username=username,password=password)
        if not user1.lockedout:
            if user is not None:            
                request.session['username'] = username
                send_otp(request)
                return redirect('otp')
            elif user1 is not None:
                user1.login_attempts += 1 
                print(user1.login_attempts)
                if int(user1.login_attempts) > 3:
                    user1.lockedout = True
                user1.save()
                messages.error(request,'invalid password')
        else:
            messages.error(request,'user has been locked out, please contact your admin')            
    htmlvar = {'page':page}
    return render(request,'login.html',htmlvar)

def logoutUser(request):
    logout(request)
    return redirect('login')

def registerUser(request):
    if request.method == "POST":
        form = SignupForm(request.POST)
        if form.is_valid():
            user = form.save()
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
            messages.error(request,'Please confirm your email address to complete the registration')
            return redirect('myrooms')
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
                    user = get_object_or_404(get_user_model(),username=username)
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
        return render(request,'Email/emailvalid.html')
    else:
        return messages.error(request,'Activation link is invalid!')

def send_otp(request):
    totp = pyotp.TOTP(pyotp.random_base32(),interval=60)
    otp = totp.now()
    request.session['otp_secret_key'] = totp.secret
    valid_date = datetime.now() + timedelta(minutes=1)
    request.session['otp_valid_date'] = str(valid_date)
    user = get_object_or_404(get_user_model(),username=request.POST.get('username'))
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
    print(otp)
    
def guestLogin(request):
    if request.user.is_authenticated:
        return redirect('myrooms')    
    if request.method == "GET":
        username = 'Guest'
        password = 'Guest@room1'
        user = get_object_or_404(get_user_model(),username=username)
        user.is_active = True
        user.save()
        if user is not None:
            login(request,user)
            request.session['username'] = username
            return redirect('myrooms')
    htmlvar = {}
    return render(request,'login.html',htmlvar)

