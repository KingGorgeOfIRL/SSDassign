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
    
    #checks for request method if is post from a form
    if request.method == "POST":
        # blanket try/except block to catch all errors
        try:
            #getting information from the form
            form = SearchRoomForm(request.POST)
            #validating the forms input by django 
            if form.is_valid():
                #including results from search bar
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
        except:
            messages.error('there has been an internal error')
    else:
        #returning the empty search bar and gets all room objects listed as public and that user is not in
        form = SearchRoomForm()
        rooms = ForumRoom.objects.filter(roomStatus = 'public').exclude(memberList = request.user)
    #sends information to template
    htmlvar = {'rooms':rooms,'form':form}
    return render(request,'discover.html',htmlvar)

@login_required(login_url='/login')
def myrooms(request):
    #gets all room objects where user is a member
    rooms = ForumRoom.objects.filter(memberList = request.user)
    #user object
    user = get_object_or_404(get_user_model(), username = request.user.username)
    #sends information to template
    htmlvar = {'rooms':rooms, 'user':user}
    return render(request,'myrooms.html',htmlvar)

@login_required(login_url='/login')
def room(request,pk):
    #getting room object
    Room = get_object_or_404(ForumRoom,roomName=pk) 
    #adding room information to the session information
    request.session['room'] = Room.roomName
    request.session['pk'] = pk
    username = request.session['username']
    #getting user object
    user = get_object_or_404(get_user_model(),username=username)
    #checks for request method if is post from a form
    if request.method == "POST":
        # blanket try/except block to catch all errors
        try:
            #getting inputted form information
            form = SearchCommentForm(request.POST)
            #validating the forms input by django 
            if form.is_valid():
                #including results from search bar
                cleanedPhrase = form['phrase'].value()
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
        except:
            messages.error('there has been an internal error')
    else:
        #returning the empty search bar and gets all comment objects 
        form = SearchCommentForm()
        comments = Comment.objects.filter(room=Room)
    #sends information to template
    htmlvar = {'comments':comments,'user':user, 'room':Room,'form':form}
    return render(request,'room.html',htmlvar)



#limits the number of rooms that can be created to 2 a minute
@ratelimit(key='post:username', rate='4/m',block=True)
def createRoom(request):
    #getting user 
    user = get_object_or_404(get_user_model(),username= request.session['username'])
    #checks for request method if is post from a form
    if request.method == 'POST':
        # blanket try/except block to catch all errors
        try:
            #getting inputted form information
            form = RoomForm(request.POST,username=request.user.username)
            #validating the forms input by django 
            if form.is_valid():
                #creating and saving newly crearted room
                room = form.save(commit=False)
                memberlist_name = request.POST.getlist("memberList")
                memberlist_name.append(request.session['username'])
                memberlist = [get_object_or_404(get_user_model(), username=username) for username in memberlist_name]
                room.roomCreator = user
                room.roomModerator = user
                room.roomName = str(room.roomName).replace('/',' ')
                room.save()
                room.memberList.set(memberlist)
                room.save()
                #converting new object into dictionary for logging
                obj_dict = model_to_dict(room)
                obj_dict['memberList'] = [user.username for user in obj_dict['memberList']]
                #logging action
                Logs.objects.create(
                    actiontype = 'Create',
                    place = f'room/{room.roomName}',
                    action = {
                        'room': obj_dict
                    },
                    user = request.user.username
                    )
                return redirect('room', pk = room.roomName)
        except:
            messages.error('there has been an internal error')
    else:
        #returning empty room form 
        form = RoomForm(username=request.user.username)
    #sends information to template
    htmlvar = {'form':form}
    return render(request,'CRUD/roomform.html',htmlvar)

def editRoom(request,pk):
    page = 'edit'
    #gets room object to be edited and logged
    oldroom = get_object_or_404(ForumRoom,roomName=pk)
    form = EditRoomForm(instance = oldroom, username=request.user.username)
    #copies object into dictionary to be logged
    obj_dict = model_to_dict(oldroom)
    obj_dict['memberList'] = [user.username for user in obj_dict['memberList']]
    old_dict = {k: obj_dict[k] for k in obj_dict}

    if request.method == "POST":
        # blanket try/except block to catch all errors
        try:
            form = EditRoomForm(request.POST,instance=oldroom, username=request.user.username)
            if form.is_valid():
                #saving new settings 
                room = form.save(commit=False)
                memberlist_name = request.POST.getlist("memberList")
                memberlist_name.append(request.session['username'])
                memberlist = [get_object_or_404(get_user_model(), username=username) for username in memberlist_name]
                room.memberList.set(memberlist)
                room.save()
                #identifing changed settings
                obj_dict = model_to_dict(room)
                obj_dict['memberList'] = [user.username for user in obj_dict['memberList']]
                diff = {}
                for (k,v),(k2,v2) in zip(old_dict.items(),obj_dict.items()):
                    if v != v2:
                        diff[k] = (v,v2)
                #logging changed settings 
                Logs.objects.create(
                    actiontype = 'Update',
                    place = f'room/{room.roomName}',
                    action = diff,
                    user = request.session['username']
                )
                return redirect('myrooms')
        except:
            messages.error('there has been an internal error')
    #sends information to template
    htmlvar = {"form": form, 'room':oldroom, 'page':page}
    return render(request,'CRUD/roomForm.html',htmlvar)

def deleteRoom(request,pk):
    #gets room object
    room = get_object_or_404(ForumRoom, roomName=pk)
    #creates a copy of room object about to be deleted for logging
    obj_dict = model_to_dict(room)
    obj_dict['memberList'] = [user.username for user in obj_dict['memberList']]
    old_dict = {k: obj_dict[k] for k in obj_dict}
    #checks for request method if is post from a form
    if request.method == "POST":
        #deletes original room object
        room.delete()
        #creats a log of the room and settings of the room and allows admin to undo action if needed
        Logs.objects.create(
        actiontype = 'Delete',
        place = f'room/',
        action = {
            'room': old_dict
        },
        user = request.user.username
        )
        return redirect('myrooms')
    #sends information to template
    htmlvar = {"obj":room}
    return render(request, 'CRUD/delete.html',htmlvar)

def leaveRoom(request,pk):
    #removes username from member list
    room = get_object_or_404(ForumRoom, roomName= pk)
    user = get_object_or_404(get_user_model(), username=request.user.username)    
    room.memberList.remove(user)
    return redirect('myrooms')

def joinRoom(request,pk):
    #adds username to memberlist
    room = get_object_or_404(ForumRoom, roomName= pk)
    user = get_object_or_404(get_user_model(), username=request.user.username)
        
    room.memberList.add(user)
    return redirect('myrooms')

#limits the number of comments that can be created to 10 a minute
@ratelimit(key='post:username', rate='20/m',block=True)
def addComment(request):
    roomname = request.session['room']
    room = get_object_or_404(ForumRoom,roomName=roomname) 
    username = request.session['username']
    pk = request.session['pk']
    user = get_object_or_404(get_user_model(),username=username)

    if request.method == "POST":
        #creats and log comment
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
        #redirects user to room
        return  redirect('room',pk=pk)
    #sends information to template
    htmlvar = {'room':room}
    return render(request, 'comment.html', htmlvar)

def deleteMessage(request,pk):
    #gets and copies comment object for logging 
    message= get_object_or_404(Comment,commentId=pk)
    roomName = request.session['room'] 
    room = get_object_or_404(ForumRoom,roomName=roomName) 
    obj_dict = model_to_dict(message)
    old_dict = {k: obj_dict[k] for k in obj_dict}
    if request.method == "POST":
        #deletes and logs comment 
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
    #sends information to template
    htmlvar = {"obj":message}
    return render(request, 'CRUD/delete.html',htmlvar)

#custom error for forbiden permissions
def handler403(request, exception):
    messages.error(request,'you have exceeded the maximum limit per minute')
    return redirect('room',pk=request.session['pk'])

def loginUser(request):
    #login and registration template is on one html doc
    page = 'login'
    #checks if user has been authenticated in the session
    if request.user.is_authenticated:
        return redirect('myrooms')
    if request.method == "POST":
        # blanket try/except block to catch all errors
        try:
            #gets username and password
            username = request.POST.get("username")
            password = request.POST.get("password")
            #checking if username is vaild
            try:
                user1 =get_user_model().objects.get(username=username)
            except:
                messages.error(request,'invalid username')
                htmlvar = {'page':page}
                return render(request,'login.html',htmlvar)
            
            #checking if valid user is locked out
            if not user1.lockedout:
                #checking if password is valid
                if user1.check_password(password): 
                    #checking if email is activated
                    if user1.is_active:         
                        request.session['username'] = username
                        send_otp(request)
                        return redirect('otp')
                    else:
                        messages.error(request,'please vaildate email first')
                #user password is not valid, this is a login attempt and it will be recorded 
                elif user1 is not None:
                    user1.login_attempts += 0
                    if int(user1.login_attempts) > 3:
                        user1.lockedout = True
                    user1.save()
                    messages.error(request,'invalid password')
            else:
                messages.error(request,'user has been locked out, please contact your admin')         
        except:
            messages.error(request,"there has been an internal error, please try again")
    #sends information to template
    htmlvar = {'page':page}
    return render(request,'login.html',htmlvar)

def logoutUser(request):
    #logs user out of session
    logout(request)
    return redirect('login')

def registerUser(request):
    #checks for request method if is post from a form
    if request.method == "POST":
        # blanket try/except block to catch all errors
        try:
            form = SignupForm(request.POST)
            #validating the forms input by django 
            if form.is_valid():
                #creating and saving new user object as not active
                user = form.save()
                user.is_active = False
                user = form.save()
                #creating and sending activation email to user
                current_site = get_current_site(request)
                mail_subject = 'Activate your account.'
                message = render_to_string('Email/emailVerification.html', {
                            'user': user,
                            'domain': current_site.domain,
                            'uid': urlsafe_base64_encode(force_bytes(user.username)),
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
                #redirects to login page 
                return redirect('myrooms')
            else:
                messages.error(request, "An error occured during registration")
        except:
            messages.error('there has been an interal error, please try again')
    else:
        #returns empty signup form
        form = SignupForm()
    #sends info to template 
    htmlvar = {'form':form}
    return render(request,'login.html',htmlvar)

def OTPview(request):
    if request.method == "POST":
        # blanket try/except block to catch all errors
        try:
            #gets information to re-create TOTP from session information
            otp = request.POST['OTP']
            username = request.session['username']
            otp_secret_key = request.session['otp_secret_key']
            otp_valid_until = request.session['otp_valid_date']
            
            #vaildating TOTP
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
        except:
            messages.error(request,"there has been an internal error, please try again")
    return render(request,'Email/OTP.html')

def activate(request, uidb64, token):
    #checking of token and uid is valid
    try:
        username = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(username=username)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        return render(request,'Email/emailvalid.html')
    else:
        return HttpResponse('<h1>Activation link is invalid!</h1>')

def send_otp(request):
    #generates OTP
    totp = pyotp.TOTP(pyotp.random_base32(),interval=60)
    otp = totp.now()
    #stores totp information in session
    request.session['otp_secret_key'] = totp.secret
    valid_date = datetime.now() + timedelta(minutes=1)
    request.session['otp_valid_date'] = str(valid_date)
    user = get_object_or_404(get_user_model(),username=request.POST.get('username'))
    #sends OTP to user in email
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
    #checks if user is signed in
    if request.user.is_authenticated:
        return redirect('myrooms')    
    #signs user into guest account
    if request.method == "GET":
        username = 'Guest'
        user = get_object_or_404(get_user_model(),username=username)
        user.is_active = True
        user.save()
        if user is not None:
            login(request,user)
            request.session['username'] = username
            return redirect('myrooms')
    htmlvar = {}
    return render(request,'login.html',htmlvar)

