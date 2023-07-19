from django.urls import path
from . import views
urlpatterns = [
#authentication urls
    path('',views.loginUser,name='login'),
    path('login/',views.loginUser,name='login'),
    path('register/',views.registerUser, name='register'),    
    path("logout/",views.logoutUser , name="logout"),
    path("Guest-Login",views.guestLogin, name="login-guest"),
    path('emailVerification/<uidb64>/<token>', views.activate, name='activate'),
    path('OTP/',views.OTPview,name='otp'),
#room urls
    path('discover/',views.discover, name='discover'),
    path('myrooms/', views.myrooms,name='myrooms'),
    path('AccountDetails/',views.Accountdets,name='Accountdets'),
    path('room/<str:pk>/',views.room,name='room'),
#CRUD
    path('create_room/', views.createRoom, name='createRoom'),
    path('edit_room/<str:pk>',views.editRoom,name='editRoom'),
    path('delete_room/<str:pk>',views.deleteRoom,name='deleteRoom'),
    path('leave_room/<str:pk>',views.leaveRoom,name='leaveRoom'),
    path('join_room/<str:pk>',views.joinRoom,name='joinRoom'),
    path('delete_message/<int:pk>',views.deleteMessage,name='deleteMessage'),
    path('add-comment/', views.addComment, name='addComment'),
]   