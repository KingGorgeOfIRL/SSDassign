from django.urls import path
from . import views
urlpatterns = [
    path('',views.loginUser,name='login'),
    path('discover/',views.discover, name='discover'),
    path('myrooms/', views.myrooms,name='myrooms'),
    path('AccountDetails/',views.Accountdets,name='Accountdets'),
    path('login/',views.loginUser,name='login'),
    path('register/',views.registerUser, name='register'),
    path('room/<str:pk>/',views.room,name='room'),
    path("logout/",views.logoutUser , name="logout"),
    path("Guest-Login",views.guestLogin, name="login-guest"),
    path('emailVerification/<uidb64>/<token>', views.activate, name='activate'),
    path('OTP/',views.OTPview,name='otp'),
]   