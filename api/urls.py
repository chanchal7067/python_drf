from django.urls import path
from . import views

urlpatterns = [ 
    path('signup/', views.signup, name='signup'),
    path("verify-email-resend-otp/", views.verified_email_or_resendOTP, name="verify_email"),
    path('login/', views.login, name='Login'),
    path('refresh/', views.refresh_access_token, name='refresh_access_token'),
    path('logout/', views.logout, name='logout'),
    
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('reset-password/', views.reset_password, name='reset_password'),
    
    # Authenticated endpoints
    path('users/', views.list_users, name='list_users'),
    path('me/', views.current_user, name='current_user'),
    path('my-profile/', views.my_profile, name='my_profile'),
    
]