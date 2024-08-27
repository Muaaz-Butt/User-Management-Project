
from django.contrib import admin
from django.urls import path
from .views import UserDeleteView, UserUpdateView, LogoutView, UserRegistrationView, UserPasswordResetView, UserLoginView, UserProfileView, UserChangePasswordView,SendPasswordResetEmailView

urlpatterns = [
    path('register/' , UserRegistrationView.as_view(), name='register'),
    path('login/' , UserLoginView.as_view(), name='login'),
    path('profile/' , UserProfileView.as_view(), name='profile'),
    path('changepassword/' , UserChangePasswordView.as_view(), name='change-password'), 
    path('send-reset-password-email/' , SendPasswordResetEmailView.as_view(), name='send-reset-password-email'), 
    path('reset-password/<uid>/<token>/' , UserPasswordResetView.as_view(), name='reset-password'),
    path('logout/' , LogoutView.as_view(), name='logout'),
    path('update/', UserUpdateView.as_view(), name='user-update'),
    path('delete/', UserDeleteView.as_view(), name='user-delete'),  # Add this line

]


