from django.urls import path
from .views import UserRegistrationView, LoginView, UserProfileView, ChangePasswordView, SendPasswordResendView

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('profile/', UserProfileView.as_view(), name='user_profile'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('send-reset-password-email/', SendPasswordResendView.as_view(), name='send-reset-password-email'),

    # Add other URL patterns as needed
]
