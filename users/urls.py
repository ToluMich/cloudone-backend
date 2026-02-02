from django.urls import path
from .views import ForgotPasswordView, LoginView, GoogleLoginView, GitHubLoginView, RegisterView, ResetPasswordConfirmView
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path("register/", RegisterView.as_view()),
    path("login/", LoginView.as_view()),
    path("google/", GoogleLoginView.as_view()),
    path("github/", GitHubLoginView.as_view()),
    path("token/refresh/", TokenRefreshView.as_view()),
    
    path("forgot-password/", ForgotPasswordView.as_view()),
    path("reset-password/<str:uid>/<str:token>/", ResetPasswordConfirmView.as_view()),
]
