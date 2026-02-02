from django.contrib.auth import authenticate
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import SocialAccount

import requests
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import send_mail

from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import update_session_auth_hash

User = get_user_model()


class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")
        username = request.data.get("username")

        if not email or not password or not username:
            return Response({"error": "Email, username and password required"}, status=400)

        if User.objects.filter(email=email).exists():
            return Response({"error": "User with this email already exists"}, status=400)

        user = User.objects.create_user(
            email=email,
            username=username,
            password=password
        )

        return Response(issue_tokens(user))



# ---------------- JWT ISSUANCE ---------------- #
def issue_tokens(user):
    """
    Generates access and refresh JWT tokens for a user
    """
    refresh = RefreshToken.for_user(user)
    return {
        "access": str(refresh.access_token),
        "refresh": str(refresh),
    }


# ---------------- EMAIL / PASSWORD LOGIN ---------------- #
class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):        
        email = request.data.get("email")
        password = request.data.get("password")

        if not email or not password:
            return Response({"error": "Email and password required"}, status=400)

        user = authenticate(email=email, password=password)
        if not user:
            return Response({"error": "Invalid credentials"}, status=400)
        if not user.is_active:
            return Response({"error": "User is inactive"}, status=400)

        return Response(issue_tokens(user))


# ---------------- GOOGLE LOGIN ---------------- #
class GoogleLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        token = request.data.get("token")
        if not token:
            return Response({"error": "Google token required"}, status=400)

        # Verify token with Google
        try:
            payload = id_token.verify_oauth2_token(
                token,
                google_requests.Request(),
                settings.GOOGLE_CLIENT_ID
            )
        except Exception:
            return Response({"error": "Invalid Google token"}, status=400)

        email = payload.get("email")
        google_id = payload.get("sub")

        if not email or not google_id:
            return Response({"error": "Invalid Google payload"}, status=400)

        # Check if this Google account is already linked
        social = SocialAccount.objects.filter(
            provider="google", provider_user_id=google_id
        ).first()

        if social:
            user = social.user
        else:
            # If email exists, link it; else create new user
            user, created = User.objects.get_or_create(
                email=email, defaults={"username": email.split("@")[0]}
            )
            SocialAccount.objects.create(
                user=user,
                provider="google",
                provider_user_id=google_id
            )

        return Response(issue_tokens(user))



# ---------------- GITHUB LOGIN ---------------- #
class GitHubLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        # The frontend sends the "code" from GitHub URL as "token"
        code = request.data.get("token") 
        if not code:
            return Response({"error": "GitHub code required"}, status=400)

        # STEP 1: Exchange the Code for an Actual Access Token
        token_response = requests.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": settings.GITHUB_CLIENT_ID,
                "client_secret": settings.GITHUB_CLIENT_SECRET,
                "code": code,
            },
            headers={"Accept": "application/json"}
        )
        
        token_res_data = token_response.json()
        access_token = token_res_data.get("access_token")

        if not access_token:
            return Response({"error": "Failed to obtain access token from GitHub"}, status=400)

        # STEP 2: Fetch GitHub User Profile
        user_headers = {"Authorization": f"token {access_token}"}
        user_resp = requests.get("https://api.github.com/user", headers=user_headers)
        
        if user_resp.status_code != 200:
            return Response({"error": "Could not fetch GitHub profile"}, status=400)
        
        github_data = user_resp.json()

        # STEP 3: Fetch GitHub User Emails (in case email is private)
        email_resp = requests.get("https://api.github.com/user/emails", headers=user_headers)
        
        if email_resp.status_code != 200:
            return Response({"error": "Could not fetch GitHub emails"}, status=400)

        emails = email_resp.json()
        # Find the primary email
        primary_email = next((e["email"] for e in emails if e.get("primary")), None)

        if not primary_email or "id" not in github_data:
            return Response({"error": "Incomplete GitHub account data"}, status=400)

        github_id = str(github_data["id"])
        email = primary_email

        # STEP 4: Link or Create User in the Database
        social = SocialAccount.objects.filter(
            provider="github", provider_user_id=github_id
        ).first()

        if social:
            user = social.user
        else:
            # Get or create user by email, link to social
            user, created = User.objects.get_or_create(
                email=email, 
                defaults={"username": github_data.get("login", email.split("@")[0])}
            )
            SocialAccount.objects.get_or_create(
                user=user,
                provider="github",
                provider_user_id=github_id
            )

        return Response(issue_tokens(user))


# ---------------- FORGOT PASSWORD ---------------- #
# This is the point of Request Reset
class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        if not email:
            return Response({"error": "Email is required"}, status=400)

        user = User.objects.filter(email=email).first()
        
        # Security Note: Always return a 200 even if the user doesn't exist 
        # to prevent "email harvesting" (where attackers check which emails are registered).
        if user:
            # Generate a one-time token
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            
            # In a real app, this link should point to your Frontend (React/Vue)
            # Example: https://myapp.com/reset-password/uid/token/
            reset_link = f"{settings.BASE_URL}api/auth/reset-password/{uid}/{token}/"

            send_mail(
                "Password Reset Request",
                f"Click the link to reset your password: {reset_link}",
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )

        return Response({"message": "If an account exists with this email, a reset link has been sent."})


# This is the point of Confirm Reset
class ResetPasswordConfirmView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, uid, token):
        uidb64 = request.data.get("uid")
        token = request.data.get("token")
        new_password = request.data.get("new_password")

        if not all([uidb64, token, new_password]):
            return Response({"error": "All fields are required"}, status=400)

        try:
            # Decode the user ID
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            user.set_password(new_password)
            user.save()
            return Response({"message": "Password has been reset successfully."})
        
        return Response({"error": "Invalid or expired token"}, status=400)
    
    

class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")

        # 1. Validation
        if not old_password or not new_password:
            return Response({"error": "Both old and new passwords are required"}, status=400)

        # 2. Check if the old password is correct
        if not user.check_password(old_password):
            return Response({"error": "Incorrect current password"}, status=400)

        # 3. Optional: Prevent setting the same password
        if old_password == new_password:
            return Response({"error": "New password cannot be the same as the old one"}, status=400)

        # 4. Set the new password
        user.set_password(new_password)
        user.save()

        # 5. Keep the user logged in (updates the session/hash)
        update_session_auth_hash(request, user)

        return Response({"message": "Password updated successfully"})