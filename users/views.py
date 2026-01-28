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
        token = request.data.get("token")
        if not token:
            return Response({"error": "GitHub token required"}, status=400)

        # Get GitHub user info
        headers = {"Authorization": f"Bearer {token}"}
        user_resp = requests.get("https://api.github.com/user", headers=headers)
        email_resp = requests.get("https://api.github.com/user/emails", headers=headers)

        if user_resp.status_code != 200 or email_resp.status_code != 200:
            return Response({"error": "Invalid GitHub token"}, status=400)

        github_data = user_resp.json()
        emails = email_resp.json()
        primary_email = next((e["email"] for e in emails if e.get("primary")), None)

        if not primary_email or "id" not in github_data:
            return Response({"error": "Could not fetch GitHub user info"}, status=400)

        github_id = github_data["id"]
        email = primary_email

        # Check if GitHub account is already linked
        social = SocialAccount.objects.filter(
            provider="github", provider_user_id=github_id
        ).first()

        if social:
            user = social.user
        else:
            user, created = User.objects.get_or_create(
                email=email, defaults={"username": email.split("@")[0]}
            )
            SocialAccount.objects.create(
                user=user,
                provider="github",
                provider_user_id=github_id
            )

        return Response(issue_tokens(user))
