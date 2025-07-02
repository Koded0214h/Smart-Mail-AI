import os
from django.shortcuts import redirect
from django.http import JsonResponse
from google_auth_oauthlib.flow import Flow
from django.views.decorators.csrf import csrf_exempt
from decouple import config
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

from django.contrib.auth.models import User
from .models import UserProfile
from .utils import sync_gmail_emails

# Enable insecure transport for local dev only
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = config("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = config("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = "http://localhost:8000/api/auth/google/callback/"

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "openid"
]

def google_login(request):
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uris": [REDIRECT_URI],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token"
            }
        },
        scopes=SCOPES
    )
    flow.redirect_uri = REDIRECT_URI

    auth_url, _ = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent"
    )

    return redirect(auth_url)

@csrf_exempt
def google_callback(request):
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uris": [REDIRECT_URI],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token"
            }
        },
        scopes=SCOPES
    )
    flow.redirect_uri = REDIRECT_URI

    authorization_response = request.build_absolute_uri()
    flow.fetch_token(authorization_response=authorization_response)
    credentials = flow.credentials

    idinfo = id_token.verify_oauth2_token(
        credentials.id_token,
        google_requests.Request(),
        GOOGLE_CLIENT_ID
    )

    email = idinfo.get("email")
    name = idinfo.get("name")
    picture = idinfo.get("picture")

    user, _ = User.objects.get_or_create(username=email, defaults={
        "email": email,
        "first_name": name
    })

    UserProfile.objects.update_or_create(
        user=user,
        defaults={
            "email": email,
            "google_access_token": credentials.token,
            "google_refresh_token": credentials.refresh_token,
            "token_expiry": credentials.expiry,
            "profile_picture": picture,
            "full_name": name
        }
    )

    return JsonResponse({
        "access_token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "token_expiry": credentials.expiry.isoformat(),
        "email": email,
        "name": name,
        "profile_picture": picture
    })

# Manually test sync
def test_email_sync(request):
    user = User.objects.first()
    profile = UserProfile.objects.get(user=user)
    sync_gmail_emails(user, profile.google_access_token)
    return JsonResponse({"status": "emails synced"})
