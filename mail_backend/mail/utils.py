import os
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from allauth.socialaccount.models import SocialToken, SocialAccount, SocialApp
from django.utils import timezone
import logging

logger = logging.getLogger(__name__)

def get_gmail_credentials(user):
    """
    Get Gmail credentials with guaranteed refresh handling
    """
    try:
        account = SocialAccount.objects.filter(user=user, provider="google").first()
        if not account:
            logger.warning("No Google account found for user")
            return None
        
        token = SocialToken.objects.filter(account=account).first()
        if not token:
            logger.warning("No SocialToken found for Google account")
            return None

        # Get client ID and secret from SocialApp
        social_app = SocialApp.objects.get(provider="google")
        
        # Debug: Check what tokens we have
        logger.info(f"Token: {token.token[:20]}..., Secret: {token.token_secret[:20] if token.token_secret else 'None'}")
        
        # Try to get refresh token from extra_data first, then fall back to token_secret
        refresh_token = None
        if account.extra_data and 'refresh_token' in account.extra_data:
            refresh_token = account.extra_data['refresh_token']
            logger.info("Found refresh token in extra_data")
        elif token.token_secret:
            refresh_token = token.token_secret
            logger.info("Using token_secret as refresh token")
        
        creds = Credentials(
            token=token.token,
            refresh_token=refresh_token,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=social_app.client_id,
            client_secret=social_app.secret,
            scopes=[
                "https://www.googleapis.com/auth/gmail.readonly",
                "https://www.googleapis.com/auth/gmail.modify",
            ]
        )

        # Refresh automatically if expired
        if creds.expired:
            logger.info("Credentials expired, attempting refresh...")
            if creds.refresh_token:
                try:
                    creds.refresh(Request())
                    # Update the token in database
                    token.token = creds.token
                    token.save()
                    
                    # Also update the account's extra_data with the new refresh token if needed
                    if not account.extra_data:
                        account.extra_data = {}
                    account.extra_data['refresh_token'] = creds.refresh_token
                    account.save()
                    
                    logger.info("Token refreshed successfully")
                except Exception as refresh_error:
                    logger.error(f"Token refresh failed: {refresh_error}")
                    return None
            else:
                logger.warning("No refresh token available, reauthentication required")
                return None

        return creds

    except SocialApp.DoesNotExist:
        logger.error("Google SocialApp not configured")
        return None
    except Exception as e:
        logger.error(f"Error getting Gmail credentials: {e}")
        return None


def get_gmail_service(user):
    """
    Get a Gmail service instance with guaranteed refresh handling
    """
    creds = get_gmail_credentials(user)
    if not creds:
        print("❌ No credentials found")  # Debug
        return None
    
    try:
        service = build('gmail', 'v1', credentials=creds)
        print("✅ Gmail service built successfully")  # Debug
        return service
    except Exception as e:
        print(f"❌ Error building Gmail service: {e}")  # Debug
        return None

def is_token_valid(user):
    """
    Check if the user's token is valid
    """
    service = get_gmail_service(user)
    if not service:
        return False
    
    try:
        # Test the token with a simple API call
        service.users().getProfile(userId='me').execute()
        return True
    except HttpError as e:
        if e.resp.status == 401:
            return False
        raise
    except Exception:
        return False
    
    
# filters.py
def categorize_email(subject, snippet):
    text = f"{subject} {snippet}".lower()

    categories = {
        "Finance": ["invoice", "payment", "bill", "subscription"],
        "Work": ["meeting", "schedule", "project", "deadline"],
        "Promotions": ["offer", "discount", "sale", "deal"],
        "Personal": ["friend", "family", "hello", "invitation"],
    }

    for category, keywords in categories.items():
        if any(kw in text for kw in keywords):
            return category

    return "General"
