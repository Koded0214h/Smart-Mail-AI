# profiles/signals.py
from allauth.socialaccount.signals import social_account_added, social_account_updated
from django.dispatch import receiver
from .models import Profile
from allauth.socialaccount.models import SocialToken

@receiver([social_account_added, social_account_updated])
def save_google_tokens(request, sociallogin, **kwargs):
    user = sociallogin.user
    token = SocialToken.objects.filter(account__user=user, account__provider='google').first()

    if token:
        profile, created = Profile.objects.get_or_create(user=user)
        profile.google_id = sociallogin.account.uid
        profile.access_token = token.token
        profile.refresh_token = token.token_secret
        profile.token_expiry = token.expires_at
        profile.save()
