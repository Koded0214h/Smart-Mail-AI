import os
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.decorators import login_required
from googleapiclient.errors import HttpError
from allauth.socialaccount.models import SocialToken, SocialAccount
from .utils import get_gmail_service, get_gmail_credentials, categorize_email
from .forms import ProfileForm
from .models import Profile

def register_view(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('login')
    else:
        form = UserCreationForm()
    return render(request, 'register.html', {'form': form})

@login_required
def complete_profile(request):
    profile, created = Profile.objects.get_or_create(user=request.user)

    if request.method == 'POST':
        form = ProfileForm(request.POST, instance=profile)
        if form.is_valid():
            form.save()
            return redirect('inbox')  # Redirect to inbox after saving
    else:
        form = ProfileForm(instance=profile)

    return render(request, 'complete_profile.html', {'form': form})



def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect('inbox')
    else:
        form = AuthenticationForm()
    return render(request, 'login.html', {'form': form})

def logout_view(request):
    logout(request)
    return redirect('login')

def home_redirect(request):
    return redirect('inbox')

@login_required
def inbox_view(request):
    # Ensure profile exists
    try:
        profile = request.user.profile
    except Profile.DoesNotExist:
        return redirect("complete_profile")

    # If no filters set, force user to complete profile
    if not profile.filters:
        return redirect("complete_profile")

    try:
        service = get_gmail_service(request.user)
        if not service:
            return render(request, 'inbox.html', {
                'emails': [],
                'error': "No valid Gmail credentials. Please reconnect your Google account.",
                'needs_reconnect': True
            })

        # Get filters from profile
        filter_keywords = profile.get_filter_list()

        # Allow override with query param (?keywords=foo,bar)
        keywords = request.GET.get('keywords', '')
        if keywords:
            filter_keywords = [kw.strip().lower() for kw in keywords.split(",") if kw.strip()]

        query = ""
        if filter_keywords:
            query = " OR ".join([f'"{kw}"' for kw in filter_keywords])

        # --- Gmail profile test ---
        try:
            service.users().getProfile(userId='me').execute()
        except HttpError as e:
            if e.resp.status == 401:
                return render(request, 'inbox.html', {
                    'emails': [],
                    'error': "Authentication failed. Please reconnect your Google account.",
                    'needs_reconnect': True
                })
            return render(request, 'inbox.html', {
                'emails': [],
                'error': f"Gmail API error: {str(e)}",
                'needs_reconnect': False
            })

        # --- Fetch messages ---
        results = service.users().messages().list(
            userId='me',
            labelIds=['INBOX'],
            q=query,
            maxResults=10
        ).execute()

        messages = results.get('messages', [])
        email_list = []

        for msg in messages:
            msg_data = service.users().messages().get(
                userId='me',
                id=msg['id'],
                format='metadata',
                metadataHeaders=['Subject', 'From', 'Date']
            ).execute()

            snippet = msg_data.get('snippet', '')
            headers = msg_data.get('payload', {}).get('headers', [])

            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '(No Subject)')
            from_email = next((h['value'] for h in headers if h['name'] == 'From'), '(Unknown Sender)')
            date = next((h['value'] for h in headers if h['name'] == 'Date'), '')

            email_list.append({
                'id': msg['id'],
                'subject': subject,
                'from': from_email,
                'snippet': snippet,
                'date': date,
            })

        return render(request, 'inbox.html', {
            'emails': email_list,
            'error': None,
            'keywords': ", ".join(filter_keywords),
            'needs_reconnect': False
        })

    except Exception as e:
        import traceback
        print("Unexpected error in inbox_view:", traceback.format_exc())
        return render(request, 'inbox.html', {
            'emails': [],
            'error': f"Unexpected error: {str(e)}",
            'needs_reconnect': 'token' in str(e).lower() or 'auth' in str(e).lower()
        })



@login_required
def email_detail_view(request, email_id):
    try:
        service = get_gmail_service(request.user)
        if not service:
            return render(request, 'email_detail.html', {
                'error': "No valid Gmail credentials. Please reconnect your Google account.",
                'needs_reconnect': True
            })

        # Get full email content
        msg_data = service.users().messages().get(
            userId='me', 
            id=email_id,
            format='full'
        ).execute()

        # Extract email data
        payload = msg_data.get('payload', {})
        headers = payload.get('headers', [])
        
        email_info = {
            'id': email_id,
            'subject': next((h['value'] for h in headers if h['name'] == 'Subject'), '(No Subject)'),
            'from': next((h['value'] for h in headers if h['name'] == 'From'), '(Unknown Sender)'),
            'to': next((h['value'] for h in headers if h['name'] == 'To'), ''),
            'date': next((h['value'] for h in headers if h['name'] == 'Date'), ''),
            'snippet': msg_data.get('snippet', ''),
        }

        # Try to get email body
        if 'parts' in payload:
            for part in payload['parts']:
                if part['mimeType'] == 'text/plain':
                    email_info['body'] = part['body']['data']
                    break
                elif part['mimeType'] == 'text/html':
                    email_info['body'] = part['body']['data']
                    break
        else:
            email_info['body'] = payload.get('body', {}).get('data', '')

        # Decode base64 body if exists
        if 'body' in email_info and email_info['body']:
            import base64
            email_info['body'] = base64.urlsafe_b64decode(email_info['body']).decode('utf-8')

        return render(request, 'email_detail.html', {
            'email': email_info,
            'error': None,
            'needs_reconnect': False
        })

    except Exception as e:
        return render(request, 'email_detail.html', {
            'error': f"Error loading email: {str(e)}",
            'needs_reconnect': True
        })
        
@login_required
def debug_auth(request):
    """
    Debug view to see what's happening with authentication
    """
    from allauth.socialaccount.models import SocialApp
    debug_info = {
        'user': str(request.user),
        'is_authenticated': request.user.is_authenticated,
    }
    
    # Check SocialAccount
    try:
        account = SocialAccount.objects.filter(user=request.user, provider='google').first()
        debug_info['has_social_account'] = bool(account)
        if account:
            debug_info['social_account'] = {
                'provider': account.provider,
                'uid': account.uid,
                'extra_data': account.extra_data
            }
    except Exception as e:
        debug_info['social_account_error'] = str(e)
    
    # Check SocialToken
    try:
        if account:
            token = SocialToken.objects.filter(account=account).first()
            debug_info['has_social_token'] = bool(token)
            if token:
                debug_info['social_token'] = {
                    'token': token.token[:20] + '...' if token.token else None,
                    'token_secret': token.token_secret[:20] + '...' if token.token_secret else None,
                    'expires_at': token.expires_at
                }
    except Exception as e:
        debug_info['social_token_error'] = str(e)
    
    # Check SocialApp
    try:
        social_app = SocialApp.objects.filter(provider='google').first()
        debug_info['has_social_app'] = bool(social_app)
        if social_app:
            debug_info['social_app'] = {
                'name': social_app.name,
                'client_id': social_app.client_id[:10] + '...' if social_app.client_id else None,
                'secret': social_app.secret[:10] + '...' if social_app.secret else None,
            }
    except Exception as e:
        debug_info['social_app_error'] = str(e)
    
    # Test credentials
    try:
        creds = get_gmail_credentials(request.user)
        debug_info['has_credentials'] = bool(creds)
        if creds:
            debug_info['credentials'] = {
                'valid': not creds.expired,
                'has_refresh_token': bool(creds.refresh_token),
                'scopes': creds.scopes
            }
    except Exception as e:
        debug_info['credentials_error'] = str(e)
    
    return render(request, 'debug_auth.html', {'debug_info': debug_info})