from google.oauth2.credentials import Credentials  # <-- this is the correct class
from googleapiclient.discovery import build
from .models import EmailMessage
import base64
import datetime

def sync_gmail_emails(user, access_token):
    creds = Credentials(token=access_token)
    service = build("gmail", "v1", credentials=creds)

    results = service.users().messages().list(userId="me", maxResults=10).execute()
    messages = results.get("messages", [])

    for msg in messages:
        msg_detail = service.users().messages().get(userId="me", id=msg["id"], format="full").execute()

        headers = msg_detail['payload'].get('headers', [])
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
        sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')

        snippet = msg_detail.get('snippet', '')
        body = ''
        try:
            parts = msg_detail['payload'].get('parts', [])
            for part in parts:
                if part['mimeType'] == 'text/plain':
                    body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                    break
        except:
            pass

        timestamp_ms = int(msg_detail.get('internalDate', '0'))
        date_received = datetime.datetime.fromtimestamp(timestamp_ms / 1000.0)

        if not EmailMessage.objects.filter(message_id=msg['id'], user=user).exists():
            EmailMessage.objects.create(
                user=user,
                message_id=msg['id'],
                subject=subject,
                sender=sender,
                snippet=snippet,
                body=body,
                date_received=date_received
            )
