from django.db import models
from django.contrib.auth.models import User

# Create your models here.

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    email = models.EmailField(unique=True)
    google_access_token = models.TextField()
    google_refresh_token = models.TextField()
    token_expiry = models.DateTimeField()
    profile_picture = models.URLField(blank=True, null=True)
    full_name = models.CharField(max_length=255, blank=True)

    def __str__(self):
        return self.email


class EmailMessage(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    message_id = models.CharField(max_length=255, unique=True)
    subject = models.CharField(max_length=500, blank=True)
    sender = models.CharField(max_length=500, blank=True)
    snippet = models.TextField(blank=True)
    body = models.TextField(blank=True)
    date_received = models.DateTimeField()

    def __str__(self):
        return f"{self.subject or 'No Subject'} from {self.sender}"
