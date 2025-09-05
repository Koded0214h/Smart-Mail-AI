from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class Profile(models.Model):
    FILTER_CHOICES = [
        ('finance', 'Finance'),
        ('work', 'Work'),
        ('promotions', 'Promotions'),
        ('personal', 'Personal'),
        ('meetings', 'Meetings'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")

    # Google OAuth fields
    google_id = models.CharField(max_length=255, blank=True, null=True)
    access_token = models.TextField(blank=True, null=True)
    refresh_token = models.TextField(blank=True, null=True)
    token_expiry = models.DateTimeField(blank=True, null=True)

    # Filtering preference
    filter = models.CharField(max_length=255, choices=FILTER_CHOICES, default="personal")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.user.email
