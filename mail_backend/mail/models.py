from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")

    # Google OAuth fields
    google_id = models.CharField(max_length=255, blank=True, null=True)
    access_token = models.TextField(blank=True, null=True)
    refresh_token = models.TextField(blank=True, null=True)
    token_expiry = models.DateTimeField(blank=True, null=True)

    # Filtering keywords (comma-separated)
    filters = models.CharField(max_length=300, blank=True, help_text="Enter keywords separated by commas")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.user.email

    def get_filter_list(self):
        """Return list of filter keywords, stripped and lowercased"""
        if not self.filters:
            return []
        return [kw.strip().lower() for kw in self.filters.split(",") if kw.strip()]
