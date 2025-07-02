from django.contrib import admin

from .models import UserProfile, EmailMessage

# Register your models here.
admin.site.register(UserProfile)
admin.site.register(EmailMessage)
