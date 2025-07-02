from django.urls import path
from . import views

urlpatterns = [
    path("auth/google/login/", views.google_login, name="google-login"),
    path("auth/google/callback/", views.google_callback, name="google-callback"),
    path("test/sync/", views.test_email_sync, name="test-email-sync"),
]
