from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('inbox/', views.inbox_view, name='inbox'),
    path('complete-profile/', views.complete_profile, name='complete_profile'),
    path('debug-auth/', views.debug_auth, name='debug_auth'),
    path('email/<str:email_id>/', views.email_detail_view, name='email_detail'),
    path('', views.home_redirect),
]
