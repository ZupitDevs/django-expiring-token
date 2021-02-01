"""URL conf for testing Expiring Tokens."""
from django.urls import path

from drf_expiring_token.views import LoginView, LogoutView

urlpatterns = [
    path('obtain-token/', LoginView.as_view(), name='obtain-token'),
    path('revoke-token/', LogoutView.as_view(), name='revoke-token'),
]
