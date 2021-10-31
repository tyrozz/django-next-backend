from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)

from .api.views import (
    PasswordChangeView,
    PasswordResetConfirmView,
    PasswordResetView,
    ResendEmailVerificationView,
    VerifyEmailView,
)
from .views import user_detail_view, user_redirect_view, user_update_view

app_name = "users"
urlpatterns = [
    path("~redirect/", view=user_redirect_view, name="redirect"),
    path("~update/", view=user_update_view, name="update"),
    path("<str:username>/", view=user_detail_view, name="detail"),
    path(
        "api/password/reset/", PasswordResetView.as_view(), name="rest_password_reset"
    ),
    path(
        "api/password/reset/confirm/",
        PasswordResetConfirmView.as_view(),
        name="rest_password_reset_confirm",
    ),
    path(
        "api/reset/confirm/<uidb64>/<token>/",
        PasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),
    path(
        "api/password/change/",
        PasswordChangeView.as_view(),
        name="rest_password_change",
    ),
    path("api/verify-email/", VerifyEmailView.as_view(), name="rest_verify_email"),
    path(
        "api/resend-email/",
        ResendEmailVerificationView.as_view(),
        name="rest_resend_email",
    ),
    path("api/token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("api/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("api/token/verify/", TokenVerifyView.as_view(), name="token_verifiy"),
]
