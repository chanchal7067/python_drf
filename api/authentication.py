from typing import Optional, Tuple

from django.conf import settings
from django.utils.translation import gettext_lazy as _
from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions
from rest_framework_simplejwt.tokens import AccessToken

from .models import CustomUser
import logging

logger = logging.getLogger('api.auth')


class CookieJWTAuthentication(BaseAuthentication):
    """
    Authenticate the user via JWT access token stored in the 'access' cookie.
    Returns (user, token) on success, or raises AuthenticationFailed.
    """

    www_authenticate_realm = 'api'

    def authenticate(self, request) -> Optional[Tuple[CustomUser, str]]:
        # If middleware already authenticated the user, honor it.
        # IMPORTANT: Do NOT access request.user here (DRF property) to avoid recursion.
        django_request = getattr(request, '_request', request)
        existing_user = getattr(django_request, 'user', None)
        if getattr(existing_user, 'is_authenticated', False):
            logger.debug('CookieJWTAuthentication: existing authenticated user detected')
            return existing_user, ''

        # Try common cookie names
        raw_token = (
            request.COOKIES.get('access')
            or request.COOKIES.get('access_token')
            or request.COOKIES.get('jwt')
            or request.COOKIES.get('token')
        )
        if not raw_token:
            # Fallback to Authorization header
            auth_header = request.META.get('HTTP_AUTHORIZATION', '')
            if auth_header.lower().startswith('bearer '):
                raw_token = auth_header[7:].strip()
        if not raw_token:
            logger.debug('CookieJWTAuthentication: no token found in cookies or header')
            return None

        # Normalize possible prefixes/quotes
        raw_token = raw_token.strip().strip('"').strip("'")
        if raw_token.lower().startswith('bearer '):
            raw_token = raw_token[7:].strip()

        try:
            token = AccessToken(raw_token)
        except Exception:
            # Be tolerant: return None so middleware-provided request.user can still be used
            logger.debug('CookieJWTAuthentication: invalid/expired token')
            return None

        user_id = token.get('user_id', None)
        if user_id is None:
            user_id = token.get('id', None)
        if not user_id:
            logger.debug('CookieJWTAuthentication: token missing user id claim')
            return None

        try:
            user = CustomUser.objects.get(id=user_id)
        except CustomUser.DoesNotExist:
            logger.debug('CookieJWTAuthentication: user not found for id=%s', user_id)
            return None

        # Attach for downstream usage if needed
        request.auth = token
        logger.debug('CookieJWTAuthentication: authenticated user id=%s via token', user_id)
        return user, str(token)

    def authenticate_header(self, request) -> str:
        return 'Bearer realm="%s"' % self.www_authenticate_realm
