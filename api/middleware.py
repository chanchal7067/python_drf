from typing import Optional
import logging

from django.utils.deprecation import MiddlewareMixin
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework import exceptions

from .models import CustomUser

logger = logging.getLogger('api.auth')


class CookieJWTMiddleware(MiddlewareMixin):
    """
    Middleware that authenticates a user on every request using the JWT access
    token stored in the 'access' cookie, and sets request.user to CustomUser.
    If invalid or missing, leaves request.user as is.
    """

    def process_request(self, request):
        # Try common cookie names
        raw_token: Optional[str] = (
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
            logger.debug('CookieJWTMiddleware: no token found in cookies or header')
            return None
        try:
            # Normalize possible prefixes/quotes
            raw_token = raw_token.strip().strip('"').strip("'")
            if raw_token.lower().startswith('bearer '):
                raw_token = raw_token[7:].strip()
            token = AccessToken(raw_token)
            user_id = token.get('user_id')
            if not user_id:
                logger.debug('CookieJWTMiddleware: token missing user_id claim')
                return None
            try:
                user = CustomUser.objects.get(id=user_id)
            except CustomUser.DoesNotExist:
                logger.debug('CookieJWTMiddleware: user not found for id=%s', user_id)
                return None
            # Set DRF-compatible hooks
            request.user = user
            # Also set Django auth cached user to ensure downstream sees it
            try:
                setattr(request, '_cached_user', user)
            except Exception:
                pass
            request.auth = token
            logger.debug('CookieJWTMiddleware: authenticated user id=%s', user_id)
        except Exception:
            # Ignore invalid tokens; downstream can treat as anonymous
            logger.debug('CookieJWTMiddleware: invalid/expired token')
            return None
        return None
