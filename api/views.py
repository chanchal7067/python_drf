from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from django.utils import timezone
from django.contrib.auth.hashers import make_password
from django.contrib.auth import get_user_model
import random

from .utils.send_email_otp import send_otp_email
from .models import CustomUser, Verification, UserProfile
from .serializers import (
    SignupSerializer,
    LoginSerializer,
    UserProfileSerializer,
    CustomUserSerializer
)
@api_view(['POST'])
def signup(request):
    serializer = SignupSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response({"message": "User created successfully. OTP sent to email"}, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_users(request):
    """
    If role is admin: return all users (admins, teachers, users).
    If role is teacher: return only users with role 'user'.
    Otherwise: 403.
    """
    current: CustomUser = request.user  # type: ignore
    if not isinstance(current, CustomUser):
        return Response({'detail': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)

    if current.role == 'admin':
        qs = CustomUser.objects.all().order_by('id')
    elif current.role == 'teacher':
        qs = CustomUser.objects.filter(role='user').order_by('id')
    else:
        return Response({'detail': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)

    data = CustomUserSerializer(qs, many=True).data
    return Response(data, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def current_user(request):
    """Return the authenticated user's details (from request.user)."""
    user = request.user
    if not isinstance(user, CustomUser):
        return Response({'detail': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
    return Response(CustomUserSerializer(user).data, status=status.HTTP_200_OK)


@api_view(['GET', 'PATCH'])
@permission_classes([IsAuthenticated])
def my_profile(request):
    """
    GET: return own profile (create empty shell if not exists)
    PATCH: update own profile fields
    """
    user = request.user
    if not isinstance(user, CustomUser):
        return Response({'detail': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)

    profile, created = UserProfile.objects.get_or_create(user=user)
    if request.method == 'GET':
        serializer = UserProfileSerializer(profile)
        return Response(serializer.data, status=status.HTTP_200_OK)

    # PATCH
    serializer = UserProfileSerializer(profile, data=request.data, partial=True, context={'request': request})
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def verified_email_or_resendOTP(request):
    email = request.data.get('email')
    otp = request.data.get('otp')

    if not email:
        return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = CustomUser.objects.get(email=email)
    except CustomUser.DoesNotExist:
        return Response({'error':'User does not exist'}, status=status.HTTP_400_BAD_REQUEST)

    if user.is_verified:
        return Response({'message':'Email is already verified. Please Login'}, status=status.HTTP_400_BAD_REQUEST)

    if otp:
        try:
            token = Verification.objects.get(user=user, otp=otp)
        except Verification.DoesNotExist:
            return Response({'error':'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

        if token.is_expired():
            token.delete()
            return Response({'error':'OTP expired. Request a new one.'}, status=status.HTTP_400_BAD_REQUEST)

        user.is_verified = True
        user.save()
        token.delete()
        return Response({'message':'Email verified successfully'}, status=status.HTTP_200_OK)
    else:
        # Resend OTP
        Verification.objects.filter(user=user).delete()
        otp = str(random.randint(100000, 999999))
        Verification.objects.create(user=user, otp=otp)
        send_otp_email(user.email, otp)
        return Response({'message':'OTP resent successfully to your email'}, status=status.HTTP_200_OK)

@api_view(['POST'])
def forgot_password(request):
    email = request.data.get('email')
    if not email:
        return Response({'error':'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = CustomUser.objects.get(email=email)
        Verification.objects.filter(user=user).delete()
        otp = str(random.randint(100000, 999999))
        Verification.objects.create(user=user, otp=otp, created_at=timezone.now())
        send_otp_email(user.email, otp)
        return Response({'message':'OTP sent to your email'}, status=status.HTTP_200_OK)
    except CustomUser.DoesNotExist:
        return Response({'error':'User does not exist'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def reset_password(request):
    email = request.data.get('email')
    otp = request.data.get('otp')
    new_password = request.data.get('new_password')
    confirm_password = request.data.get('confirm_password')

    if not email or not otp or not new_password or not confirm_password:
        return Response({'error':'All fields are required'}, status=status.HTTP_400_BAD_REQUEST)

    if new_password != confirm_password:
        return Response({'error':'Passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = CustomUser.objects.get(email=email)
        token = Verification.objects.get(user=user, otp=otp)
        if token.is_expired():
            token.delete()
            return Response({'error':'OTP expired. Request a new one.'}, status=status.HTTP_400_BAD_REQUEST)

        user.password = make_password(new_password)
        user.save()
        token.delete()
        return Response({'message':'Password reset successfully'}, status=status.HTTP_200_OK)
    except CustomUser.DoesNotExist:
        return Response({'error':'User does not exist'}, status=status.HTTP_400_BAD_REQUEST)
    except Verification.DoesNotExist:
        return Response({'error':'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def login(request):
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.validated_data['user']

        # Create JWT tokens
        refresh = RefreshToken.for_user(user)
        access = refresh.access_token

        response = Response({
            'message':'Login successful',
            'access': str(access),
            'refresh': str(refresh),
            'user':{
                'id': user.id,
                'username': user.username,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'email': user.email,
                'mobile': user.mobile,
                'role': user.role,
                'gender': user.gender,
                'city': user.city,
                'state': user.state,
                'country': user.country
            }
        }, status=status.HTTP_200_OK)
    
        response.set_cookie(
            key='access',
            value=str(access),
            httponly=True,
            secure=False,      # change to True in production with HTTPS
            samesite='Lax',    # can be 'Strict' or 'None' (with secure=True)
            max_age=60 * 15    # access token expiry (e.g., 15 minutes)
        )

        response.set_cookie(
            key='refresh',
            value=str(refresh),
            httponly=True,
            secure=False,      # change to True in production
            samesite='Lax',
            max_age=60 * 60 * 24 * 7   # refresh token expiry (e.g., 7 days)
        )
        # Also include tokens in headers for easy Postman usage
        response['Authorization'] = f'Bearer {str(access)}'
        response['X-Access-Token'] = str(access)
        return response

    return Response({'error': 'Invalid email or password'}, status=status.HTTP_400_BAD_REQUEST)



@api_view(['POST'])
def refresh_access_token(request):
    """Issue a new access token from the refresh cookie and set it back in cookies."""
    raw_refresh = request.COOKIES.get('refresh')
    if not raw_refresh:
        return Response({'detail': 'Refresh token missing'}, status=status.HTTP_401_UNAUTHORIZED)
    try:
        refresh = RefreshToken(raw_refresh)
        access = refresh.access_token
    except Exception:
        return Response({'detail': 'Invalid or expired refresh token'}, status=status.HTTP_401_UNAUTHORIZED)

    response = Response({'access': str(access)}, status=status.HTTP_200_OK)
    response.set_cookie(
        key='access',
        value=str(access),
        httponly=True,
        secure=False,
        samesite='Lax',
        max_age=60 * 15
    )
    response['Authorization'] = f'Bearer {str(access)}'
    response['X-Access-Token'] = str(access)
    return response


@api_view(['POST'])
def logout(request):
    """Clear auth cookies."""
    response = Response({'message': 'Logged out'}, status=status.HTTP_200_OK)
    response.delete_cookie('access')
    response.delete_cookie('refresh')
    return response


@api_view(['GET'])
@permission_classes([AllowAny])
def debug_auth(request):
    """Return info about cookies and auth state for debugging."""
    cookies = {k: ('<set>' if k.lower() in {'access','refresh','access_token','jwt','token'} else v)
               for k, v in request.COOKIES.items()}
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    user = getattr(request, 'user', None)
    user_id = getattr(user, 'id', None)
    role = getattr(user, 'role', None)
    is_auth = getattr(user, 'is_authenticated', False)
    return Response({
        'cookies': cookies,
        'auth_header_present': bool(auth_header),
        'request_user_is_authenticated': bool(is_auth),
        'request_user_id': user_id,
        'request_user_role': role,
    }, status=status.HTTP_200_OK)
