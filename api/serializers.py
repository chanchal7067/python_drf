from rest_framework import serializers
from django.contrib.auth.hashers import check_password, make_password
from api.models import CustomUser, Verification, UserProfile
import re, random
from .utils.send_email_otp import send_otp_email


# ------------------ CustomUser Serializer ------------------
class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        exclude = ['password']   # ✅ correct: don’t expose password


# ------------------ Signup Serializer ------------------
class SignupSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=100)
    first_name = serializers.CharField(max_length=100, required=False, allow_blank=True)
    last_name = serializers.CharField(max_length=100, required=False, allow_blank=True)
    email = serializers.EmailField()
    mobile = serializers.CharField(max_length=15)
    password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    confirm_password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    role = serializers.ChoiceField(choices=['admin', 'user', 'teacher'])   # ✅ ChoiceField already validates
    gender = serializers.ChoiceField(choices=['male', 'female', 'other']) # ✅ same here
    city = serializers.CharField(max_length=100, required=False, allow_blank=True)
    state = serializers.CharField(max_length=100, required=False, allow_blank=True)
    country = serializers.CharField(max_length=100, required=False, allow_blank=True)

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError("Password and Confirm Password do not match")
        return data

    def validate_email(self, value):
        if CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already exists")
        return value
    
    def validate_mobile(self, value):
        pattern = r'^[6-9]\d{9}$'   # ✅ Good: Indian mobile validation
        if not re.match(pattern, value):
            raise serializers.ValidationError("Enter a valid mobile number")
        if CustomUser.objects.filter(mobile=value).exists():
            raise serializers.ValidationError("Mobile number already exists")
        return value
    
    # ❌ Removed redundant validate_role and validate_gender 
    # because ChoiceField already enforces valid options

    def create(self, validated_data):
        validated_data.pop('confirm_password')
        user = CustomUser.objects.create(
            username=validated_data['username'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            email=validated_data['email'],
            mobile=validated_data['mobile'],
            password=make_password(validated_data['password']),   # ✅ hash password
            gender=validated_data['gender'],
            role=validated_data['role'],
            city=validated_data.get('city', ''),
            state=validated_data.get('state', ''),
            country=validated_data.get('country', ''),
            is_verified=False
        )

        # ✅ OTP creation
        otp = str(random.randint(100000, 999999))
        Verification.objects.create(user=user, otp=otp)

        send_otp_email(user.email, otp)
        return user


# ------------------ Login Serializer ------------------
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, style={'input_type': 'password'})

    def validate(self, data):
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            raise serializers.ValidationError("Email and Password are required")
        
        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("Invalid email or password")

        if not check_password(password, user.password):
            raise serializers.ValidationError("Invalid email or password")
        
        if not user.is_verified:
            raise serializers.ValidationError("Email is not verified")

        data["user"] = user
        return data


# ------------------ Forgot Password Serializer ------------------
class ForgotSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        try:
            user = CustomUser.objects.get(email=value)
            if not user.is_verified:
                raise serializers.ValidationError("Email is not verified")
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist")
        return value


# ------------------ Reset Password Serializer ------------------
class ResetSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)
    new_password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    confirm_password = serializers.CharField(write_only=True, style={'input_type': 'password'})

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("New password and Confirm Password do not match")
        return data


# ------------------ User Profile Serializer ------------------
class UserProfileSerializer(serializers.ModelSerializer):
    user_id = serializers.PrimaryKeyRelatedField(
        source='user', queryset=CustomUser.objects.all(), required=False
    )
    
    bio = serializers.SerializerMethodField()
    address = serializers.SerializerMethodField()

    class Meta:
        model = UserProfile
        fields = [
            'id', 'user_id', 'bio', 'date_of_birth', 'address', 'profile_image',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']

    def get_bio(self, obj):
        if obj.bio:
            return obj.bio.strip('"')  # remove leading/trailing quotes
        return obj.bio

    def get_address(self, obj):
        if obj.address:
            return obj.address.strip('"')  # remove leading/trailing quotes
        return obj.address
