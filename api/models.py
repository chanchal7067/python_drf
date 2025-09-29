from django.db import models
from django.utils import timezone
from cloudinary.models import CloudinaryField


class CustomUser(models.Model):
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('user', 'User'),
        ('teacher', 'Teacher'),
    )
    GENDER_CHOICES = (
        ('male','MALE'),
        ('female','FEMALE'),
        ('other','OTHER'),
    )
    username = models.CharField(max_length=100, unique=True)
    first_name = models.CharField(max_length=100, blank=True, null=True)
    last_name = models.CharField(max_length=100, blank=True, null=True)
    email = models.EmailField(unique=True)
    mobile = models.CharField(max_length=15, unique=True)
    password = models.CharField(max_length=128)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    city = models.CharField(max_length=100, blank=True, null=True)
    state = models.CharField(max_length=100, blank=True, null=True)
    country = models.CharField(max_length=100, blank=True, null=True)
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES, blank=True, null=True)

    is_verified = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.username} - {self.role}"
    
    @property
    def is_authenticated(self):
        """
        For compatibility with Django's authentication system when using a custom
        non-AbstractUser model and manual authentication. DRF's IsAuthenticated
        checks this attribute.
        """
        return True

    @property
    def is_anonymous(self):
        return False
    
class Verification(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def is_expired(self):
        return timezone.now() > self.created_at + timezone.timedelta(minutes=5)
         
    def __str__(self):
        return f"OTP for {self.user.email}: {self.otp}"
    

class UserProfile(models.Model):
    """
    Profile information for a user.
    - One-to-one with CustomUser
    - Holds optional demographic and media fields
    """
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='profile')
    bio = models.TextField(blank=True, null=True)
    date_of_birth = models.DateField(blank=True, null=True)
    address = models.CharField(max_length=255, blank=True, null=True)
    profile_image = CloudinaryField('image', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Profile of {self.user.username}"