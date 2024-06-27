from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
from .choice import gender_choice
from .managers import CustomUserManager
from django.utils import timezone
import uuid
from django.conf import settings

# Create your models here.

class Department(models.Model):
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.name


class CustomUser(AbstractUser):
    username = models.CharField(max_length=150, blank=True, null=True, default='Anonymous')
    email = models.EmailField(max_length=100, unique=True)
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    gender = models.CharField(choices=gender_choice, max_length=30, null=True, blank=True)
    profile_picture = models.ImageField(upload_to='profile_pics/', null=True, blank=True)
    token = models.CharField(max_length=255, unique=True, null=True, blank=True)
    is_email_confirmed = models.CharField(max_length=20, blank=True, null=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True, blank=True, related_name='employees')
    is_department_superuser = models.BooleanField(default=False)

    # Adding related_name attributes to avoid clashes
    groups = models.ManyToManyField(
        Group,
        related_name='customuser_set',  # Change to avoid conflict
        blank=True,
        help_text='The groups this user belongs to.',
        related_query_name='customuser',
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name='customuser_set',  # Change to avoid conflict
        blank=True,
        help_text='Specific permissions for this user.',
        related_query_name='customuser',
    )

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    objects = CustomUserManager()

    def __str__(self):
        return self.email
    
    def save(self, *args, **kwargs):
        # Ensure password is hashed before saving
        if self.password:
            self.set_password(self.password)
        super().save(*args, **kwargs)
    
    def delete(self, *args, **kwargs):
        """
        Custom delete method to handle cleanup or any related logic before actual deletion.
        """
        # Perform any cleanup or additional logic here
        super().delete(*args, **kwargs)


class Role(models.Model):
    name = models.CharField(max_length=50, unique=True)

    def __str__(self):
        return self.name

class UserRole(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    department = models.ForeignKey(Department, on_delete=models.CASCADE)
    reports_to = models.ForeignKey('self', null=True, blank=True, on_delete=models.SET_NULL, related_name='subordinates')

    def __str__(self):
        return f"{self.user.username} - {self.role.name} - {self.department.name}"
    

class LoginAttempt(models.Model):
    userid = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    attempted_at = models.DateTimeField(auto_now_add=True)
    ipaddress = models.CharField(max_length=45)  # 45 chars to support IPv6
    issuccessful = models.BooleanField()

    def __str__(self):
        return f"LoginAttempt by {self.userid} at {self.attempted_at}"
    
    
class EmailConfirmation(models.Model):
    userid = models.ForeignKey('CustomUser', on_delete=models.CASCADE,null=True,blank=True)
    confirmation_code = models.CharField(max_length=255)
    sent_at = models.DateTimeField(default=timezone.now)
    is_confirmed = models.BooleanField(default=False)
    is_sent = models.BooleanField(default=False)  # New field to track if the email was sent

    def __str__(self):
        return self.confirmation_code


# class Invitation(models.Model):
#     email = models.EmailField(max_length=254)
#     invitation_code = models.CharField(max_length=100)
#     sent_date = models.DateTimeField(auto_now_add=True)
#     is_accepted = models.BooleanField(default=False)
#     invited_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE)

#     def __str__(self):
#         return f"Invitation {self.invitation_code} to {self.email}"
    


# class InvitationToken(models.Model):
#     tokenpk = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
#     email = models.EmailField(max_length=254, unique=True)
#     expiresat = models.DateTimeField(default=lambda: timezone.now() + timezone.timedelta(days=7))
#     isused = models.BooleanField(default=False)

#     def __str__(self):
#         return f"{self.email} - {'Used' if self.isused else 'Unused'}"

#     class Meta:
#         verbose_name = "Invitation Token"
#         verbose_name_plural = "Invitation Tokens"


class BillingDetails(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    billing_information = models.TextField()

    def __str__(self):
        return f"{self.user.username} - {self.amount}"

   
class SuperuserRegistrationToken(models.Model):
    email = models.EmailField(unique=True)
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def is_valid(self):
        # Token is valid for 3 minutes
        return timezone.now() < self.updated_at + timezone.timedelta(minutes=3)

    def __str__(self):
        return f'{self.email}'
    
class AccountRegistrationToken(models.Model):
    email = models.EmailField(unique=True)
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def is_valid(self):
        # Token is valid for 3 minutes
        return timezone.now() < self.updated_at + timezone.timedelta(minutes=3)

    def __str__(self):
        return f'{self.email}'
    
    
class MemberRegistrationToken(models.Model):
    email = models.EmailField()
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def is_valid(self):
        return timezone.now() < self.updated_at + timezone.timedelta(minutes=3)