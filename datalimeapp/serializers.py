from rest_framework import serializers, generics, viewsets
from rest_framework.response import Response
from rest_framework import status
from .models import *
from django.core.exceptions import ValidationError
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password

User = get_user_model()


class SuperuserRegistrationTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = SuperuserRegistrationToken
        fields = ['email']
        
class AccountRegistrationTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = AccountRegistrationToken
        fields = ['email']

class MemberRegistrationTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = MemberRegistrationToken
        fields = ['email']

    
class SetPasswordSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    confirm_password = serializers.CharField(write_only=True, style={'input_type': 'password'})

    class Meta:
        model = CustomUser
        fields = ['username','password', 'confirm_password']
        extra_kwargs = {'password': {'write_only': True}}

    def validate_email(self, value):
        existing_user = CustomUser.objects.filter(email=value).first()
        if existing_user:
            raise serializers.ValidationError("This email address is already in use.")
        return value

    def validate(self, data):
        if data['password'] != data.pop('confirm_password'):
            raise serializers.ValidationError("Passwords do not match.")
        try:
            validate_password(data['password'])
        except serializers.ValidationError as e:
            raise serializers.ValidationError(str(e))
        return data

    def create(self, validated_data):
        user = CustomUser.objects.create_user(**validated_data)
        return user


class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=3)
    password = serializers.CharField(max_length=25, min_length=8, required=True)

    class Meta:
        model = CustomUser
        fields = ['email', 'password']

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        if not email:
            raise serializers.ValidationError("Email is required.")

        if not password:
            raise serializers.ValidationError("Password is required.")

        # Check if user with this email exists
        user = CustomUser.objects.filter(email=email).first()
        if not user:
            raise serializers.ValidationError("User with this email does not exist.")

        return data
    
    
class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        # Add custom claims
        token['username'] = user.username
        # try:
        #     token['role'] = user.user_role.name
        # except AttributeError as e:
        #     token['role'] = "role not found"
        # Add any other custom claims you need

        return token
    
    
class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255, min_length=3)
    
    def validate_email(self, value):
        user = CustomUser.objects.filter(email=value).first()
        if not user:
            raise serializers.ValidationError("User with this email does not exist.")
        return value



class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)

    class Meta:
        fields = ['password', 'password2']

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        token = self.context.get('token')

        # Retrieve the user using the token
        try:
            user = CustomUser.objects.get(token=token)
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError('Token is not valid or expired')

        # Check if the token is expired (optional)
        if user.updated_at < timezone.now() - timezone.timedelta(minutes=10):
            raise serializers.ValidationError('Token is expired')

        # Validate password match
        if password != password2:
            raise serializers.ValidationError("Passwords do not match.")
        
        if len(password) < 8:
            raise serializers.ValidationError("Password length must be 8 characters.")

        # Set new password and save the user
        user.set_password(password)
        user.token = None  # Clear the token after password reset
        user.save()

        return attrs




class SuperuserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ['username','password', 'confirm_password']
        extra_kwargs = {'password': {'write_only': True}}


    def validate(self, data):
        if data['password'] != data.pop('confirm_password'):
            raise serializers.ValidationError("Passwords do not match.")
        try:
            validate_password(data['password'])
        except serializers.ValidationError as e:
            raise serializers.ValidationError(str(e))
        return data


class DepartmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Department
        fields = ['id', 'name', 'description']

class AccountUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)
    department_name = serializers.CharField(source='department.name', read_only=True)

    class Meta:
        model = CustomUser
        fields = ['username','password', 'confirm_password', 'phone_number', 'gender', 'department', 'is_department_superuser', 'department_name']
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, data):
        if data['password'] != data.pop('confirm_password'):
            raise serializers.ValidationError("Passwords do not match.")
        try:
            validate_password(data['password'])
        except serializers.ValidationError as e:
            raise serializers.ValidationError(str(e))
        return data

    def create(self, validated_data):
        validated_data.pop('confirm_password', None)
        user = CustomUser.objects.create_user(
            email=validated_data['email'],
            username=validated_data.get('username', 'Anonymous'),
            password=validated_data['password'],
            phone_number=validated_data.get('phone_number', ''),
            gender=validated_data.get('gender', None),
            department=validated_data.get('department', None),
            is_department_superuser=validated_data.get('is_department_superuser', False),
        )
        return user

    # def update(self, instance, validated_data):
    #     validated_data.pop('confirm_password', None)
    #     if 'password' in validated_data:
    #         password = validated_data.pop('password')
    #         instance.set_password(password)
        
    #     for attr, value in validated_data.items():
    #         setattr(instance, attr, value)
        
    #     instance.save()
    #     return instance