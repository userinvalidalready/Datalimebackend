from rest_framework.response import Response
from rest_framework import viewsets, permissions, status, generics
from .models import *
from .serializers import *
from django.contrib.auth import get_user_model

from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags

from drf_yasg.utils import swagger_auto_schema
from rest_framework.decorators import api_view
from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth import authenticate
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.utils import timezone
from .utils import send_registration_email

User = get_user_model()


class SuperuserRegistrationTokenCreateView(generics.CreateAPIView):
    queryset = SuperuserRegistrationToken.objects.all()
    serializer_class = SuperuserRegistrationTokenSerializer
    permission_classes = [permissions.AllowAny]

    def perform_create(self, serializer):
        # Check if a superuser already exists
        if CustomUser.objects.filter(is_superuser=True).exists():
            return Response({'detail': 'A superuser already exists. You cannot create another superuser.'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            email = serializer.validated_data['email']
            token_instance, created = SuperuserRegistrationToken.objects.update_or_create(
                email=email,
                defaults={'token': uuid.uuid4()}
            )
            
            send_registration_email(email, token_instance.token, 'superuser')

            return Response({'detail': 'Registration link sent.'}, status=status.HTTP_201_CREATED)


class SuperuserRegisterSetPasswordView(APIView):
    @swagger_auto_schema(request_body=SetPasswordSerializer)
    def post(self, request, token, format=None):
        # Fetch the registration token from the database
        registration_token = get_object_or_404(SuperuserRegistrationToken, token=token)

        # Check if the registration link has expired
        if not registration_token.is_valid():
            return Response({'detail': 'This registration link has expired.'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if a superuser already exists
        if CustomUser.objects.filter(is_superuser=True).exists():
            return Response({'detail': 'A superuser already exists. You cannot create another superuser.'}, status=status.HTTP_400_BAD_REQUEST)

        # Use the email from the registration token
        email = registration_token.email

        # Validate the request data using the SetPasswordSerializer
        serializer = SetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']

            # Check if a user with this email already exists
            if CustomUser.objects.filter(email=email).exists():
                return Response({'detail': 'A user with this email already exists.'}, status=status.HTTP_400_BAD_REQUEST)

            # Create a new superuser
            user = CustomUser.objects.create_superuser(
                email=email,
                username=username,
                password=password,
            )

            # Mark the user as active and save to the database
            user.is_active = True
            user.save()

            # Delete the registration token after successful registration
            registration_token.delete()

            return Response({'detail': 'Superuser registration completed successfully.'}, status=status.HTTP_201_CREATED)

        # Return validation errors if the serializer is not valid
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    
class AccountRegistrationTokenCreateView(generics.CreateAPIView):
    queryset = AccountRegistrationToken.objects.all()
    serializer_class = AccountRegistrationTokenSerializer

    def perform_create(self, serializer):
        email = serializer.validated_data['email']
        token_instance, created = AccountRegistrationToken.objects.update_or_create(
            email=email,
            defaults={'token': uuid.uuid4()}
        )

        send_registration_email(email, token_instance.token, 'account')

        return Response({'detail': 'Registration link sent.'}, status=status.HTTP_201_CREATED)
    
    
class AccountuserViewSet(viewsets.ModelViewSet):
    queryset = CustomUser.objects.all()
    serializer_class = AccountUserSerializer
    permission_classes = (permissions.AllowAny,)

    def create(self, request, *args, **kwargs):
        # Extract the token from the URL
        token = kwargs.get('token')

        # Retrieve the registration token object
        registration_token = get_object_or_404(AccountRegistrationToken, token=token)

        # Check if the token is valid
        if not registration_token.is_valid():
            return Response({'detail': 'This registration link has expired.'}, status=status.HTTP_400_BAD_REQUEST)

        # Use the email from the registration token
        email = registration_token.email

        # Combine the request data with the email from the token
        user_data = request.data.copy()
        user_data['email'] = email

        # Validate the incoming user data
        serializer = self.get_serializer(data=user_data)
        serializer.is_valid(raise_exception=True)

        # Create the user without calling the serializer's save method
        validated_data = serializer.validated_data
        username = validated_data.get('username', 'Anonymous')
        password = validated_data['password']
        phone_number = validated_data.get('phone_number', '')
        gender = validated_data.get('gender', None)
        department = validated_data.get('department', None)
        is_department_superuser = validated_data.get('is_department_superuser', False)

        # Create the CustomUser instance
        user = CustomUser.objects.create_user(
            email=email,
            username=username,
            password=password,
            phone_number=phone_number,
            gender=gender,
            department=department,
            is_department_superuser=is_department_superuser,
        )

        # Delete the token after successful registration
        registration_token.delete()

        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
    
    # def update(self, request, *args, **kwargs):
    #     # Fetch the instance to be updated
    #     partial = kwargs.pop('partial', False)
    #     instance = self.get_object()

    #     # Combine request data
    #     user_data = request.data.copy()

    #     # Ensure that email field cannot be updated via the API
    #     user_data['email'] = instance.email

    #     # Validate and update the user data
    #     serializer = self.get_serializer(instance, data=user_data, partial=partial)
    #     serializer.is_valid(raise_exception=True)
    #     self.perform_update(serializer)

    #     return Response(serializer.data, status=status.HTTP_200_OK)

    # def perform_update(self, serializer):
    #     instance = serializer.instance
    #     # Update the password if provided
    #     if 'password' in serializer.validated_data:
    #         instance.set_password(serializer.validated_data['password'])
    #         instance.save()

    #     # Call the default save method to update other fields
    #     serializer.save()

    def perform_create(self, serializer):
        # No need to call save here, as we handle the creation directly in the create method
        pass
      
class MemberRegistrationTokenCreateView(generics.CreateAPIView):
    queryset = MemberRegistrationToken.objects.all()
    serializer_class = MemberRegistrationTokenSerializer

    def perform_create(self, serializer):
        email = serializer.validated_data['email']
        token_instance, created = MemberRegistrationToken.objects.update_or_create(
            email=email,
            defaults={'token': uuid.uuid4()}
        )

        send_registration_email(email, token_instance.token, 'member')

        return Response({'detail': 'Registration link sent.'}, status=status.HTTP_201_CREATED)

class MemberRegisterSetPasswordView(APIView):
    @swagger_auto_schema(request_body=SetPasswordSerializer)
    def post(self, request, token, format=None):
        registration_token = get_object_or_404(MemberRegistrationToken, token=token)

        if not registration_token.is_valid():
            return Response({'detail': 'This registration link has expired.'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = SetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = registration_token.email
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']

            user, created = CustomUser.objects.get_or_create(email=email, defaults={'username': username})
            if created:
                user.set_password(password)
                user.is_active = True
                user.save()
                registration_token.delete()
                return Response({'detail': 'Registration completed successfully.'}, status=status.HTTP_201_CREATED)
            else:
                return Response({'detail': 'A user with this email already exists.'}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
            
class DepartmentViewSet(viewsets.ModelViewSet):
    queryset = Department.objects.all()
    serializer_class = DepartmentSerializer
    # permission_classes = (permissions.IsAuthenticated,)
 
class UserLoginViewSet(viewsets.GenericViewSet):
    serializer_class = UserLoginSerializer
    permission_classes = (permissions.AllowAny,)
    queryset = CustomUser.objects.all()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        # ip_address = request.META.get('REMOTE_ADDR', '')  # Get user's IP address
        ip_address = "djkfdkfjkd"

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            user = None
            
        if user is None:
            # Log login attempt (unsuccessful)
            LoginAttempt.objects.create(
                userid=None,
                attempted_at=timezone.now(),
                ipaddress=ip_address,
                issuccessful=False
            )
            return Response({
                'status': 400,
                'message': 'Invalid email Address.'
            }, status=status.HTTP_400_BAD_REQUEST)
            
        if not user.is_active:
            # Log login attempt (unsuccessful)
            LoginAttempt.objects.create(
                userid=user,
                attempted_at=timezone.now(),
                ipaddress=ip_address,
                issuccessful=False
            )
            return Response({
                'status': 400,
                'message': 'User does not exists.'
            }, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(request, email=email, password=password)
        
        print('dkfkduser suer',user)
        if user is None:
            # Log login attempt (unsuccessful)
            LoginAttempt.objects.create(
                userid=user,
                attempted_at=timezone.now(),
                ipaddress=ip_address,
                issuccessful=False
            )
            return Response({
                'status': 400,
                'message': 'The password you entered is incorrect. Please try again.'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Log login attempt (successful)
        LoginAttempt.objects.create(
            userid=user,
            attempted_at=timezone.now(),
            ipaddress=ip_address,
            issuccessful=True
        )

        # Generate custom token
        custom_token_serializer = MyTokenObtainPairSerializer()
        refresh = custom_token_serializer.get_token(user)
        access_token = str(refresh.access_token)
        return Response({
            'refresh': str(refresh),
            'access': access_token,
            # Add other data you want to return with the token
            'success': 'Login successful.'
        }, status=status.HTTP_200_OK)

class CustomPasswordResetTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return str(user.pk) + str(timestamp) + str(user.token)

class SendPasswordResetEmailView(viewsets.ViewSet):
    serializer_class = SendPasswordResetEmailSerializer
    permission_classes = (permissions.AllowAny,)

    @swagger_auto_schema(request_body=SendPasswordResetEmailSerializer)
    def create(self, request):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'detail': 'User with this email does not exist.'}, status=status.HTTP_404_NOT_FOUND)

        # Generate a password reset token
        token_generator = CustomPasswordResetTokenGenerator()
        token = token_generator.make_token(user)
        user.token = token
        user.save()

        # Render the HTML email content
        ctx = {
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': token
        }

        msg_html = render_to_string('password_reset_form.html', ctx)
        plain_message = strip_tags(msg_html)
        recipient_list = [user.email] 
        # Send the password reset email
        subject = 'Your Novuscrm password request'
        to_email = user.email
        frm_email = ""
        send_mail(
            subject,
            plain_message,
            frm_email,
            [to_email],
            recipient_list,
            html_message=msg_html,
        )

        return Response({'detail': 'Password reset link sent successfully.'}, status=status.HTTP_200_OK)
    

class UserPasswordResetView(APIView):
  permission_classes = (permissions.AllowAny,)
  @swagger_auto_schema(request_body=UserPasswordResetSerializer)
  def post(self, request, uid, token, format=None):
    serializer = UserPasswordResetSerializer(data=request.data, context={'uid':uid, 'token':token})
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset Successfully'}, status=status.HTTP_200_OK)