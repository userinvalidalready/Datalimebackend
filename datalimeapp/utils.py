from django.core.mail import send_mail
from django.utils import timezone
from .models import *

def send_registration_email(email, token, user_type):
    base_url = "http://127.0.0.1:8000"
    
    # Determine the URL path and email subject based on the user type
    if user_type == 'superuser':
        path = f"/superuser/register/complete/{token}"
        subject = 'Complete Your Superuser Registration'
    elif user_type == 'account':
        path = f"/account/users/{token}"
        subject = 'Complete Your Registration'
    elif user_type == 'member':
        path = f"/member/register/complete/{token}"
        subject = 'Complete Your Registration'
    else:
        raise ValueError("Invalid user type provided.")

    full_link = f"{base_url}{path}"
    message = f'Click the following link to complete your registration: {full_link}'
    from_email = ''  # Replace with your email

    # Log whether the email was sent successfully
    email_sent_successfully = False

    try:
        # Attempt to send the email
        send_mail(
            subject,
            message,
            from_email,
            [email],
            fail_silently=False,
        )
        email_sent_successfully = True
    except Exception as e:
        print(f"Failed to send email: {e}")
    
    # Update the EmailConfirmation table
    EmailConfirmation.objects.create(
        userid=None,  # User ID can be None because the user is not yet created.
        confirmation_code=token,
        sent_at=timezone.now(),
        is_confirmed=False,
        is_sent = False
    )

    # After logging the email sending status, link it to the respective user or token table
    if email_sent_successfully:
        if user_type == 'superuser':
            token_instance = SuperuserRegistrationToken.objects.filter(email=email, token=token).first()
        elif user_type == 'account':
            token_instance = AccountRegistrationToken.objects.filter(email=email, token=token).first()
        elif user_type == 'member':
            token_instance = MemberRegistrationToken.objects.filter(email=email, token=token).first()
        else:
            token_instance = None

        # If we have a valid token instance, create an EmailConfirmation entry
        if token_instance:
            EmailConfirmation.objects.update_or_create(
                userid=None,  # Initially, userid is set to None because the user is not created yet.
                confirmation_code=token,
                defaults={
                    'sent_at': timezone.now(),
                    'is_confirmed': False,
                    'is_sent': True
                }
            )
