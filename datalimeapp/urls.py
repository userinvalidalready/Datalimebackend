from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework.urlpatterns import format_suffix_patterns
from .views import *

router = DefaultRouter()
router.register(r'departments', DepartmentViewSet, basename='department')


urlpatterns = [
    path('', include(router.urls)),
    path('superuser/register/sendemail', SuperuserRegistrationTokenCreateView.as_view(), name='superuser-registration'),
    path('superuser/register/complete/<uuid:token>/', SuperuserRegisterSetPasswordView.as_view(), name='complete-superuser-registration'),
    path('account/users/register/', AccountRegistrationTokenCreateView.as_view(), name='account-token'),
    path('account/users/register/<uuid:token>/', AccountuserViewSet.as_view({'post': 'create'}), name='account-register'),
    path('member/register/', MemberRegistrationTokenCreateView.as_view(), name='register-token'),
    path('member/register/complete/<str:token>/', MemberRegisterSetPasswordView.as_view(), name='register-api'),
    path('login/', UserLoginViewSet.as_view({'post': 'create'}), name='user-login'),
    path('send_reset_password_email/', SendPasswordResetEmailView.as_view({'post': 'create'}), name='send_reset_password_email'),
    path('reset-password/<uid>/<token>/', UserPasswordResetView.as_view(), name='reset-password'),
    
  
]
