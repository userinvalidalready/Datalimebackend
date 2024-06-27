from django.contrib import admin
from .models import *

# Register your models here.
@admin.register(SuperuserRegistrationToken)
class SuperuserRegistrationAdmin(admin.ModelAdmin):
    list_display = ['email','token','created_at','updated_at']
    
@admin.register(AccountRegistrationToken)
class AccountRegistrationAdmin(admin.ModelAdmin):
    list_display = ['email','token','created_at','updated_at']
    
@admin.register(MemberRegistrationToken)
class MemberRegistrationAdmin(admin.ModelAdmin):
    list_display = ['email','token','created_at','updated_at']
    
admin.site.register(CustomUser)
admin.site.register(Department)

@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ['userid','attempted_at','ipaddress','issuccessful']
    
@admin.register(EmailConfirmation)
class EmailConfirmationAdmin(admin.ModelAdmin):
    list_display = ['userid','confirmation_code','sent_at','is_confirmed','is_sent']
