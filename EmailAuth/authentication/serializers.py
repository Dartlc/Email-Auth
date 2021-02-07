"""
    Model Serializers
"""
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from rest_framework import serializers
from .models import CustomUser


class UserRegistrationSerializers(serializers.Serializer):
    """
        User Registration Serializers
    """
    email = serializers.EmailField(max_length=255)
    password = serializers.CharField(max_length=255)

    class Meta:
        """
            Sub Class For Serializers
        """
        fields = ['email', 'password']


class ResetPasswordSerialisers(serializers.Serializer):
    """
        Login Serializers
    """
    email = serializers.EmailField(max_length=255)

    class Meta:
        """
            Subclass for reset
        """
        fields = ['email']


class SetNewPasswordSerializers(serializers.Serializer):
    """
        Set new password serializers
    """
    password = serializers.CharField(max_length=255)
    token = serializers.CharField(max_length=255)
    uidb64 = serializers.CharField(max_length=255)

    class Meta:
        """
            Subclass new password serializers
        """
        fields = ['password', 'token', 'uidb64']

    def validate(self, attrs):
        password = attrs.get('password', None)
        token = attrs.get('token', None)
        uidb64 = attrs.get('uidb64', None)

        user_id = force_str(urlsafe_base64_decode(uidb64))
        user = CustomUser.objects.get(id=user_id)

        if not PasswordResetTokenGenerator().check_token(user, token):
            raise serializers.ValidationError('Invalid client or token')
        user.set_password(password)
        user.save()
        return attrs
