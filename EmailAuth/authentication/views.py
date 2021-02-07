"""
    functionality Routes
"""
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.utils.encoding import smart_bytes, force_str, smart_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .serializers import UserRegistrationSerializers, ResetPasswordSerialisers, SetNewPasswordSerializers
from .models import CustomUser
from django.core.mail import EmailMessage


@api_view(['GET'])
def index(request):
    """
        Sample request
    :param request: None
    :return: string
    """
    return Response({'data': 'Hello World'}, status=status.HTTP_200_OK)


@api_view(['POST'])
def create_user(request):
    """
        End point for user registration
    :param request: None
    :return: string
    """
    serializer_data = UserRegistrationSerializers(data=request.data)
    if serializer_data.is_valid(raise_exception=True):
        try:
            CustomUser.objects.create_user(email=serializer_data.data['email'],
                                           password=serializer_data.data['password'])
        except Exception as e:
            return Response({'error': f'The Record is not created: {e}'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer_data.data, status=status.HTTP_200_OK)
    return Response({'error': f'The given data is invalid'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def reset_password(request):
    """
        Password reset
    :param request: None
    :return: string
    """
    serializers_data = ResetPasswordSerialisers(data=request.data)
    if serializers_data.is_valid(raise_exception=True):
        if CustomUser.objects.filter(email=serializers_data.data['email']).exists():
            user = CustomUser.objects.get(email=serializers_data.data['email'])
            safe_url = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(request=request).domain
            relative_link = reverse('password-reset-confirm', kwargs={'uidb64': safe_url, 'token': token})
            abs_url = f'http://{current_site}{relative_link}'
            email_body = f'Hello, \nUse link below to reset your password  \n{abs_url}'
            email = EmailMessage(subject='Reset Password mail', body=email_body, to=['sudhagarnarayanan@gmail.com'])
            email.send()
            return Response({'data': 'mail sent successfully'}, status=status.HTTP_200_OK)
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    return Response({'error': 'Invalid data'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def password_reset_check(request, uidb64, token):
    """
        Password Reset api
    :param request: None
    :param uidb64: uidb64
    :param token: token
    :return: string
    """
    global user
    try:
        user_id = smart_str(urlsafe_base64_decode(uidb64))
        user = CustomUser.objects.get(id=user_id)

        if not PasswordResetTokenGenerator().check_token(user, token):
            return Response({'error': 'Token is invalid'}, status=status.HTTP_400_BAD_REQUEST)
        return Response({'success': True, 'message': 'Credentials Valid', 'uidb64': uidb64, 'token': token},
                        status=status.HTTP_200_OK)
    except Exception as e:
        if not PasswordResetTokenGenerator().check_token(user, token):
            return Response({'error': 'Token is invalid'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['PATCH'])
def set_new_password(request):
    """
        set new password
    :param request: None
    :return: string
    """
    serializers_data = SetNewPasswordSerializers(data=request.data)
    if serializers_data.is_valid(raise_exception=True):
        return Response({'data': 'Password updated successfully'}, status=status.HTTP_200_OK)
    return Response({'error': 'Invalid data'}, status=status.HTTP_400_BAD_REQUEST)
