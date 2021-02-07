"""
    Path for the functionality
"""

from .views import *
from django.urls import path

urlpatterns = [
    path('', index, name='index'),
    path('create/', create_user, name='create_user'),
    path('rest_password/', reset_password, name='reset_password'),
    path('password-reset/<uidb64>/<token>/', password_reset_check, name='password-reset-confirm'),
    path('set_new_password/', set_new_password, name='set_new_password'),
]
