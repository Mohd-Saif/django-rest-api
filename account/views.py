from django.shortcuts import render
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import (SendPasswordResetEmailSerializer, UserRegistrationSerializer, LoginSerializer, UserProfileSerializer,
                          ChangePasswordSerializer, UserPasswordResetSerializer)
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken

from .models import  User


# Create your views here.
# Generate Token manually

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }
class UserRegistrationView(APIView):
    def post(self,request,format=None):
        serializer=UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# login views.py

class LoginView(APIView):
    # permission_classes = [AllowAny]
    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = authenticate(request, email=serializer.validated_data['email'],
                            password=serializer.validated_data['password'])
        if user:
            token=get_tokens_for_user(user)
            return Response({'token': token}, status=status.HTTP_200_OK)
        else:
            return Response({"msg":"email and password not match"},status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

        # if user:
        #     token, created = Token.objects.get_or_create(user=user)
        #     return Response({'token': token.key, 'user_id': user.id},
        #                     status=status.HTTP_200_OK)
        # else:
        #     return Response({'error': 'Invalid credentials'},
        #                     status=status.HTTP_401_UNAUTHORIZED)


class UserProfileView(APIView):
    permission_classes=[IsAuthenticated]

    def get(self,request,format=None):
        print("serializer")
        serializer=UserProfileSerializer(request.user)
        print("serializer")
        return Response(serializer.data)

# views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from django.contrib.auth.hashers import check_password

class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = ChangePasswordSerializer(data=request.data)

        if serializer.is_valid():
            user = request.user
            old_password = serializer.validated_data['password']
            new_password = serializer.validated_data['password2']

            # Check if the old password is correct
            if not check_password(old_password, user.password):
                return Response({'error': 'Old password is incorrect.'}, status=status.HTTP_400_BAD_REQUEST)

            # Set the new password
            user.set_password(new_password)
            user.save()

            # # If using Token authentication, invalidate the existing token
            # Token.objects.filter(user=user).delete()

            return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class SendPasswordResetEmailView(APIView):
    def post(self,request,format=None):
        serializer=SendPasswordResetEmailSerializer(data=request.data)
        if serializer.is_valid():
            print("jsdbjsbdbjdb")
            return Response({"msg":'Password Reset link send Please check you Email'},status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserPasswordResetView(APIView):
    def post(self,request,uid,token):
        serializer=UserPasswordResetSerializer(data=request.data, context={'uid':uid, 'token':token})
        if serializer.is_valid():
            return Response({"msg":'password Reset Successfully'},status=status.HTTP_200_OK)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)



