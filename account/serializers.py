# serializers.py
from base64 import urlsafe_b64decode
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode
from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework.exceptions import ValidationError
from account.models import User
from account.utils import Util


class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['email','name','password','password2','tc']
        extra_field={
            "password":{'write_only':True}
        }
    def validate(self, data):
        password=data.get('password')
        password2=data.get('password2')
        if password != password2:
            raise serializers.ValidationError("password and conformed password does not match")
        return data

    def create(self,validated_data):
        # user = User.objects.create_user(
        #     email=validated_data['email'],
        #     name=validated_data['name', ' '],
        #     password=validated_data['password'],
        #     password2 = validated_data['password2'],
        # )
        return User.objects.create_user(**validated_data)
        # return  validated_data

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    class Meta:
        model = User
        fields = ['email','password']
        # password = serializers.CharField(write_only=True)

class UserProfileSerializer(serializers.ModelSerializer):
    print("inter")
    class Meta:
        model =User
        fields=["id","name","tc"]


class ChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(required=True)
    password2 = serializers.CharField(required=True)

    class Meta:
        print("password2")
        fields=["password","password2"]
    # def validate(self,attrs):
    #     password=attrs.get('password')
    #     password2=attrs.get('password2')
    #     if password != password2:
    #         raise serializers.ValidationError("password and conformed password does not match")
    #     user.set_password(password)
    #     user.set()
    #     return attrs


class SendPasswordResetEmailSerializer(serializers.Serializer):
    email=serializers.EmailField(max_length=255)
    class Meta:
        fields=['email']
    def validate(self, attrs):
        email=attrs.get('email')
        if User.objects.filter(email=email).exists():
            user=User.objects.get(email=email)
            uid=urlsafe_base64_encode(force_bytes(user.id))
            print(("user_id",uid))
            token=PasswordResetTokenGenerator().make_token(user)
            print("password rest token",token)
            link='http://localhost:3000/api/reset/'+uid+'/'+token
            print("password reset link ", link)
            # send Email
            body = 'Click Following Link to Reset Your Password' + link
            data = {
                'subject': 'Reset Your Password',
                'body': body,
                'to_email': user.email
            }
            Util.send_email(data)
            return attrs
        else:
            raise ValidationError('your are not a register user')
# class SendPasswordResetEmailSerializer(serializers.Serializer):
#       email = serializers.EmailField(max_length=255)
#       class Meta:
#           fields = ['email']
#           def validate(self, attrs):
#               email = attrs.get('email')
#               if User.objects.filter(email=email).exists():
#                   user = User.objects.get(email=email)
#                   uid = urlsafe_base64_encode(force_bytes(user.id))
#                   print('Encoded UID', uid)
#                   token = PasswordResetTokenGenerator().make_token(user)
#                   print('Password Reset Token', token)
#                   link = 'http://localhost:3000/api/user/reset/' + uid + '/' + token
#                   print('Password Reset Link', link)
#                   # Send EMail
#                   body = 'Click Following Link to Reset Your Password' + link
#                   data = {
#                       'subject': 'Reset Your Password',
#                       'body': body,
#                       'to_email': user.email
#                   }
#                   Util.send_email(data)
#                   return attrs
#               else:
#                   raise serializers.ValidationError('You are not a Registered User')

class UserPasswordResetSerializer(serializers.Serializer):
    
    password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    class Meta:
        fields = ['password', 'password2']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            password2 = attrs.get('password2')
            uid = self.context.get('uid')
            token = self.context.get('token')
            print(token)
            if password != password2:
                raise serializers.ValidationError("Password and Confirm Password doesn't match")
            id = smart_str(urlsafe_b64decode(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError('Token is not Valid or Expired')
            user.set_password(password)
            user.save()
            return attrs
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user, token)
            raise serializers.ValidationError('Token is not Valid or Expired')


