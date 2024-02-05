# serializers.py
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_bytes,smart_str
from django.utils.http import urlsafe_base64_encode
from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework.exceptions import ValidationError
from account.models import User

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
        fields=["password","password2"]
    # def validate(self,attrs):
    #     password=attrs.get('password')
    #     password2=attrs.get('password2')
    #     if password != password2:
    #         raise serializers.ValidationError("password and conformed password does not match")
    #     user.set_password(password)
    #     user.set()
    #     return attrs


class SendPasswordResendSerializer(serializers.Serializer):
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
            return attrs
        else:
            raise ValidationError('your are not a register user')


class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(required=True)
    password2 = serializers.CharField(required=True)
    class Meta:
        fields = ["password", "password2"]
    def validate(self, attrs):
        password=attrs.get('password')
        password2=attrs.get('password2')
        uid=self.context.get('uid')
        token=self.context.get('token')
        if password!=password2:
            raise serializers.ValidationError("password and confirm password doesn't match")
        id=smart_str(urlsafe_base64_encode(uid))
        user=User.objects.get(id=id)
        if not PasswordResetTokenGenerator().check_token(user,token):
            raise ValidationError({"msg":'token is not valid and Expired'})
        user.set_password(password)
        user.save()
        return attrs
