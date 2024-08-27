from rest_framework import serializers
from .models import User
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError, force_str, smart_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .utils import Util

class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    class Meta:
        model = User
        fields = ['email', 'name', 'password', 'password2', 'tc']
        extra_kwargs = {
            'password' : {'write_only' : True},
            
        }
    def validate(self, attrs) :
        password = attrs.get('password')
        password2 = attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError("Passwords must match")
        return attrs
    
    def create(self, validate_data):
        return User.objects.create_user(**validate_data)
      

class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = User
        fields = ['email', 'password']


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'name']


class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(required=True, max_length=255, style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(required=True, max_length=255, style={'input_type': 'password'}, write_only=True)
    class Meta:
        fields = ['password', 'password2']
        
    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2') 
        user=self.context.get('user')
        if password != password2:
            raise serializers.ValidationError("password must match")
        user.set_password(password)
        user.save()
        return attrs


class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        fields = ['email']
        
    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print('Encoded uid:', uid)
            token = PasswordResetTokenGenerator().make_token(user)
            print("Token:", token)
            link = 'http://localhost:3000/reset/'+uid+'/'+token  
            print("Link:", link)
            body = "Click following link to reset your password \n"+link
            data = {'subject': "Reset your password", 'body': body, 'to_email': user.email}
            Util.send_email(data)
            return attrs
        else:
            raise serializers.ValidationError("Email does not exist")
          
          
class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(required=True, max_length=255, style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(required=True, max_length=255, style={'input_type': 'password'}, write_only=True)
    class Meta:
        fields = ['password', 'password2']
        
    def validate(self, attrs):
        try:
            password = attrs.get('password')
            password2 = attrs.get('password2') 
            uid=self.context.get('uid')
            token=self.context.get('token')
            if password != password2:
                raise serializers.ValidationError("password must match")
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError("Token is not valid or expired")
            user.set_password(password)
            user.save()
            return attrs
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user, token) 
            raise serializers.ValidationError("Token is not valid or expired")
          

class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'name']

    def validate_email(self, value):
        user = self.context['request'].user
        if User.objects.exclude(pk=user.pk).filter(email=value).exists():
            raise serializers.ValidationError("This email is already in use.")
        return value