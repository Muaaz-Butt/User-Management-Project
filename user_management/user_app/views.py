from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from .serializers import UserUpdateSerializer, UserRegistrationSerializer, UserLoginSerializer, UserProfileSerializer, UserChangePasswordSerializer, SendPasswordResetEmailSerializer, UserPasswordResetSerializer
from django.contrib.auth import authenticate
from.models import User
from .renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import generics
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .models import LoginAttempt, LoginSettings
from .serializers import UserLoginSerializer
from .utils import get_tokens_for_user

from django.http import HttpResponse




#Generate tokens manually
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class UserRegistrationView(APIView):
    permission_classes = [AllowAny]  
    renderer_classes = [UserRenderer]
    @swagger_auto_schema(
        request_body=UserRegistrationSerializer,
        responses={
            201: openapi.Response('Registration successful', openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'token': openapi.Schema(type=openapi.TYPE_STRING),
                    'msg': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )),
            400: "Bad Request"
        }
    )
    def post(self, request, format = None):
        serializer = UserRegistrationSerializer(data = request.data)
        if serializer.is_valid(raise_exception = True):
            user = serializer.save()
            token = get_tokens_for_user(user)
            return Response({'token' : token, 'msg' : 'Registration successful'}, status = status.HTTP_201_CREATED)
        return Response(serializer.errors, status = status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):
    permission_classes = [AllowAny]
    renderer_classes = [UserRenderer]

    @swagger_auto_schema(
        request_body=UserLoginSerializer,
        responses={
            200: openapi.Response('Login Successful', openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'token': openapi.Schema(type=openapi.TYPE_STRING),
                    'msg': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )),
            400: "Bad Request",
            401: openapi.Response('Unauthorized', openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'errors': openapi.Schema(type=openapi.TYPE_OBJECT, properties={
                        'non_field_errors': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING))
                    })
                }
            )),
            403: openapi.Response('Forbidden', openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'errors': openapi.Schema(type=openapi.TYPE_OBJECT, properties={
                        'non_field_errors': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING))
                    })
                }
            )),
        }
    )
    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data.get('email')
            password = serializer.data.get('password')
            ip_address = self.get_client_ip(request)

            user = self.get_user(email)
            if user is None:
                return Response({'errors': {'non_field_errors': ['Invalid email or password']}}, status=status.HTTP_400_BAD_REQUEST)
            
            if self.is_user_locked_out(user):
                return Response({'errors': {'non_field_errors': ['Account locked. Try again later.']}}, status=status.HTTP_403_FORBIDDEN)

            if user is not None and self.authenticate_user(user, password):
                return self.login_success(user)
            else:
                return self.login_failure(user, ip_address)

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        return x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')

    def get_user(self, email):
        from django.contrib.auth import get_user_model
        User = get_user_model()
        return User.objects.filter(email=email).first()

    def is_user_locked_out(self, user):
        settings = LoginSettings.get_settings()
        recent_attempts = LoginAttempt.get_recent_attempts(user, minutes=settings.lockout_duration)
        return recent_attempts.count() >= settings.max_attempts

    def authenticate_user(self, user, password):
        return authenticate(email=user.email, password=password) is not None

    def login_success(self, user):
        token = get_tokens_for_user(user)
        LoginAttempt.objects.create(user=user, successful=True, ip_address=self.get_client_ip(self.request))
        return Response({'token': token, 'msg': 'Login Successful'}, status=status.HTTP_200_OK)

    def login_failure(self, user, ip_address):
        LoginAttempt.objects.create(user=user, successful=False, ip_address=ip_address)
        settings = LoginSettings.get_settings()
        recent_attempts = LoginAttempt.get_recent_attempts(user, minutes=settings.lockout_duration)
        if recent_attempts.count() >= settings.max_attempts:
            return Response({'errors': {'non_field_errors': ['Account locked. Try again later.']}}, status=status.HTTP_403_FORBIDDEN)
        else:
            return Response({'errors': {'non_field_errors': ['Invalid email or password']}}, status=status.HTTP_400_BAD_REQUEST)

class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        responses={
            200: openapi.Response('Profile Data Retrieved', openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                    'email': openapi.Schema(type=openapi.TYPE_STRING),
                    'first_name': openapi.Schema(type=openapi.TYPE_STRING),
                    'last_name': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )),
            401: "Unauthorized",
        }
    )
    def get(self, request, format = None):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status = status.HTTP_200_OK) 
      
class UserChangePasswordView(APIView):  
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        request_body=UserChangePasswordSerializer,
        responses={
            200: openapi.Response('Password changed successfully', openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'msg': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )),
            400: openapi.Response('Bad Request', openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'error': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )),
        }
    )
    
    def post(self, request, format=None):
        serializer = UserChangePasswordSerializer(data=request.data, context = {'user': request.user})
        if serializer.is_valid(raise_exception = True):
            return Response({'msg' : 'Password changed successfully'}, status = status.HTTP_200_OK)
        return Response(serializer.errors, status = status.HTTP_400_BAD_REQUEST)
      

class SendPasswordResetEmailView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [AllowAny]
    @swagger_auto_schema(
        request_body=SendPasswordResetEmailSerializer,
        responses={
            200: openapi.Response('Password reset email sent', openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'msg': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )),
            400: openapi.Response('Bad Request', openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'error': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )),
        }
    )
    def post(self, request, formet= None):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        if serializer.is_valid(raise_exception = True):
            return Response({'msg' : 'Password reset email has been sent'}, status = status.HTTP_200_OK)
    

class UserPasswordResetView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [AllowAny]
    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter('uid', openapi.IN_PATH, description="User ID", type=openapi.TYPE_STRING),
            openapi.Parameter('token', openapi.IN_PATH, description="Password reset token", type=openapi.TYPE_STRING)
        ],
        request_body=UserPasswordResetSerializer,
        responses={
            200: openapi.Response('Password reset successful', openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'msg': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )),
            400: openapi.Response('Bad Request', openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'error': openapi.Schema(type=openapi.TYPE_STRING),
                    # Add other possible validation error fields here
                }
            )),
        }
    )

    def post(self, request, uid, token, format = None):
        serializer = UserPasswordResetSerializer(data=request.data, context = {'uid' : uid, 'token' : token})
        if serializer.is_valid(raise_exception = True):
            return Response({'msg' : 'Password reset successful'}, status = status.HTTP_200_OK)
          
          
class LogoutView(APIView):
    permission_classes = [AllowAny]
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'refresh_token': openapi.Schema(type=openapi.TYPE_STRING, description="The refresh token to be blacklisted"),
            },
            required=['refresh_token'],
        ),
        responses={
            205: openapi.Response('Successfully logged out', openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'message': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )),
            400: openapi.Response('Bad Request', openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'error': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )),
        }
    )

    def post(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message": "Successfully logged out."}, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
          

class UserUpdateView(APIView):
    permission_classes = [IsAuthenticated]
    renderer_classes = [UserRenderer]
    @swagger_auto_schema(
        request_body=UserUpdateSerializer,
        responses={
            200: openapi.Response('Profile updated successfully', openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'msg': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )),
            400: openapi.Response('Bad Request', openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'errors': openapi.Schema(type=openapi.TYPE_OBJECT),
                }
            )),
        }
    )

    def put(self, request, format=None):
        user = request.user
        serializer = UserUpdateSerializer(user, data=request.data, partial=True, context={'request': request})
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({'msg': 'Profile updated successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserDeleteView(APIView):
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'refresh_token': openapi.Schema(type=openapi.TYPE_STRING, description="The refresh token to be blacklisted"),
            },
            required=[],
        ),
        responses={
            204: openapi.Response('User account deleted successfully', openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'msg': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )),
            400: openapi.Response('Bad Request', openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'error': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )),
        }
    )

    def delete(self, request, format=None):
        user = request.user
        
        user.delete()
        
        try:
            refresh_token = request.data.get('refresh_token')
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
        return Response({"msg": "User account deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
      
      
