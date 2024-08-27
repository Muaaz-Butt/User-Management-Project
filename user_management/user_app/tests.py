from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from user_app.models import User
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator



# class UserRegistrationTests(APITestCase):
#     def test_successful_registration(self):
#         url = reverse('register')
#         data = {
#             'email': 'testuser@example.com',
#             'name': 'Test User',
#             'password': 'Testpass123',
#             'password2': 'Testpass123',
#             'tc': True
#         }
#         response = self.client.post(url, data, format='json')
        
#         self.assertEqual(response.status_code, status.HTTP_201_CREATED)
#         self.assertIn('token', response.data)
#         self.assertEqual(User.objects.count(), 1)
#         self.assertEqual(User.objects.get().email, 'testuser@example.com')

#     def test_passwords_do_not_match(self):
#         url = reverse('register')
#         data = {
#             'email': 'testuser@example.com',
#             'name': 'Test User',
#             'password': 'Testpass123',
#             'password2': 'DifferentPass123',
#             'tc': True
#         }
#         response = self.client.post(url, data, format='json')
        
#         self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
#         self.assertIn('Passwords must match', response.data['non_field_errors'])

#     def test_missing_required_fields(self):
#         url = reverse('register')
#         data = {
#             'email': 'testuser@example.com',
#             # 'name': 'Test User', # Missing name
#             'password': 'Testpass123',
#             'password2': 'Testpass123',
#             'tc': True
#         }
#         response = self.client.post(url, data, format='json')
        
#         self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
#         self.assertIn('name', response.data)



# class UserLoginTests(APITestCase):

#     def setUp(self):
#         # Create a test user using the custom User model
#         self.user = User.objects.create_user(
#             email='testuser@example.com',
#             name='Test User',
#             tc=True,
#             password='Testpass123'
#         )
#         self.url = reverse('login')
    
#     def test_successful_login(self):
#         data = {
#             'email': 'testuser@example.com',
#             'password': 'Testpass123',
#         }
#         response = self.client.post(self.url, data, format='json')
        
#         self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
#         self.assertIn('token', response.data, response.data)
#         self.assertEqual(response.data['msg'], 'Login Successful', response.data)

#     def test_invalid_credentials(self):
#         data = {
#             'email': 'testuser@example.com',
#             'password': 'WrongPassword',
#         }
#         response = self.client.post(self.url, data, format='json')
        
#         self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED, response.data)
#         self.assertIn('errors', response.data, response.data)
#         self.assertIn('non_field_errors', response.data['errors'], response.data)
#         self.assertEqual(response.data['errors']['non_field_errors'], ['Email or password is not valid'], response.data)

#     def test_missing_email(self):
#         data = {
#             'password': 'Testpass123',
#         }
#         response = self.client.post(self.url, data, format='json')
        
#         self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, response.data)
#         self.assertIn('email', response.data, response.data)

#     def test_missing_password(self):
#         data = {
#             'email': 'testuser@example.com',
#         }
#         response = self.client.post(self.url, data, format='json')
        
#         self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, response.data)
#         self.assertIn('password', response.data, response.data)
        

# class UserProfileTests(APITestCase):
    
#     def setUp(self):
#         self.user = User.objects.create_user(
#             email='testuser@example.com',
#             name='Test User',
#             password='Testpass123',
#             tc=True
#         )
#         self.url = reverse('profile')
#         self.token = self.get_token_for_user(self.user)

#     def get_token_for_user(self, user):
#         refresh = RefreshToken.for_user(user)
#         return str(refresh.access_token)
    
#     def test_get_user_profile_success(self):
#         self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.token)
#         response = self.client.get(self.url)
        
#         self.assertEqual(response.status_code, status.HTTP_200_OK)
#         self.assertEqual(response.data['email'], self.user.email)
#         self.assertEqual(response.data['name'], self.user.name)
    
#     def test_get_user_profile_unauthorized(self):
#         response = self.client.get(self.url)
        
#         self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
#         self.assertIn('detail', response.data)
#         self.assertEqual(response.data['detail'], 'Authentication credentials were not provided.')
        
# class UserChangePasswordTests(APITestCase):
    
#     def setUp(self):
#         self.user = User.objects.create_user(
#             email='testuser@example.com',
#             name='Test User',
#             password='Testpass123',
#             tc=True
#         )
#         self.url = reverse('change-password')
#         self.token = self.get_token_for_user(self.user)
        
#     def get_token_for_user(self, user):
#         refresh = RefreshToken.for_user(user)
#         return str(refresh.access_token)
    
#     def test_change_password_success(self):
#         self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.token)
#         data = {
#             'password': 'NewTestpass123',
#             'password2': 'NewTestpass123'
#         }
#         response = self.client.post(self.url, data, format='json')
        
#         self.assertEqual(response.status_code, status.HTTP_200_OK)
#         self.assertEqual(response.data['msg'], 'Password changed successfully')
        
#         # Verify that the password was updated
#         self.user.refresh_from_db()
#         self.assertTrue(self.user.check_password('NewTestpass123'))
    
#     def test_passwords_do_not_match(self):
#         self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.token)
#         data = {
#             'password': 'NewTestpass123',
#             'password2': 'DifferentPass123'
#         }
#         response = self.client.post(self.url, data, format='json')
        
#         self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
#         self.assertIn('password2', response.data)
#         self.assertEqual(response.data['password2'][0], 'passwords must match')
    
#     def test_missing_required_fields(self):
#         self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.token)
#         data = {
#             # Missing 'password2'
#             'password': 'NewTestpass123',
#         }
#         response = self.client.post(self.url, data, format='json')
        
#         self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
#         self.assertIn('password2', response.data)
#         self.assertEqual(response.data['password2'][0], 'This field is required.')
        
  
class UserDeleteTests(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            email='testuser@example.com',
            name='Test User',
            password='Testpass123',
            tc=True
        )
        self.url = reverse('user-delete')
        self.token = self.get_token_for_user(self.user)
        self.refresh_token = self.get_refresh_token_for_user(self.user)
        
    def get_token_for_user(self, user):
        refresh = RefreshToken.for_user(user)
        return str(refresh.access_token)
    
    def get_refresh_token_for_user(self, user):
        refresh = RefreshToken.for_user(user)
        return str(refresh)
    
    def test_delete_user_success(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.token)
        data = {
            'refresh_token': self.refresh_token
        }
        response = self.client.delete(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(response.data['msg'], 'User account deleted successfully')
        
        # Verify that the user has been deleted
        self.assertFalse(User.objects.filter(email='testuser@example.com').exists())
    
    def test_delete_user_with_invalid_token(self):
        invalid_refresh_token = 'invalid_token'
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.token)
        data = {
            'refresh_token': invalid_refresh_token
        }
        response = self.client.delete(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertTrue('Invalid token' in response.data['error'])
    
    def test_delete_user_without_refresh_token(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.token)
        response = self.client.delete(self.url, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(response.data['msg'], 'User account deleted successfully')
        
        # Verify that the user has been deleted
        self.assertFalse(User.objects.filter(email='testuser@example.com').exists())
        

class UserUpdateTests(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            email='testuser@example.com',
            name='Test User',
            password='Testpass123',
            tc=True
        )
        self.url = reverse('user-update')
        self.token = self.get_token_for_user(self.user)
        
    def get_token_for_user(self, user):
        # Generate a JWT access token for the user
        from rest_framework_simplejwt.tokens import RefreshToken
        refresh = RefreshToken.for_user(user)
        return str(refresh.access_token)
    
    def test_update_user_success(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.token)
        data = {
            'name': 'Updated Name',
            'email': 'updateduser@example.com'
        }
        response = self.client.put(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['msg'], 'Profile updated successfully')
        
        # Verify that the user data has been updated
        user = User.objects.get(email='updateduser@example.com')
        self.assertEqual(user.name, 'Updated Name')
    
    def test_update_user_invalid_email(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.token)
        data = {
            'email': 'invalidemail'
        }
        response = self.client.put(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data['errors'])
    
    def test_update_user_existing_email(self):
        existing_user = User.objects.create_user(
            email='existinguser@example.com',
            name='Existing User',
            password='Testpass123',
            tc=True
        )
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.token)
        data = {
            'email': 'existinguser@example.com'
        }
        response = self.client.put(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data['errors'])
        

class LogoutTests(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            email='testuser@example.com',
            name='Test User',
            password='Testpass123',
            tc=True
        )
        self.url = reverse('logout')  # Update this with the correct URL name
        self.token = self.get_token_for_user(self.user)

    def get_token_for_user(self, user):
        # Generate a JWT access token and refresh token for the user
        refresh = RefreshToken.for_user(user)
        return str(refresh)

    def test_logout_success(self):
        # Make sure we have a valid refresh token
        refresh_token = self.get_token_for_user(self.user)
        
        response = self.client.post(self.url, {'refresh_token': refresh_token}, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_205_RESET_CONTENT)
        self.assertEqual(response.data['message'], 'Successfully logged out.')

    def test_logout_missing_token(self):
        response = self.client.post(self.url, {}, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        
    def test_logout_invalid_token(self):
        invalid_token = 'invalid_token'
        response = self.client.post(self.url, {'refresh_token': invalid_token}, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        
        
class UserPasswordResetTests(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            email='testuser@example.com',
            name='Test User',
            password='Testpass123',
            tc=True
        )
        self.url = reverse('password-reset')  # Update this with the correct URL name
        
        # Generate reset token and uid for the user
        self.uid = urlsafe_base64_encode(force_bytes(self.user.pk))
        self.token = default_token_generator.make_token(self.user)

    def test_password_reset_success(self):
        data = {
            'password': 'NewPassword123',
            'password2': 'NewPassword123',
        }
        response = self.client.post(self.url, data, format='json', 
                                    HTTP_UID=self.uid, HTTP_TOKEN=self.token)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['msg'], 'Password reset successful')

    def test_password_reset_invalid_data(self):
        data = {
            'password': 'NewPassword123',
            'password2': 'DifferentPassword',
        }
        response = self.client.post(self.url, data, format='json',
                                    HTTP_UID=self.uid, HTTP_TOKEN=self.token)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('non_field_errors', response.data)

    def test_password_reset_invalid_uid_or_token(self):
        invalid_uid = 'invalid_uid'
        invalid_token = 'invalid_token'
        
        data = {
            'password': 'NewPassword123',
            'password2': 'NewPassword123',
        }
        
        response = self.client.post(self.url, data, format='json',
                                    HTTP_UID=invalid_uid, HTTP_TOKEN=invalid_token)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)