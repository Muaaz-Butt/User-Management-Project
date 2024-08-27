from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser
from django.utils import timezone
from django.conf import settings

class MyUserManager(BaseUserManager):
    def create_user(self, email, name, tc, password=None, password2=None):
        """
        Creates and saves a User with the given email, name, tc and password.
        """
        if not email:
            raise ValueError("Users must have an email address")

        user = self.model(
            email=self.normalize_email(email),
            name=name,
            tc=tc,
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, tc, password=None):
       
        user = self.create_user(
            email,
            password=password,
            name=name,
            tc = tc,
        )
        user.is_admin = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    email = models.EmailField(
        verbose_name="email",
        max_length=255,
        unique=True,
    )
    name = models.CharField(max_length=255)
    tc = models.BooleanField()
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = MyUserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name", "tc"]

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return self.is_admin

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_admin
      
class LoginAttempt(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    successful = models.BooleanField(default=False)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    is_locked_out = models.BooleanField(default=False)

    def __str__(self):
        return f'Login attempt by {self.user.email} on {self.timestamp}'

    class Meta:
        ordering = ['-timestamp']

    @classmethod
    def get_recent_attempts(cls, user, minutes=30):
        cutoff_time = timezone.now() - timezone.timedelta(minutes=minutes)
        return cls.objects.filter(user=user, timestamp__gt=cutoff_time, successful=False)

class LoginSettings(models.Model):
    max_attempts = models.PositiveIntegerField(default=5)
    lockout_duration = models.PositiveIntegerField(default=7)  # in minutes

    def __str__(self):
        return f'Login settings: max attempts: {self.max_attempts}, lockout duration: {self.lockout_duration} minutes'

    @classmethod
    def get_settings(cls):
        return cls.objects.first() or cls.objects.create()