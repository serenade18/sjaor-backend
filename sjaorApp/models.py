from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager


class UserAccountManager(BaseUserManager):
    def create_user(self, email, first_name, last_name, phone, password=None, user_type=None):
        if not email:
            raise ValueError('Users must have an email address')

        email = self.normalize_email(email)
        email = email.lower()

        user = self.model(
            email=email,
            first_name=first_name,
            last_name=last_name,
            user_type=user_type,
            phone=phone
        )

        user.set_password(password)
        user.save(using=self._db)

        return user

    def create_superuser(self, email, first_name,  last_name, phone, user_type=None, password=None):
        user = self.create_user(email, first_name, last_name, phone, user_type, password)

        user.is_superuser = True
        user.is_staff = True

        user.save(using=self._db)

        return user


class UserAccount(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(max_length=255, unique=True)
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    phone = models.CharField(max_length=255)
    user_type = models.CharField(max_length=20, default='normal')
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = UserAccountManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name', 'phone', 'user_type']

    def __str__(self):
        return self.email


class News(models.Model):
    id = models.AutoField(primary_key=True)
    image = models.ImageField(upload_to='news/', null=True, blank=True)
    title = models.CharField(max_length=100)
    body = models.TextField()
    author = models.TextField(max_length=255, null=True, blank=True)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()


class PopesPrayerIntentions(models.Model):
    id = models.AutoField(primary_key=True)
    prayer_month = models.CharField(max_length=255)
    prayer_year = models.CharField(max_length=255)
    prayer_name = models.CharField(max_length=255)
    prayer_item = models.CharField(max_length=255)
    prayer_image = models.ImageField(upload_to='popes-prayer-intentions/', null=True, blank=True)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()


class Catalogues(models.Model):
    id = models.AutoField(primary_key=True)
    catalogue_name = models.CharField(max_length=255)
    catalogue_file = models.FileField(upload_to='catalogues/', null=True, blank=True)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()


class IgnatianThoughts(models.Model):
    id = models.AutoField(primary_key=True)
    thought_month = models.CharField(max_length=255)
    thought_day = models.CharField(max_length=255)
    thought_item = models.CharField(max_length=255)
    objects = models.Manager()


class DocumentCategory(models.Model):
    id = models.AutoField(primary_key=True)
    category = models.CharField(max_length=255)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()


class Documents(models.Model):
    id = models.AutoField(primary_key=True)
    document_name = models.CharField(max_length=255)
    document_file = models.FileField(upload_to='documents/', null=True, blank=True)
    document_category = models.ForeignKey(DocumentCategory, on_delete=models.CASCADE, default=None)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()


class EventCategory(models.Model):
    id = models.AutoField(primary_key=True)
    category = models.CharField(max_length=255)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()


class Events(models.Model):
    id = models.AutoField(primary_key=True)
    event_name = models.CharField(max_length=255)
    event_category = models.ForeignKey(EventCategory, on_delete=models.CASCADE,default=None)
    event_day = models.CharField(max_length=255)
    event_month = models.CharField(max_length=255)
    event_year = models.CharField(max_length=255)
    event_month_number = models.CharField(max_length=255)
    event_location = models.CharField(max_length=255)
    event_description = models.CharField(max_length=255)
    event_image = models.ImageField(upload_to='events/', null=True, blank=True)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()


class Shukran(models.Model):
    id = models.AutoField(primary_key=True)
    shukran_name = models.CharField(max_length=255)
    shukran_year = models.CharField(max_length=255)
    shukran_file = models.FileField(upload_to='shukran/', null=True, blank=True)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()


class Adusums(models.Model):
    id = models.AutoField(primary_key=True)
    fullname = models.CharField(max_length=255, default=None)
    username = models.CharField(max_length=255)
    email_address = models.EmailField(max_length=255, unique=True)
    date_of_birth = models.CharField(max_length=255)
    date_of_entry = models.CharField(max_length=255)
    name_of_provincial = models.CharField(max_length=255)
    current_community = models.CharField(max_length=255)
    profile_picture = models.FileField(upload_to='profilepictures/', null=True, blank=True)
    status = models.BooleanField(default=0)
    password = models.CharField(max_length=255)
    remember_token = models.CharField(max_length=255, null=True, blank=True)
    resetcode = models.CharField(max_length=255, null=True, blank=True)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()


class Products(models.Model):
    id = models.AutoField(primary_key=True)
    product_title = models.CharField(max_length=255)
    product_image = models.ImageField(upload_to='products/', null=True, blank=True)
    product_description = models.CharField(max_length=255)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()


class Archivum(models.Model):
    id = models.AutoField(primary_key=True)
    avm_title = models.CharField(max_length=255)
    avm_body = models.TextField()
    avm_picture = models.ImageField(upload_to='archivum/', blank=True, null=True)
    avm_video = models.CharField(max_length=12255, blank=True, null=True)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()
