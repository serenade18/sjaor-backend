# This is an auto-generated Django model module.
# You'll have to do the following manually to clean this up:
#   * Rearrange models' order
#   * Make sure each model has one field with primary_key=True
#   * Make sure each ForeignKey and OneToOneField has `on_delete` set to the desired behavior
#   * Remove `managed = False` lines if you wish to allow Django to create, modify, and delete the table
# Feel free to rename the models, but don't rename db_table values or field names.
from django.db import models


class AboutUs(models.Model):
    id = models.BigAutoField(primary_key=True)
    title = models.CharField(max_length=255)
    body = models.TextField()
    image = models.CharField(max_length=255)
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'about_us'


class Adusums(models.Model):
    fullname = models.CharField(max_length=255)
    username = models.CharField(unique=True, max_length=255)
    date_of_birth = models.TextField()
    date_of_entry = models.TextField()
    name_of_provincial = models.CharField(max_length=255)
    current_community = models.CharField(max_length=255)
    password = models.CharField(max_length=255)
    remember_token = models.CharField(max_length=100, blank=True, null=True)
    status = models.IntegerField(blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)
    profile_picture = models.CharField(max_length=255)
    email_address = models.CharField(max_length=255)
    resetcode = models.TextField()

    class Meta:
        managed = False
        db_table = 'adusums'


class Archivum(models.Model):
    id = models.BigAutoField(primary_key=True)
    avm_title = models.CharField(max_length=255)
    avm_body = models.TextField()
    avm_picture = models.TextField()
    avm_video = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField()
    updated_at = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'archivum'


class Catalogues(models.Model):
    catalogue_name = models.CharField(max_length=255)
    catalogue_file = models.TextField()
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'catalogues'


class Categories(models.Model):
    parent = models.ForeignKey('self', models.DO_NOTHING, blank=True, null=True)
    order = models.IntegerField()
    name = models.CharField(max_length=255)
    slug = models.CharField(unique=True, max_length=255)
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'categories'


class DataRows(models.Model):
    data_type = models.ForeignKey('DataTypes', models.DO_NOTHING)
    field = models.CharField(max_length=255)
    type = models.CharField(max_length=255)
    display_name = models.CharField(max_length=255)
    required = models.IntegerField()
    browse = models.IntegerField()
    read = models.IntegerField()
    edit = models.IntegerField()
    add = models.IntegerField()
    delete = models.IntegerField()
    details = models.TextField(blank=True, null=True)
    order = models.IntegerField()

    class Meta:
        managed = False
        db_table = 'data_rows'


class DataTypes(models.Model):
    name = models.CharField(unique=True, max_length=255)
    slug = models.CharField(unique=True, max_length=255)
    display_name_singular = models.CharField(max_length=255)
    display_name_plural = models.CharField(max_length=255)
    icon = models.CharField(max_length=255, blank=True, null=True)
    model_name = models.CharField(max_length=255, blank=True, null=True)
    policy_name = models.CharField(max_length=255, blank=True, null=True)
    controller = models.CharField(max_length=255, blank=True, null=True)
    description = models.CharField(max_length=255, blank=True, null=True)
    generate_permissions = models.IntegerField()
    server_side = models.IntegerField()
    details = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'data_types'


class Documents(models.Model):
    document_name = models.CharField(max_length=255)
    document_file = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)
    category = models.CharField(max_length=255)

    class Meta:
        managed = False
        db_table = 'documents'


class Events(models.Model):
    event_name = models.TextField()
    event_day = models.TextField(blank=True, null=True)
    event_month = models.TextField(blank=True, null=True)
    event_month_number = models.IntegerField()
    event_year = models.TextField(blank=True, null=True)  # This field type is a guess.
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)
    event_image = models.TextField(blank=True, null=True)
    event_date = models.CharField(max_length=255, blank=True, null=True)
    event_location = models.CharField(max_length=255, blank=True, null=True)
    event_description = models.TextField(blank=True, null=True)
    event_type = models.CharField(max_length=20, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'events'


class Examens(models.Model):
    id = models.BigAutoField(primary_key=True)
    title = models.CharField(max_length=255)
    body = models.TextField()
    image = models.CharField(max_length=255)
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'examens'


class FailedJobs(models.Model):
    id = models.BigAutoField(primary_key=True)
    uuid = models.CharField(unique=True, max_length=255)
    connection = models.TextField()
    queue = models.TextField()
    payload = models.TextField()
    exception = models.TextField()
    failed_at = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'failed_jobs'


class Headers(models.Model):
    id = models.BigAutoField(primary_key=True)
    heading = models.CharField(max_length=255)
    title = models.TextField()
    subtitle = models.TextField()
    image = models.CharField(max_length=255)
    month = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)
    tag = models.CharField(max_length=255)

    class Meta:
        managed = False
        db_table = 'headers'


class IgnatianThoughts(models.Model):
    thought_month = models.CharField(max_length=255)
    thought_day = models.IntegerField()
    thought_item = models.TextField()

    class Meta:
        managed = False
        db_table = 'ignatian_thoughts'


class Joins(models.Model):
    id = models.BigAutoField(primary_key=True)
    title = models.CharField(max_length=255, blank=True, null=True)
    body = models.TextField()
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)
    image = models.CharField(max_length=255, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'joins'


class MenuItems(models.Model):
    menu = models.ForeignKey('Menus', models.DO_NOTHING, blank=True, null=True)
    title = models.CharField(max_length=255)
    url = models.CharField(max_length=255)
    target = models.CharField(max_length=255)
    icon_class = models.CharField(max_length=255, blank=True, null=True)
    color = models.CharField(max_length=255, blank=True, null=True)
    parent_id = models.IntegerField(blank=True, null=True)
    order = models.IntegerField()
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)
    route = models.CharField(max_length=255, blank=True, null=True)
    parameters = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'menu_items'


class Menus(models.Model):
    name = models.CharField(unique=True, max_length=255)
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'menus'


class Migrations(models.Model):
    migration = models.CharField(max_length=255)
    batch = models.IntegerField()

    class Meta:
        managed = False
        db_table = 'migrations'


class News(models.Model):
    title = models.CharField(max_length=255)
    image = models.TextField()
    body = models.TextField()
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'news'


class Ordersanddonations(models.Model):
    fullname = models.CharField(max_length=200)
    email = models.CharField(max_length=100)
    phonenumber = models.TextField()
    description = models.TextField()

    class Meta:
        managed = False
        db_table = 'ordersanddonations'


class PasswordResets(models.Model):
    email = models.CharField(max_length=255)
    token = models.CharField(max_length=255)
    created_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'password_resets'


class PermissionRole(models.Model):
    permission = models.OneToOneField('Permissions', models.DO_NOTHING, primary_key=True)  # The composite primary key (permission_id, role_id) found, that is not supported. The first column is selected.
    role = models.ForeignKey('Roles', models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'permission_role'
        unique_together = (('permission', 'role'),)


class Permissions(models.Model):
    id = models.BigAutoField(primary_key=True)
    key = models.CharField(max_length=255)
    table_name = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'permissions'


class PopesPrayerIntentions(models.Model):
    prayer_month = models.CharField(max_length=255, blank=True, null=True)
    prayer_year = models.TextField(blank=True, null=True)  # This field type is a guess.
    prayer_name = models.CharField(max_length=255, blank=True, null=True)
    prayer_item = models.TextField(blank=True, null=True)
    prayer_image = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'popes_prayer_intentions'


class Posts(models.Model):
    author_id = models.IntegerField()
    category_id = models.IntegerField(blank=True, null=True)
    title = models.CharField(max_length=255)
    seo_title = models.CharField(max_length=255, blank=True, null=True)
    excerpt = models.TextField(blank=True, null=True)
    body = models.TextField()
    image = models.CharField(max_length=255, blank=True, null=True)
    slug = models.CharField(unique=True, max_length=255)
    meta_description = models.TextField(blank=True, null=True)
    meta_keywords = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=9)
    featured = models.IntegerField()
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'posts'


class Prayers(models.Model):
    id = models.BigAutoField(primary_key=True)
    title = models.CharField(max_length=255)
    body = models.TextField()
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'prayers'


class Products(models.Model):
    product_image = models.TextField()
    product_description = models.CharField(max_length=255, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'products'


class Roles(models.Model):
    id = models.BigAutoField(primary_key=True)
    name = models.CharField(unique=True, max_length=255)
    display_name = models.CharField(max_length=255)
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'roles'


class Settings(models.Model):
    key = models.CharField(unique=True, max_length=255)
    display_name = models.CharField(max_length=255)
    value = models.TextField(blank=True, null=True)
    details = models.TextField(blank=True, null=True)
    type = models.CharField(max_length=255)
    order = models.IntegerField()
    group = models.CharField(max_length=255, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'settings'


class SjaorappShukran(models.Model):
    shukran_name = models.CharField(max_length=255)
    shukran_year = models.CharField(max_length=255)
    shukran_file = models.CharField(max_length=100, blank=True, null=True)
    added_on = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'sjaorapp_shukran'


class Supports(models.Model):
    id = models.BigAutoField(primary_key=True)
    title = models.CharField(max_length=255)
    body = models.TextField()
    image = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'supports'


class Translations(models.Model):
    table_name = models.CharField(max_length=255)
    column_name = models.CharField(max_length=255)
    foreign_key = models.PositiveIntegerField()
    locale = models.CharField(max_length=255)
    value = models.TextField()
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'translations'
        unique_together = (('table_name', 'column_name', 'foreign_key', 'locale'),)


class Uaps(models.Model):
    id = models.BigAutoField(primary_key=True)
    title = models.CharField(max_length=255)
    body = models.TextField()
    image = models.CharField(max_length=255)
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'uaps'


class UserRoles(models.Model):
    user = models.OneToOneField('Users', models.DO_NOTHING, primary_key=True)  # The composite primary key (user_id, role_id) found, that is not supported. The first column is selected.
    role = models.ForeignKey(Roles, models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'user_roles'
        unique_together = (('user', 'role'),)


class Users(models.Model):
    id = models.BigAutoField(primary_key=True)
    role = models.ForeignKey(Roles, models.DO_NOTHING, blank=True, null=True)
    name = models.CharField(max_length=255)
    email = models.CharField(unique=True, max_length=255)
    avatar = models.CharField(max_length=255, blank=True, null=True)
    email_verified_at = models.DateTimeField(blank=True, null=True)
    password = models.CharField(max_length=255)
    remember_token = models.CharField(max_length=100, blank=True, null=True)
    settings = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'users'
