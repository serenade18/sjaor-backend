# Generated by Django 4.2.1 on 2024-02-14 12:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('sjaorApp', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Necrology',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=255)),
                ('month', models.CharField(max_length=255)),
                ('year', models.CharField(max_length=255)),
                ('file', models.ImageField(blank=True, null=True, upload_to='necrologies/')),
                ('added_on', models.DateTimeField(auto_now_add=True)),
            ],
        ),
    ]