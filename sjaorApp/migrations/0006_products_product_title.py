# Generated by Django 4.2.1 on 2024-01-28 09:54

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('sjaorApp', '0005_alter_archivum_avm_video'),
    ]

    operations = [
        migrations.AddField(
            model_name='products',
            name='product_title',
            field=models.CharField(default=0, max_length=255),
            preserve_default=False,
        ),
    ]