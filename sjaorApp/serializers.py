from djoser.serializers import UserCreateSerializer, UserSerializer
from django.contrib.auth import get_user_model
from rest_framework import serializers
from django.utils import timezone
from django.utils.timezone import make_aware

from sjaorApp.models import News, PopesPrayerIntentions, Catalogues, IgnatianThoughts, Documents, EventCategory, Events, \
    Shukran, Adusums, Products, DocumentCategory

User = get_user_model()


class UserCreateSerializer(UserCreateSerializer):
    user_type = serializers.CharField(default='normal', required=False)  # Add user_type field with default value

    class Meta(UserCreateSerializer.Meta):
        model = User
        fields = '__all__'  # Include user_type in fields

    def validate(self, attrs):
        attrs = super().validate(attrs)

        user_type = attrs.get('user_type')
        if user_type not in ['normal', 'admin']:  # Make sure user_type is either 'normal' or 'admin'
            raise serializers.ValidationError("Invalid user type")

        return attrs


class CustomUserSerializer(UserSerializer):
    last_login = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)

    class Meta(UserSerializer.Meta):
        fields = ('id', 'email', 'first_name', 'last_name', 'phone', 'last_login')

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        last_login = representation.get('last_login')

        if last_login:
            if isinstance(last_login, str):
                # If last_login is a string, try to parse it into a datetime object
                last_login = timezone.make_aware(timezone.datetime.fromisoformat(last_login))

            if not timezone.is_aware(last_login):
                # If it's still not aware, assume it's in the default timezone
                last_login = make_aware(last_login, timezone.get_current_timezone())

            formatted_last_login = timezone.localtime(last_login).strftime('%Y-%m-%d %H:%M:%S')
            representation['last_login'] = formatted_last_login

        return representation


class UserAccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

    def update(self, instance, validated_data):
        # Allow admins to update name and phone without email uniqueness check
        if self.context['request'].user.is_staff:
            instance.first_name = validated_data.get('first_name', instance.first_name)
            instance.last_name = validated_data.get('last_name', instance.last_name)
            instance.phone = validated_data.get('phone', instance.phone)
        else:
            # For regular users, update all fields
            instance.first_name = validated_data.get('first_name', instance.first_name)
            instance.last_name = validated_data.get('last_name', instance.last_name)
            instance.email = validated_data.get('email', instance.email)
            instance.phone = validated_data.get('phone', instance.phone)

        instance.save()
        return instance


class NewsSerializer(serializers.ModelSerializer):
    class Meta:
        model = News
        fields = '__all__'

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        return representation


class PopesPrayerIntentionsSerializer(serializers.ModelSerializer):
    class Meta:
        model = PopesPrayerIntentions
        fields = '__all__'

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        return representation


class CataloguesSerializer(serializers.ModelSerializer):
    class Meta:
        model = Catalogues
        fields = '__all__'

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        return representation


class IgnatianThoughtsSerializer(serializers.ModelSerializer):
    class Meta:
        model = IgnatianThoughts
        fields = '__all__'


class DocumentsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Documents
        fields = '__all__'

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        return representation


class EventCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = EventCategory
        fields = '__all__'


class EventsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Events
        fields = '__all__'

    def to_representation(self, instance):
        response = super().to_representation(instance)
        response["eventcategory"] = EventCategorySerializer(instance.eventcategory_id).data
        return response


class ShukranSerializer(serializers.ModelSerializer):
    class Meta:
        model = Shukran
        fields = '__all__'


class AdusumsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Adusums
        fields = '__all__'


class ProductsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Products
        fields = '__all__'


class DocumentCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = DocumentCategory
        fields = '__all__'


class DocumentSerializer(serializers.ModelSerializer): # Use the serializer here

    class Meta:
        model = Documents
        fields = '__all__'

    def to_representation(self, instance):
        response = super().to_representation(instance)
        response["documentcategory"] = DocumentCategorySerializer(instance.document_category).data
        return response

