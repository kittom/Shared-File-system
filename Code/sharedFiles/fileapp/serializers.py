from rest_framework import serializers
from .models import CustomUser
from django.contrib.auth.hashers import make_password
from .models import File

class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['username', 'password', 'public_key']

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = CustomUser(**validated_data)
        user.password = make_password(password)
        user.save()
        return user
    
class FileSerializer(serializers.ModelSerializer):
    owner = serializers.StringRelatedField(read_only=True)  # Add this line

    class Meta:
        model = File
        fields = ['id', 'filename', 'upload_date', 'file', 'owner']
        read_only_fields = ['id', 'upload_date', 'owner']
        extra_kwargs = {'file': {'write_only': True}}