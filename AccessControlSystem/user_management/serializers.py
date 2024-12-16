from django.contrib.auth.models import User, Group, Permission
from rest_framework import serializers
from .models import AuditLog

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)  # Make the password write-only

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'password', 'groups']

    def create(self, validated_data):
        # Ensure the password is hashed before saving the user
        password = validated_data.pop('password', None)
        user = User(**validated_data)
        if password:
            user.set_password(password)  # Hash the password
        user.save()
        return user


class GroupSerializer(serializers.ModelSerializer):
    permissions = serializers.SlugRelatedField(
        queryset=Permission.objects.all(), 
        slug_field='codename', 
        many=True
    )

    class Meta:
        model = Group
        fields = ['id', 'name', 'permissions']

class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ['id', 'name', 'codename', 'content_type']

class AuditLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuditLog
        fields = ['user', 'action', 'outcome', 'timestamp', 'details']