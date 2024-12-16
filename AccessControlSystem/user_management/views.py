from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.decorators import action
from django.utils import timezone
from datetime import timedelta
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet
from django.contrib.auth.models import User, Group, Permission
from .serializers import UserSerializer, GroupSerializer, PermissionSerializer,AuditLogSerializer
from rest_framework import  filters
from rest_framework.decorators import action
from django_filters.rest_framework import DjangoFilterBackend
from .models import AuditLog

class UserViewSet(ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def get_permissions(self):
        """Define custom permissions for different actions."""
        if self.action == 'create':
            # Allow anyone to create a user
            return [AllowAny()]
        elif self.action in ['update', 'partial_update']:
            if self.request.user.groups.filter(name='Staff').exists():
                return [IsAuthenticated()]  # Staff can only update user
            if self.request.user.groups.filter(name='Supervisor').exists() or self.request.user.is_staff:
                return [IsAuthenticated()]  # Supervisor and Admin can update user
        elif self.action in ['destroy']:
            return [IsAdminUser()]  # Only Admin can delete users
        return [IsAuthenticated()]  # Default permission for all other actions

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def assign_role(self, request, pk=None):
        """Assign a role to a user. Supervisor and Admin can assign roles."""
        user = self.get_object()
        role = request.data.get('role')
        group = Group.objects.filter(name=role).first()
        
        # Only Supervisor or Admin can assign roles
        if self.request.user.groups.filter(name='Supervisor').exists() or self.request.user.is_staff:
            if group:
                user.groups.add(group)
                return Response({'status': f'Role "{role}" assigned to user {user.username}'})
            return Response({'error': 'Invalid role'}, status=400)
        
        return Response({'error': 'Permission denied to assign role'}, status=403)


class GroupViewSet(ModelViewSet):
    queryset = Group.objects.all()
    serializer_class = GroupSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]

    filterset_fields = ['name']

    @action(detail=True, methods=['post'], permission_classes=[IsAdminUser])
    def assign_permission(self, request, pk=None):
        """Assign permission to a group. Admin only."""
        group = self.get_object()
        permission = request.data.get('permission')
        perm_obj = Permission.objects.filter(codename=permission).first()
        if perm_obj:
            group.permissions.add(perm_obj)
            return Response({'status': f'Permission "{permission}" assigned to group {group.name}'})
        return Response({'error': 'Invalid permission'}, status=400)


class PermissionViewSet(ModelViewSet):
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer
    permission_classes = [IsAuthenticated,IsAdminUser]

class AuditLogViewSet(ModelViewSet):
    queryset = AuditLog.objects.all()
    serializer_class = AuditLogSerializer

    def get_permissions(self):
        """Define custom permissions for different actions."""
        if self.action == 'create':
            # Allow any user to create a log (e.g., on login, action, etc.)
            return [AllowAny()]
        elif self.action in ['list', 'retrieve']:
            # Only allow admins to list and retrieve logs
            return [IsAdminUser()]
        return [IsAdminUser()]  # Default to admin for other actions

    # 3. **Custom Action to Filter Logs by Time Range**
    @action(detail=False, methods=['get'], permission_classes=[IsAdminUser])
    def filter_by_time(self, request):
        """Filter audit logs by a specified time range (e.g., past N hours)."""
        try:
            # Get the time range parameter (default to 24 hours if not provided)
            hours = int(request.query_params.get('hours', 24))
            time_threshold = timezone.now() - timedelta(hours=hours)
            
            # Filter the AuditLog based on the time threshold
            logs = AuditLog.objects.filter(timestamp__gte=time_threshold)

            # Serialize the filtered logs
            serializer = self.get_serializer(logs, many=True)
            return Response(serializer.data)

        except ValueError:
            return Response({'error': 'Invalid hours parameter'}, status=400)

    # Optionally override `create` method for custom behavior
    def create(self, request, *args, **kwargs):
        """Override the default create method if necessary."""
        # Log the action or modify details before saving the log
        response = super().create(request, *args, **kwargs)
        # Custom logging logic can be added here if needed
        return response