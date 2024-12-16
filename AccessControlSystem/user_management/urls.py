from rest_framework.routers import DefaultRouter
from django.urls import path, include
from .views import UserViewSet, GroupViewSet, PermissionViewSet,AuditLogViewSet

router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'roles', GroupViewSet, basename='role')
router.register(r'permissions', PermissionViewSet, basename='permission')
router.register(r'audit', AuditLogViewSet, basename='audit')

urlpatterns = [
    path('', include(router.urls)),
]