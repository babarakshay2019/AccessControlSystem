from django.db import models
from django.contrib.auth.models import User

class AuditLog(models.Model):
    ACTION_CHOICES = [
        ('create', 'Create'),
        ('update', 'Update'),
        ('delete', 'Delete'),
        ('assign_role', 'Assign Role'),
        ('assign_permission', 'Assign Permission'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE)  
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    outcome = models.CharField(max_length=10, choices=[('granted', 'Granted'), ('denied', 'Denied')])
    timestamp = models.DateTimeField(auto_now_add=True) 
    details = models.TextField(null=True, blank=True)     
    class Meta:
        ordering = ['-timestamp'] 
    
    def __str__(self):
        return f'{self.user.username} performed {self.action} ({self.outcome})'

