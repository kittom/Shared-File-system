from django.contrib.auth.models import AbstractUser
from django.db import models
from django.conf import settings

class CustomUser(AbstractUser):
    public_key = models.TextField(null=True, blank=True)
    # Add any additional fields if needed

def user_directory_path(instance, filename):
    return f'user_{instance.owner.id}/{filename}'

class File(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    file = models.FileField(upload_to=user_directory_path)
    filename = models.CharField(max_length=255)
    upload_date = models.DateTimeField(auto_now_add=True)
    encrypted_aes_key = models.BinaryField()  # Add this field

    def __str__(self):
        return self.filename

class SharedFile(models.Model):
    file = models.ForeignKey('File', on_delete=models.CASCADE)
    shared_with = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    encrypted_aes_key = models.BinaryField()

    def __str__(self):
        return f"{self.file.filename} shared with {self.shared_with.username}"