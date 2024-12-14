from django.urls import path
from .views import (hello_world, UserRegistrationView, UserLoginView,
                    FileListView, FileUploadView, FileDownloadView, ShareFileView,
                    GetPublicKeyView, GetEncryptedAESKeyView,)

urlpatterns = [
    path('hello/', hello_world, name='hello_world'),
    path('register/', UserRegistrationView.as_view(), name='user_registration'),
    path('login/', UserLoginView.as_view(), name='user_login'),
    path('files/', FileListView.as_view(), name='file_list'),
    path('upload/', FileUploadView.as_view(), name='file_upload'),
    path('files/<int:file_id>/download/', FileDownloadView.as_view(), name='file_download'),
    path('share/', ShareFileView.as_view(), name='share_file'),
    path('public_key/<str:username>/', GetPublicKeyView.as_view(), name='get_public_key'),
    path('get_encrypted_aes_key/<int:file_id>/', GetEncryptedAESKeyView.as_view(), name='get_encrypted_aes_key'),

]