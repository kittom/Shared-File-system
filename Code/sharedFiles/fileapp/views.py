# from django.shortcuts import render
from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny

from .serializers import UserRegistrationSerializer, FileSerializer
from .models import File, SharedFile

from django.contrib.auth import authenticate, get_user_model
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt


def hello_world(request):
    permission_classes = [AllowAny]
    return JsonResponse({'message': 'Hello from Django!'})


class UserRegistrationView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'User created successfully.'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
@method_decorator(csrf_exempt, name='dispatch')
class UserLoginView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(username=username, password=password)
        if user:
            # Create or retrieve a token for the user
            token, created = Token.objects.get_or_create(user=user)
            return Response({'token': token.key}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid credentials.'}, status=status.HTTP_400_BAD_REQUEST)
        

class FileListView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        # Files owned by the user
        own_files = File.objects.filter(owner=request.user)
        own_files_data = FileSerializer(own_files, many=True).data

        # Files shared with the user
        shared_files = SharedFile.objects.filter(shared_with=request.user)
        shared_files_list = [shared_file.file for shared_file in shared_files]
        shared_files_data = FileSerializer(shared_files_list, many=True).data

        # Mark shared files
        for file_data in shared_files_data:
            file_data['shared'] = True

        all_files_data = own_files_data + shared_files_data

        return Response(all_files_data, status=status.HTTP_200_OK)
    
class FileUploadView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        file_obj = request.FILES.get('file')
        filename = request.data.get('filename')
        encrypted_aes_key_hex = request.data.get('encrypted_aes_key')

        if not file_obj or not filename or not encrypted_aes_key_hex:
            return Response({'error': 'Incomplete data provided.'}, status=status.HTTP_400_BAD_REQUEST)

        # Convert encrypted AES key from hex to bytes
        encrypted_aes_key = bytes.fromhex(encrypted_aes_key_hex)

        # Save the file record in the database
        file_instance = File(
            owner=request.user,
            filename=filename,
            encrypted_aes_key=encrypted_aes_key
        )
        file_instance.file.save(filename, file_obj, save=True)

        return Response({'message': 'File uploaded successfully.'}, status=status.HTTP_201_CREATED)
    

class FileDownloadView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, file_id):
        try:
            # Check if the file belongs to the user
            file_instance = File.objects.get(id=file_id, owner=request.user)
            encrypted_aes_key = file_instance.encrypted_aes_key
        except File.DoesNotExist:
            # Check if the file is shared with the user
            try:
                shared_file = SharedFile.objects.get(file_id=file_id, shared_with=request.user)
                file_instance = shared_file.file
                encrypted_aes_key = shared_file.encrypted_aes_key
            except SharedFile.DoesNotExist:
                return Response({'error': 'File not found or access denied.'}, status=status.HTTP_404_NOT_FOUND)

        # Read the encrypted file
        with open(file_instance.file.path, 'rb') as f:
            encrypted_file_data = f.read()

        response_data = {
            'filename': file_instance.filename,
            'encrypted_file_data': encrypted_file_data.hex(),
            'encrypted_aes_key': encrypted_aes_key.hex(),
        }
        return Response(response_data, status=status.HTTP_200_OK)

class ShareFileView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        file_id = request.data.get('file_id')
        recipient_username = request.data.get('recipient_username')
        encrypted_aes_key_hex = request.data.get('encrypted_aes_key')

        if not file_id or not recipient_username or not encrypted_aes_key_hex:
            return Response({'error': 'Incomplete data provided.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            file_instance = File.objects.get(id=file_id, owner=request.user)
        except File.DoesNotExist:
            return Response({'error': 'File not found or access denied.'}, status=status.HTTP_404_NOT_FOUND)

        try:
            recipient = get_user_model().objects.get(username=recipient_username)
        except get_user_model().DoesNotExist:
            return Response({'error': 'Recipient user not found.'}, status=status.HTTP_404_NOT_FOUND)

        # Convert encrypted AES key from hex to bytes
        encrypted_aes_key = bytes.fromhex(encrypted_aes_key_hex)

        # Create a SharedFile instance
        SharedFile.objects.create(
            file=file_instance,
            shared_with=recipient,
            encrypted_aes_key=encrypted_aes_key
        )

        return Response({'message': 'File shared successfully.'}, status=status.HTTP_201_CREATED)
    

class GetPublicKeyView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, username):
        try:
            user = get_user_model().objects.get(username=username)
            public_key = user.public_key
            return Response({'public_key': public_key}, status=status.HTTP_200_OK)
        except get_user_model().DoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)


class GetEncryptedAESKeyView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, file_id):
        try:
            file_instance = File.objects.get(id=file_id, owner=request.user)
            encrypted_aes_key = file_instance.encrypted_aes_key
            return Response({'encrypted_aes_key': encrypted_aes_key.hex()}, status=status.HTTP_200_OK)
        except File.DoesNotExist:
            return Response({'error': 'File not found or access denied.'}, status=status.HTTP_404_NOT_FOUND)
