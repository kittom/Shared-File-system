# main_window.py

import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
    QLabel, QListWidget, QFileDialog, QMessageBox, QInputDialog, QLineEdit
)
from PyQt5.QtGui import QPixmap
from PyQt5.QtCore import Qt
import requests
from login_window import LoginWindow
from registration_window import RegistrationWindow

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

certificate = r'../certificate/cert.pem'

class ClientApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Varoa: The Secure File Sharing App')  # Updated window title
        self.token = None
        self.username = None
        self.init_ui()

    def init_ui(self):
        self.resize(600, 800)  # Set window size

        # Main layout
        self.layout = QVBoxLayout()

        # Logo
        logo_path = './assets/Logo.png'  # Path to your logo image
        self.logo_label = QLabel()
        pixmap = QPixmap(logo_path)
        if pixmap.isNull():
            print(f'Failed to load logo image from {logo_path}')
        else:
            scaled_pixmap = pixmap.scaledToWidth(200, Qt.SmoothTransformation)  # Adjust width as needed
            self.logo_label.setPixmap(scaled_pixmap)
            self.logo_label.setAlignment(Qt.AlignCenter)
            self.layout.addWidget(self.logo_label, alignment=Qt.AlignHCenter)

        # Welcome label
        self.label = QLabel('Welcome to Varoa.')
        self.label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(self.label)

        # Create a horizontal layout for the buttons
        self.button_layout = QHBoxLayout()

        self.register_button = QPushButton('Register')
        self.register_button.clicked.connect(self.open_registration)
        self.button_layout.addWidget(self.register_button)

        self.login_button = QPushButton('Login')
        self.login_button.clicked.connect(self.open_login)
        self.button_layout.addWidget(self.login_button)

        # Buttons that will be shown after login
        self.upload_button = QPushButton('Upload File')
        self.upload_button.clicked.connect(self.upload_file)
        self.upload_button.hide()
        self.button_layout.addWidget(self.upload_button)

        self.download_button = QPushButton('Download File')
        self.download_button.clicked.connect(self.download_file)
        self.download_button.hide()
        self.button_layout.addWidget(self.download_button)

        self.share_button = QPushButton('Share File')
        self.share_button.clicked.connect(self.share_file)
        self.share_button.hide()
        self.button_layout.addWidget(self.share_button)

        self.logout_button = QPushButton('Logout')
        self.logout_button.clicked.connect(self.logout)
        self.logout_button.hide()
        self.button_layout.addWidget(self.logout_button)

        # Add the button layout to the main layout
        self.layout.addLayout(self.button_layout)

        # Add File List
        self.file_list = QListWidget()
        self.file_list.hide()
        self.layout.addWidget(self.file_list)

        self.setLayout(self.layout)


    def open_registration(self):
        self.registration_window = RegistrationWindow()
        self.registration_window.show()

    def open_login(self):
        self.login_window = LoginWindow(parent=self)
        self.login_window.show()

    def update_ui_after_login(self):
        # Update the label to greet the user
        self.label.setText(f'Hello, {self.username}!')

        # Hide the login and register buttons
        self.register_button.hide()
        self.login_button.hide()

        # Show the other buttons
        self.upload_button.show()
        self.download_button.show()
        self.share_button.show()
        self.logout_button.show()

        # Show the file list
        self.file_list.show()

        # Fetch and display the list of files
        self.list_files()

    def list_files(self):
        headers = {
            'Authorization': f'Token {self.token}',
            'Content-Type': 'application/json'
        }
        try:
            response = requests.get(
                'https://127.0.0.1:8000/files/',
                headers=headers,
                verify=certificate
            )
            if response.status_code == 200:
                files = response.json()
                self.file_list.clear()
                self.file_ids = {}
                for file in files:
                    display_name = file['filename']
                    if file.get('shared'):
                        display_name += ' (Shared)'
                    self.file_list.addItem(display_name)
                    self.file_ids[display_name] = file['id']
            else:
                self.label.setText('Failed to retrieve files.')
        except Exception as e:
            self.label.setText(f'An error occurred: {e}')

    def upload_file(self):
        # Open file dialog to select a file
        file_path, _ = QFileDialog.getOpenFileName(self, 'Select File to Upload')
        if file_path:
            self.upload_file_to_server(file_path)

    def upload_file_to_server(self, file_path):
        # Load the user's public key
        try:
            with open(f'../user_keys/{self.username}_public_key.pem', 'rb') as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read()
                )
        except Exception as e:
            self.label.setText(f'Failed to load public key: {e}')
            return

        # Generate a random AES key
        aes_key = os.urandom(32)  # 256-bit key

        # Encrypt the file using AES
        try:
            with open(file_path, 'rb') as f:
                plaintext_data = f.read()
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
            encryptor = cipher.encryptor()
            encrypted_file_data = encryptor.update(plaintext_data) + encryptor.finalize()
            # Prefix IV to encrypted data
            encrypted_file_data = iv + encrypted_file_data
        except Exception as e:
            self.label.setText(f'Failed to encrypt file: {e}')
            return

        # Encrypt the AES key with the user's public key
        try:
            encrypted_aes_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            self.label.setText(f'Failed to encrypt AES key: {e}')
            return

        # Prepare data for upload
        filename = os.path.basename(file_path)
        headers = {
            'Authorization': f'Token {self.token}',
        }
        files = {
            'file': (filename, encrypted_file_data),
        }
        data = {
            'filename': filename,
            'encrypted_aes_key': encrypted_aes_key.hex(),
        }

        try:
            response = requests.post(
                'https://127.0.0.1:8000/upload/',
                headers=headers,
                files=files,
                data=data,
                verify=certificate
            )
            if response.status_code == 201:
                self.label.setText('File uploaded successfully.')
                self.list_files()  # Refresh the file list
            else:
                self.label.setText('Failed to upload file.')
        except Exception as e:
            self.label.setText(f'An error occurred: {e}')

    def share_file(self):
        selected_items = self.file_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, 'Error', 'Please select a file to share.')
            return

        filename = selected_items[0].text()
        file_id = self.file_ids.get(filename)

        if not file_id:
            QMessageBox.warning(self, 'Error', 'File ID not found.')
            return

        # Prompt for recipient's username
        recipient_username, ok = QInputDialog.getText(self, 'Share File', 'Enter the username of the recipient:')
        if not ok or not recipient_username:
            return

        headers = {
            'Authorization': f'Token {self.token}',
            'Content-Type': 'application/json',
        }

        # Retrieve recipient's public key
        try:
            response = requests.get(
                f'https://127.0.0.1:8000/public_key/{recipient_username}/',
                headers=headers,
                verify=certificate
            )
            if response.status_code == 200:
                public_key_pem = response.json().get('public_key').encode('utf-8')
                recipient_public_key = serialization.load_pem_public_key(public_key_pem)
            else:
                QMessageBox.warning(self, 'Error', f'User {recipient_username} not found.')
                return
        except Exception as e:
            QMessageBox.warning(self, 'Error', f'An error occurred while retrieving public key: {e}')
            return

        # Load the user's private key to decrypt the AES key
        try:
            # Update the path to match where your private keys are stored
            private_key_path = f'../user_keys/{self.username}_private_key.pem'
            with open(private_key_path, 'rb') as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None  # No passphrase if your key is unencrypted
                )
        except Exception as e:
            QMessageBox.warning(self, 'Error', f'Failed to load private key: {e}')
            return

        # Retrieve encrypted AES key from server
        try:
            response = requests.get(
                f'https://127.0.0.1:8000/get_encrypted_aes_key/{file_id}/',
                headers=headers,
                verify=certificate
            )
            if response.status_code == 200:
                encrypted_aes_key_hex = response.json().get('encrypted_aes_key')
                encrypted_aes_key = bytes.fromhex(encrypted_aes_key_hex)
            else:
                QMessageBox.warning(self, 'Error', 'Failed to retrieve encrypted AES key.')
                return
        except Exception as e:
            QMessageBox.warning(self, 'Error', f'An error occurred while retrieving AES key: {e}')
            return

        # Decrypt the AES key with the user's private key
        try:
            aes_key = private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            QMessageBox.warning(self, 'Error', f'Failed to decrypt AES key: {e}')
            return

        # Encrypt the AES key with the recipient's public key
        try:
            encrypted_aes_key_for_recipient = recipient_public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            QMessageBox.warning(self, 'Error', f'Failed to encrypt AES key for recipient: {e}')
            return

        # Send the sharing request to the server
        data = {
            'file_id': file_id,
            'recipient_username': recipient_username,
            'encrypted_aes_key': encrypted_aes_key_for_recipient.hex(),
        }

        try:
            response = requests.post(
                'https://127.0.0.1:8000/share/',
                headers=headers,
                json=data,
                verify=certificate
            )
            if response.status_code == 201:
                QMessageBox.information(self, 'Success', 'File shared successfully.')
            else:
                error_message = response.json().get('error', 'Unknown error.')
                QMessageBox.warning(self, 'Error', f'Failed to share file: {error_message}')
        except Exception as e:
            QMessageBox.warning(self, 'Error', f'An error occurred during sharing: {e}')

    def download_file(self):
        selected_items = self.file_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, 'Error', 'Please select a file to download.')
            return

        filename = selected_items[0].text()
        file_id = self.file_ids.get(filename)

        if not file_id:
            QMessageBox.warning(self, 'Error', 'File ID not found.')
            return

        headers = {
            'Authorization': f'Token {self.token}',
        }

        try:
            response = requests.get(
                f'https://127.0.0.1:8000/files/{file_id}/download/',
                headers=headers,
                verify=certificate
            )
            if response.status_code == 200:
                data = response.json()
                self.decrypt_and_save_file(data)
            else:
                QMessageBox.warning(self, 'Error', 'Failed to download file.')
        except Exception as e:
            QMessageBox.warning(self, 'Error', f'An error occurred: {e}')

    def decrypt_and_save_file(self, data):
        filename = data['filename']
        encrypted_file_data = bytes.fromhex(data['encrypted_file_data'])
        encrypted_aes_key = bytes.fromhex(data['encrypted_aes_key'])

        # Load the user's private key
        try:
            with open(f'../user_keys/{self.username}_private_key.pem', 'rb') as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                )
        except Exception as e:
            QMessageBox.warning(self, 'Error', f'Failed to load private key: {e}')
            return

        # Decrypt the AES key
        try:
            aes_key = private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            QMessageBox.warning(self, 'Error', f'Failed to decrypt AES key: {e}')
            return

        # Decrypt the file data
        try:
            iv = encrypted_file_data[:16]
            encrypted_content = encrypted_file_data[16:]

            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
            decryptor = cipher.decryptor()
            decrypted_file_data = decryptor.update(encrypted_content) + decryptor.finalize()
        except Exception as e:
            QMessageBox.warning(self, 'Error', f'Failed to decrypt file: {e}')
            return

        # Save the decrypted file
        save_path, _ = QFileDialog.getSaveFileName(self, 'Save File As', filename)
        if save_path:
            with open(save_path, 'wb') as f:
                f.write(decrypted_file_data)
            QMessageBox.information(self, 'Success', 'File downloaded and decrypted successfully.')

    def logout(self):
        self.token = None
        self.username = None
        self.label.setText('Welcome to the App.')
        self.register_button.show()
        self.login_button.show()
        self.upload_button.hide()
        self.download_button.hide()
        self.share_button.hide()
        self.logout_button.hide()
        self.file_list.hide()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    client_app = ClientApp()
    client_app.show()
    sys.exit(app.exec_())
