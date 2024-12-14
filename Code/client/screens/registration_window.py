# registration_window.py

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLineEdit, QPushButton, QMessageBox
)
import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

certificate = r'../certificate/cert.pem'

class RegistrationWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('User Registration')
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText('Username')
        layout.addWidget(self.username_input)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText('Password')
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)

        self.register_button = QPushButton('Register')
        self.register_button.clicked.connect(self.register_user)
        layout.addWidget(self.register_button)

        self.setLayout(layout)

    def register_user(self):
        username = self.username_input.text()
        password = self.password_input.text()

        if not username or not password:
            QMessageBox.warning(self, 'Error', 'Please enter a username and password.')
            return

        # Generate public/private key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()

        # Serialize public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        # Serialize private key and save locally
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        # Save the private key to a file (ensure secure storage in production)
        with open(f'../user_keys/{username}_private_key.pem', 'w') as f:
            f.write(private_pem)
        with open(f'../user_keys/{username}_public_key.pem', 'w') as f:
            f.write(public_pem)

        # Prepare data for registration
        data = {
            'username': username,
            'password': password,
            'public_key': public_pem,
        }

        # Send registration request to the server
        try:
            response = requests.post(
                'https://127.0.0.1:8000/register/',
                json=data,
                verify=certificate,  # Path to your certificate
                headers={'Content-Type': 'application/json'}
            )
            if response.status_code == 201:
                QMessageBox.information(self, 'Success', 'User registered successfully.')
                self.close()
            else:
                error_message = response.json().get('error', 'Unknown error.')
                QMessageBox.warning(self, 'Error', f'Failed to register: {error_message}')
        except Exception as e:
            QMessageBox.warning(self, 'Error', f'An error occurred: {e}')
