# login_window.py

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLineEdit, QPushButton, QMessageBox
)
import requests

certificate = r'../certificate/cert.pem'

class LoginWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__()
        self.setWindowTitle('User Login')
        self.parent = parent
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

        self.login_button = QPushButton('Login')
        self.login_button.clicked.connect(self.login_user)
        layout.addWidget(self.login_button)

        self.setLayout(layout)

    def login_user(self):
        username = self.username_input.text()
        password = self.password_input.text()

        if not username or not password:
            QMessageBox.warning(self, 'Error', 'Please enter a username and password.')
            return

        data = {
            'username': username,
            'password': password,
        }

        # Send login request to the server
        try:
            response = requests.post(
                'https://127.0.0.1:8000/login/',
                json=data,
                verify=certificate,  # Path to your certificate
                headers={'Content-Type': 'application/json'}
            )
            try:
                response_data = response.json()
            except ValueError:
                QMessageBox.warning(self, 'Error', 'Invalid response from server.')
                return

            if response.status_code == 200:
                token = response_data.get('token')
                QMessageBox.information(self, 'Success', 'Login successful.')
                # Pass token and username to the parent (main window)
                self.parent.token = token
                self.parent.username = username
                self.parent.update_ui_after_login()
                self.close()
            else:
                error_message = response_data.get('error', 'Unknown error.')
                QMessageBox.warning(self, 'Error', f'Failed to login: {error_message}')
        except Exception as e:
            QMessageBox.warning(self, 'Error', f'An error occurred: {e}')
