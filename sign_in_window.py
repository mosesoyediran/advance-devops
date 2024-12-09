from PyQt5.QtWidgets import (QLabel, QLineEdit, QPushButton, QVBoxLayout,
                             QWidget)

from auth_manager import AuthManager
from ui_main import MainUI


class SignInWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Sign In')
        self.setGeometry(100, 100, 400, 200)

        layout = QVBoxLayout()
        self.password_input = QLineEdit(self)
        self.password_input.setPlaceholderText("Enter your password")
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)

        self.sign_in_button = QPushButton('Sign In', self)
        self.sign_in_button.clicked.connect(self.sign_in)
        layout.addWidget(self.sign_in_button)

        self.message_label = QLabel(self)
        layout.addWidget(self.message_label)

        self.setLayout(layout)

    def sign_in(self):
        password = self.password_input.text()
        if not password:
            self.message_label.setText("Please enter a password.")
            return

        try:
            self.auth_manager = AuthManager(password)
            self.auth_manager.sign_in()

            # Initialize and show the main application window
            self.main_ui = MainUI(self.auth_manager)
            self.main_ui.show()

            # Close the sign-in window
            self.close()
        except ValueError as e:
            self.message_label.setText(str(e))
