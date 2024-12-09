
import os

from PyQt5.QtWidgets import (QDialog, QHBoxLayout, QPushButton, QTextEdit,
                             QVBoxLayout)


class TextEditorDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
        self.load_text()  # Load the text when the dialog is initialized

    def initUI(self):
        # Dialog Layout
        dialog_layout = QVBoxLayout()

        # Shared QTextEdit
        self.text_edit = QTextEdit(self)
        self.text_edit.setPlaceholderText("Enter your text here...")
        dialog_layout.addWidget(self.text_edit)

        # Buttons Layout
        buttons_layout = QHBoxLayout()

        save_button = QPushButton("Save", self)
        save_button.clicked.connect(self.save_text)
        buttons_layout.addWidget(save_button)

        close_button = QPushButton("Close", self)
        close_button.clicked.connect(self.close_dialog)
        buttons_layout.addWidget(close_button)

        dialog_layout.addLayout(buttons_layout)

        self.setLayout(dialog_layout)
        self.setWindowTitle("Shared Text Editor")
        self.setGeometry(300, 200, 400, 300)  # Size of the dialog window

    def save_text(self):
        # Define the file path where the text will be saved
        file_path = os.path.join(os.path.expanduser("~"), "shared_text.txt")

        # Save the text from QTextEdit to the file
        with open(file_path, 'w') as file:
            file.write(self.text_edit.toPlainText())

        # Close the dialog after saving
        self.close_dialog()

    def load_text(self):
        # Define the file path where the text is saved
        file_path = os.path.join(os.path.expanduser("~"), "shared_text.txt")

        # Load the text from the file if it exists
        if os.path.exists(file_path):
            with open(file_path, 'r') as file:
                content = file.read()
                self.text_edit.setPlainText(content)

    def close_dialog(self):
        self.close()