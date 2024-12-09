import os

from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import (QDialog, QFileDialog, QHBoxLayout, QLabel,
                             QPushButton, QTabWidget, QTextEdit, QVBoxLayout,
                             QWidget)

from system_tab import SystemTab
from text_editor_dialog import TextEditorDialog


class MainUI(QWidget):
    def __init__(self, auth_manager):
        super().__init__()
        self.auth_manager = auth_manager
        self.initUI()

    def initUI(self):
        # Set background color for the main window
        # self.setStyleSheet("""
        #     QWidget {
        #         background-color: rgb(10, 50, 76);
        #         color: rgb(2, 255, 200);
        #     }
        #     QPushButton {
        #         border-bottom: 2px solid rgba(0,0,0,100);
        #         padding: 10px;
        #         font: 14pt 'Terminal';
        #         color: rgb(2, 255, 200);
        #         border-radius: 20px;
        #     }
        #     QPushButton:hover {
        #         background-color: rgb(10, 80, 76);
        #         color: rgb(2, 255, 200);
        #     }
        # """)
        # Main Layout
        main_layout = QVBoxLayout()

        # Tab Widget
        tabs = QTabWidget()

        # Initialize SystemTab and add it to the tab widget
        self.system_tab = SystemTab(self.auth_manager, tabs)
        tabs.addTab(self.system_tab, "System")

        # Add tabs to the main layout
        main_layout.addWidget(tabs)

        # Create a small circular button for the text editor
        self.text_editor_button = QPushButton("T", self)
        self.text_editor_button.setFixedSize(40, 40)  # Small circular size
        self.text_editor_button.setStyleSheet("border-radius: 20px; background-color: #3498db; color: white;")
        self.text_editor_button.setToolTip("Open Shared Text Editor")
        self.text_editor_button.clicked.connect(self.open_text_editor)

        # Add sign-out button
        sign_out_button = QPushButton("Sign Out", self)
        sign_out_button.clicked.connect(self.sign_out)
        main_layout.addWidget(sign_out_button)

        self.setLayout(main_layout)
        self.setWindowTitle('Diran v1.0.0')
        self.setWindowIcon(QIcon('image/logo.jpg'))
        self.setGeometry(100, 100, 1200, 800)
        self.show()

    def open_text_editor(self):
        # Open the shared text editor dialog
        self.text_editor_dialog = TextEditorDialog(self)
        self.text_editor_dialog.exec_()  # Open the dialog as a modal

    def sign_out(self):
        self.auth_manager.sign_out()
        self.close()
        from sign_in_window import \
            SignInWindow  # Import here to avoid circular dependency
        self.sign_in_window = SignInWindow()
        self.sign_in_window.show()

    def closeEvent(self, event):
        # Save data when the application is closed
        self.auth_manager.save_data()
        event.accept()



