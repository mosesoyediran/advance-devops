import re

import paramiko
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QTextCursor
from PyQt5.QtWidgets import (QFileDialog, QFormLayout, QHBoxLayout,
                             QInputDialog, QLabel, QLineEdit, QPushButton,
                             QTextEdit, QVBoxLayout, QWidget)

from ssh.ssh_worker import SSHInteractiveWorker


class SSHTab(QWidget):
    def __init__(self, auth_manager, main_tab_widget):
        super().__init__()
        self.auth_manager = auth_manager
        self.main_tab_widget = main_tab_widget
        self.command_history = []
        self.history_index = -1
        self.current_directory = None
        self.initUI()
        self.worker = None

    def initUI(self):
        main_layout = QHBoxLayout()

        # Left Column - SSH Connection Controls
        left_column = QVBoxLayout()

        # SSH Command Entry (Single Command)
        self.ssh_command_entry = QLineEdit(self)
        self.ssh_command_entry.setPlaceholderText("Enter SSH command (e.g., ssh user@host)")
        self.ssh_command_entry.returnPressed.connect(self.start_ssh_session)

        self.ssh_connect_button = QPushButton("Connect", self)
        self.ssh_connect_button.clicked.connect(self.start_ssh_session)

        left_column.addWidget(QLabel("SSH Connection"))
        left_column.addWidget(self.ssh_command_entry)
        left_column.addWidget(self.ssh_connect_button)

        # Add File Transfer Buttons
        self.upload_button = QPushButton("Upload File", self)
        self.upload_button.clicked.connect(self.upload_file)
        self.upload_button.setEnabled(False)

        self.download_button = QPushButton("Download File", self)
        self.download_button.clicked.connect(self.download_file)
        self.download_button.setEnabled(False)

        left_column.addWidget(self.upload_button)
        left_column.addWidget(self.download_button)

        # Add a Back button for navigating back
        back_button = QPushButton("Back to System", self)
        back_button.clicked.connect(self.go_back_to_system)
        left_column.addWidget(back_button)

        main_layout.addLayout(left_column)

        # Right Column - Terminal
        right_column = QVBoxLayout()

        # Terminal Output
        self.ssh_output = QTextEdit(self)
        self.ssh_output.setReadOnly(True)

        # Command Input
        self.ssh_command_input = QLineEdit(self)
        self.ssh_command_input.setPlaceholderText("Enter command and press Enter")
        self.ssh_command_input.returnPressed.connect(self.send_command)
        self.ssh_command_input.keyPressEvent = self.keyPressEvent

        right_column.addWidget(self.ssh_output)
        right_column.addWidget(self.ssh_command_input)

        main_layout.addLayout(right_column)

        self.setLayout(main_layout)
        
    def go_back_to_system(self):
        from system_tab import SystemTab
        
        for i in reversed(range(self.main_tab_widget.count())):
            self.main_tab_widget.removeTab(i)
        system_tab = SystemTab(self.auth_manager, self.main_tab_widget)
        self.main_tab_widget.addTab(system_tab, "System")
        self.main_tab_widget.setCurrentWidget(system_tab)

    def start_ssh_session(self):
        ssh_command = self.ssh_command_entry.text().strip()
        if not ssh_command.startswith("ssh "):
            self.ssh_output.setText("Please enter a valid SSH command (e.g., ssh user@host).")
            return

        try:
            user_host = ssh_command.split(" ")[1]
            user, host = user_host.split("@")
        except ValueError:
            self.ssh_output.setText("Invalid SSH command format. Use: ssh user@host")
            return

        password, ok = QInputDialog.getText(self, 'SSH Password', 'Enter your password:', QLineEdit.Password)
        if not ok:
            self.ssh_output.setText("Password entry canceled.")
            return

        self.ssh_output.setText("Starting interactive SSH session...")

        # Add the -o IdentitiesOnly=yes option
        ssh_options = "-o IdentitiesOnly=yes"

        # Start SSH session
        self.worker = SSHInteractiveWorker(host, user, password, ssh_options)
        self.worker.output_ready.connect(self.handle_output)
        self.worker.current_directory_ready.connect(self.update_current_directory)
        self.worker.start()

        # Enable file transfer buttons once connected
        self.upload_button.setEnabled(True)
        self.download_button.setEnabled(True)


    def send_command(self):
        command = self.ssh_command_input.text().strip()
        if command == "clear":
            self.ssh_output.clear()
            self.ssh_command_input.clear()
            return

        if self.worker and self.worker.isRunning() and command:
            self.worker.send_command(command)
            self.command_history.append(command)
            self.history_index = -1
            self.ssh_command_input.clear()

    def handle_output(self, output):
        self.ssh_output.append(output)
        self.ssh_output.moveCursor(QTextCursor.End)  # Scroll to the bottom

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Up:
            self.show_previous_command()
        elif event.key() == Qt.Key_Down:
            self.show_next_command()
        elif event.key() == Qt.Key_C and event.modifiers() & Qt.ControlModifier:
            self.worker.send_special_key('\x03')  # Send Ctrl+C to interrupt
        elif event.key() == Qt.Key_L and event.modifiers() & Qt.ControlModifier:
            self.worker.send_special_key('\x0c')  # Send Ctrl+L to clear
        elif event.key() == Qt.Key_Q:
            self.worker.send_special_key('q')  # Send 'q' to exit less/more
        else:
            QLineEdit.keyPressEvent(self.ssh_command_input, event)

    def show_previous_command(self):
        if self.command_history and self.history_index < len(self.command_history) - 1:
            self.history_index += 1
            self.ssh_command_input.setText(self.command_history[-(self.history_index + 1)])

    def show_next_command(self):
        if self.command_history and self.history_index > 0:
            self.history_index -= 1
            self.ssh_command_input.setText(self.command_history[-(self.history_index + 1)])
        elif self.history_index == 0:
            self.history_index = -1
            self.ssh_command_input.clear()

    def update_current_directory(self, directory):
        self.current_directory = directory
        print(f"Current directory updated: {self.current_directory}")

    def upload_file(self):
        if self.worker and self.worker.sftp_client:
            local_path, _ = QFileDialog.getOpenFileName(self, "Select file to upload")
            if local_path:
                self.worker.upload_file(local_path)

    def download_file(self):
        if self.worker and self.worker.sftp_client:
            file_name, ok = QInputDialog.getText(self, 'File Name', 'Enter the file name to download from current directory:')
            if ok:
                local_path = QFileDialog.getExistingDirectory(self, "Select Directory to Save File")
                if local_path:
                    local_file_path = f"{local_path}/{file_name}"
                    remote_file_path = f"{self.current_directory}/{file_name}"
                    self.worker.download_file(remote_file_path, local_file_path)

    def closeEvent(self, event):
        if self.worker:
            self.worker.stop()
        event.accept()