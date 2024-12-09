import re

import paramiko
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtWidgets import QInputDialog, QLineEdit


class Worker(QThread):
    result = pyqtSignal(str)

    def __init__(self, ssh_method, ssh_command, remote_command, parent=None):
        super().__init__(parent)
        self.ssh_method = ssh_method
        self.ssh_command = ssh_command
        self.remote_command = remote_command

    def run(self):
        output = ""
        if self.ssh_method == "SSH Key":
            output = self.execute_command_with_key()
        elif self.ssh_method == "Password":
            output = self.execute_command_with_password()
        self.result.emit(output)

    def execute_command_with_key(self):
        match = re.search(r'ssh\s+-i\s+(\S+)\s+(\S+@\S+)', self.ssh_command)
        if match:
            key_path = match.group(1)
            user_host = match.group(2)

            try:
                key = paramiko.RSAKey.from_private_key_file(key_path)
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(user_host.split('@')[1], username=user_host.split('@')[0], pkey=key)

                stdin, stdout, stderr = client.exec_command(self.remote_command)
                output = stdout.read().decode()
                error = stderr.read().decode()
                client.close()

                if error:
                    return error
                return output
            except Exception as e:
                return f"Error: {str(e)}"
        return "Invalid SSH command format."

    def execute_command_with_password(self):
        match = re.search(r'ssh\s+(\S+@\S+)', self.ssh_command)
        if match:
            user_host = match.group(1)
            password, ok = QInputDialog.getText(None, "Enter SSH Password", "Password:", QLineEdit.Password)
            if ok and password:
                try:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(user_host.split('@')[1], username=user_host.split('@')[0], password=password)

                    stdin, stdout, stderr = client.exec_command(self.remote_command)
                    output = stdout.read().decode()
                    error = stderr.read().decode()
                    client.close()

                    if error:
                        return error
                    return output
                except Exception as e:
                    return f"Error: {str(e)}"
        return "Invalid SSH command format."
