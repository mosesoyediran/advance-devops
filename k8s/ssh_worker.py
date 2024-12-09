import os

import paramiko
from PyQt5.QtCore import QThread, pyqtSignal


class SSHWorker(QThread):
    result = pyqtSignal(str, object)  # Emit both result and SSH client

    def __init__(self, ssh_command=None, ssh_client=None, remote_command=None, password=None, ssh_key_path=None, parent=None):
        super().__init__(parent)
        self.ssh_client = ssh_client  # Store existing SSHClient to reuse connection
        self.ssh_command = ssh_command
        self.remote_command = remote_command
        self.password = password
        self.ssh_key_path = ssh_key_path  # SSH key path

    def run(self):
        # If there's an existing client, use it directly
        if self.ssh_client:
            self.execute_command_with_existing_client()
        elif self.password:
            self.execute_command_with_password()
        elif self.ssh_key_path:
            # Check if the SSH key file exists
            if os.path.exists(self.ssh_key_path):
                self.result.emit(f"SSH key found: {self.ssh_key_path}", None)
                self.execute_command_with_key()
            else:
                self.result.emit(f"Error: SSH key file not found at {self.ssh_key_path}", None)
        else:
            self.result.emit("Error: Password or SSH key is required for this connection method.", None)

    def execute_command_with_existing_client(self):
        try:
            stdin, stdout, stderr = self.ssh_client.exec_command(self.remote_command)
            self.read_output(stdout, stderr)
        except Exception as e:
            self.result.emit(f"Error: {str(e)}", None)

    def execute_command_with_password(self):
        user, host = self.extract_user_host(self.ssh_command)
        if not user or not host:
            self.result.emit("Invalid SSH command format.", None)
            return

        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_client.connect(host, username=user, password=self.password)

            stdin, stdout, stderr = self.ssh_client.exec_command(self.remote_command)
            self.read_output(stdout, stderr)
        except paramiko.AuthenticationException:
            self.result.emit("Error: Authentication failed. Check your password and username.", None)
        except Exception as e:
            self.result.emit(f"Error: {str(e)}", None)

    def execute_command_with_key(self):
        user, host = self.extract_user_host(self.ssh_command)
        if not user or not host:
            self.result.emit("Invalid SSH command format.", None)
            return

        try:
            # Load the private key
            self.result.emit(f"Loading SSH key from: {self.ssh_key_path}", None)
            key = paramiko.RSAKey.from_private_key_file(self.ssh_key_path)

            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_client.connect(host, username=user, pkey=key)

            stdin, stdout, stderr = self.ssh_client.exec_command(self.remote_command)
            self.read_output(stdout, stderr)
        except paramiko.AuthenticationException:
            self.result.emit("Error: Authentication failed. Check your SSH key and username.", None)
        except paramiko.SSHException as ssh_error:
            self.result.emit(f"SSH Error: {str(ssh_error)}", None)
        except Exception as e:
            self.result.emit(f"Error: {str(e)}", None)

    def read_output(self, stdout, stderr):
        """
        Incrementally read SSH command output and send it to the UI.
        """
        try:
            # Read stdout incrementally
            while not stdout.channel.exit_status_ready():
                if stdout.channel.recv_ready():
                    output = stdout.channel.recv(1024).decode('utf-8')
                    self.result.emit(output, self.ssh_client)
            
            # Read any remaining output after the command completes
            output = stdout.read().decode('utf-8')
            if output:
                self.result.emit(output, self.ssh_client)

            # Read stderr if any
            error_output = stderr.read().decode('utf-8')
            if error_output:
                self.result.emit(f"Error: {error_output}", None)
        except Exception as e:
            self.result.emit(f"Error reading output: {str(e)}", None)

    def extract_user_host(self, ssh_command):
        parts = ssh_command.split()
        
        # Check if the command contains the "-i" option (for SSH keys)
        if '-i' in parts:
            try:
                user_host = parts[3]
                if '@' in user_host:
                    user, host = user_host.split('@', 1)
                    return user, host
            except IndexError:
                return None, None
        else:
            if len(parts) == 2 and '@' in parts[1]:
                user_host = parts[1]
                user, host = user_host.split('@', 1)
                return user, host

        return None, None
