import re

import paramiko
from PyQt5.QtCore import QThread, pyqtSignal


class SSHInteractiveWorker(QThread):
    output_ready = pyqtSignal(str)
    current_directory_ready = pyqtSignal(str)
    sftp_client = None

    def __init__(self, host, user, password, ssh_options=None):
        super().__init__()
        self.host = host
        self.user = user
        self.password = password
        self.ssh_options = ssh_options
        self.channel = None
        self.client = None
        self.keep_running = True
        self.current_directory = None
        self.expecting_pwd = False

    def run(self):
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Forcing `IdentitiesOnly=yes` in `paramiko`
            if self.ssh_options and "IdentitiesOnly=yes" in self.ssh_options:
                # Add logic here if you have any specific way to handle it in `paramiko`
                # This line is just for demonstration since `paramiko` does not directly use SSH options
                print(f"Using SSH option: {self.ssh_options}")

            # Connect to the SSH server
            self.client.connect(self.host, username=self.user, password=self.password)
            #print(f"Connected to {self.host} as {self.user}")

            self.channel = self.client.invoke_shell()
            self.channel.settimeout(0.0)

            # Initialize SFTP client
            self.sftp_client = self.client.open_sftp()

            # Get the initial current directory
            self.send_command("pwd")
            self.expecting_pwd = True

            while self.keep_running:
                if self.channel.recv_ready():
                    output = self.channel.recv(1024).decode('utf-8')
                    clean_output = self.clean_output(output)
                    self.output_ready.emit(clean_output)
                    self.check_for_directory_change(clean_output)

        except Exception as e:
            self.output_ready.emit(f"Error: {str(e)}")

    def send_command(self, command):
        if self.channel:
            self.channel.send(command + '\n')

    def send_special_key(self, key_sequence):
        if self.channel:
            self.channel.send(key_sequence)

    def clean_output(self, output):
        output = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', output)  # Clean ANSI escape codes
        output = re.sub(r'\x1b\[\?2004[hl]', '', output)  # Clean specific terminal sequences
        return output.strip()

    def check_for_directory_change(self, output):
        lines = output.splitlines()
        for line in lines:
            if self.expecting_pwd:
                if line.startswith("/"):  # Expecting output from `pwd`
                    self.current_directory = line
                    self.current_directory_ready.emit(self.current_directory)
                    self.expecting_pwd = False
                    return
            elif line.strip().endswith(("#", "$")):
                # Detected a prompt, but not a directory
                self.output_ready.emit(f"Detected shell prompt: {line.strip()}")
                return

    def stop(self):
        self.keep_running = False
        if self.channel:
            self.channel.close()
        if self.client:
            self.client.close()

    def upload_file(self, local_path):
        try:
            with open(local_path, 'rb') as f:
                print(f"Local file found: {local_path}")

            if self.current_directory:
                remote_path = f"{self.current_directory}/{local_path.split('/')[-1]}"
                try:
                    print(f"Uploading {local_path} to {remote_path} on remote server")
                    self.sftp_client.put(local_path, remote_path)
                    self.output_ready.emit(f"File uploaded: {local_path} to {remote_path}")
                except Exception as e:
                    self.output_ready.emit(f"Upload failed: {str(e)}")
            else:
                self.output_ready.emit("Could not determine the current directory. Upload failed.")
        except FileNotFoundError:
            self.output_ready.emit(f"Local file not found: {local_path}")
        except Exception as e:
            self.output_ready.emit(f"Error accessing local file: {str(e)}")

    def download_file(self, remote_path, local_path):
        try:
            self.sftp_client.get(remote_path, local_path)
            self.output_ready.emit(f"File downloaded: {remote_path} to {local_path}")
        except Exception as e:
            self.output_ready.emit(f"Download failed: {str(e)}")