import subprocess

from PyQt5.QtCore import QThread, pyqtSignal


class InstallationWorker(QThread):
    result = pyqtSignal(str)  # Signal to send output back to the main thread

    def __init__(self, commands):
        super().__init__()
        self.commands = commands

    def run(self):
        try:
            for command in self.commands:
                self.result.emit(f"Executing: {command}\n")  # Send command to UI before execution
                # Execute each command
                process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout = process.stdout.decode()
                stderr = process.stderr.decode()

                if stdout:
                    self.result.emit(f"Output: {stdout}")
                if stderr:
                    self.result.emit(f"Error: {stderr}")
        except Exception as e:
            self.result.emit(f"Installation error: {str(e)}")
