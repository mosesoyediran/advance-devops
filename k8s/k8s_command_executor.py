import os
import subprocess


class K8sCommandExecutor:
    def run_k8s_command(self, command):
        """
        Executes a kubectl command and returns the output.
        """
        return self._run_command(f"kubectl {command}")

    def _run_command(self, command):
        """
        General method to run any shell command.
        """
        try:
            result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return result.stdout.decode('utf-8')
        except subprocess.CalledProcessError as e:
            return f"Error: {e.stderr.decode('utf-8')}"