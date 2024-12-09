import os
import sys
import time

import paramiko


def wait_for_ssh(host, port, user, key_filename, timeout=300, delay=10):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    end_time = time.time() + timeout
    while time.time() < end_time:
        try:
            print(f"Trying to connect to {host}:{port} via SSH...")
            client.connect(hostname=host, port=port, username=user, key_filename=key_filename)
            print(f"Connected to {host} via SSH!")
            client.close()
            return True
        except (paramiko.ssh_exception.NoValidConnectionsError, paramiko.ssh_exception.SSHException) as e:
            print(f"Failed to connect: {e}")
            time.sleep(delay)
    
    print(f"Failed to connect to {host}:{port} within {timeout} seconds.")
    return False

if __name__ == "__main__":
    # Get the current directory dynamically (relative to where the script is run)
    app_dir = os.path.dirname(os.path.abspath(__file__))

    host = sys.argv[1]       # The remote host (e.g., EC2 instance DNS)
    port = int(sys.argv[2])  # The SSH port
    user = sys.argv[3]       # The SSH user
    key_filename = sys.argv[4]  # The SSH private key file
    
    print(f"App directory is: {app_dir}")

    # Run the wait_for_ssh function
    if not wait_for_ssh(host, port, user, key_filename):
        sys.exit(1)  # Exit with error if unable to connect
