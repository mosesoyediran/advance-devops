import argparse
import configparser
import json
import os
import subprocess
import sys


def update_ansible_cfg(project_folder, remote_user):
        """Update or create ansible.cfg with remote_user"""
        
        ansible_cfg_path = os.path.join(project_folder, 'ansible.cfg')
        config = configparser.ConfigParser()

        # Read existing config file or create a new one
        if os.path.exists(ansible_cfg_path):
            config.read(ansible_cfg_path)
        else:
            config['defaults'] = {}

        # Update the defaults section with dynamic values
        config['defaults']['remote_user'] = remote_user


        # Write the updated ansible.cfg
        with open(ansible_cfg_path, 'w') as configfile:
            config.write(configfile)

        print(f"Updated ansible.cfg with remote_user={remote_user}")


def extract_remote_user_from_terraform(project_folder_path):
    """Retrieve remote_user based on the instance created by Terraform."""
    remote_user = ''  # Default to an empty string

    # Run terraform output command to get the details
    terraform_output_process = subprocess.run(
        ["terraform", "output", "-json"],
        cwd=project_folder_path,
        capture_output=True,
        text=True
    )

    if terraform_output_process.returncode == 0:
        output_json = json.loads(terraform_output_process.stdout)
        print("Terraform output successfully retrieved.")
        
        # Check for the instance OS information
        instance_os = output_json.get('instance_os', {}).get('value', '')
        if instance_os:
            print(f"Detected instance OS: {instance_os}")
            # Match the instance_os with possible OS names
            if 'ubuntu' in instance_os.lower():
                remote_user = 'ubuntu'
            elif 'amzn' in instance_os.lower() or 'amazon' in instance_os.lower():
                remote_user = 'ec2-user'
            elif 'rhel' in instance_os.lower() or 'centos' in instance_os.lower():
                remote_user = 'root'
            else:
                remote_user = 'admin'  # Fallback for other systems
        else:
            print("No OS type found in Terraform output, using fallback.")

    else:
        print(f"Failed to retrieve Terraform output: {terraform_output_process.stderr}")

    # If remote_user is still empty, provide a default
    if not remote_user:
        remote_user = 'ubuntu'  # Default to 'ubuntu' if OS detection fails

    print(f"Determined remote_user: {remote_user}")
    return remote_user



def run_playbook(playbook_path, inventory_path, private_key_path, remote_user):
    """Run Ansible playbook using subprocess to call ansible-playbook command."""
    
    command = [
        'ansible-playbook',
        '-i', inventory_path,
        playbook_path,
        '--private-key', private_key_path,
        '-u', remote_user,   
        '--ssh-extra-args', '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes',
        '-v'  # Verbose output
    ]

    print(f"Running Ansible playbook '{playbook_path}' with inventory '{inventory_path}'...")

    # Run the playbook command
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # Read real-time output
    for line in process.stdout:
        print(line.strip())

    process.wait()
    if process.returncode != 0:
        print(f"Playbook execution failed with code {process.returncode}")
        for line in process.stderr:
            print(line.strip())
    else:
        print(f"Playbook executed successfully with return code {process.returncode}")

    return process.returncode


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Ansible playbook using subprocess")
    parser.add_argument('--inventory', type=str, required=True, help='Path to the inventory file')
    parser.add_argument('--playbook', type=str, required=True, help='Path to the Ansible playbook')
    parser.add_argument('--private-key', type=str, required=True, help='Path to the private SSH key file')
    parser.add_argument('--remote-user', type=str, required=True, help='Remote user for SSH login')

    args = parser.parse_args()

    # Ensure paths are absolute
    inventory_path = os.path.abspath(args.inventory)
    playbook_path = os.path.abspath(args.playbook)
    private_key_path = os.path.abspath(args.private_key)
    
    remote_user = args.remote_user 
    
    
    

    # Run the playbook
    result = run_playbook(playbook_path, inventory_path, private_key_path, remote_user)
    sys.exit(result)
