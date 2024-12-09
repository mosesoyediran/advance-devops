import configparser
import os


def get_aws_credentials():
    # Define paths to AWS CLI config files
    aws_credentials_path = os.path.expanduser('~/.aws/credentials')
    aws_config_path = os.path.expanduser('~/.aws/config')

    # Initialize parser
    credentials_parser = configparser.ConfigParser()
    config_parser = configparser.ConfigParser()

    # Read credentials and config
    credentials_parser.read(aws_credentials_path)
    config_parser.read(aws_config_path)

    # Fetch values from 'default' section (or another profile)
    aws_access_key = credentials_parser.get('default', 'aws_access_key_id', fallback=None)
    aws_secret_key = credentials_parser.get('default', 'aws_secret_access_key', fallback=None)
    region = config_parser.get('default', 'region', fallback=None)

    return {
        'access_key': aws_access_key,
        'secret_key': aws_secret_key,
        'region': region
    }

def update_terraform_file(file_path, aws_creds):
    # Read the main.tf file content
    with open(file_path, 'r') as file:
        file_content = file.read()

    # Replace the placeholders with actual AWS credentials
    file_content = file_content.replace('AWS_REGION_PLACEHOLDER', aws_creds['region'])
    file_content = file_content.replace('AWS_ACCESS_KEY_PLACEHOLDER', aws_creds['access_key'])
    file_content = file_content.replace('AWS_SECRET_KEY_PLACEHOLDER', aws_creds['secret_key'])

    # Write the updated content back to the file
    with open(file_path, 'w') as file:
        file.write(file_content)

    print(f"Updated {file_path} with AWS credentials.")


