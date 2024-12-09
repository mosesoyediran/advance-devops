# terraform/terraform_module_manager.py

import json
import logging
import os
import re
import shutil
import subprocess
import threading
from typing import List

from PyQt5.QtWidgets import QMessageBox


class TerraformModuleManager:
    def __init__(self, project_option, provider_option, config_editor, log_function, output_area):
        """
        Initialize the manager with project options, provider options, configuration editor, and logging function.
        """
        self.project_option = project_option
        self.provider_option = provider_option
        self.config_editor = config_editor
        self.log_message = log_function
        self.output_area = output_area

    def on_provider_selection(self, provider: str):
        """
        Handle provider selection and load the corresponding Terraform configuration.
        """
        if provider == "EC2":
            self.load_ec2_modules()
        elif provider == "EKS":
            self.load_eks_modules()
        else:
            self.clear_configuration_editor()
            self.log_message("No valid provider selected.")

    def load_ec2_modules(self):
        """
        Load the EC2 modules, create folders and files, and move terraform.tfvars.
        """
        selected_project = self.project_option.currentText()
        if not selected_project:
            QMessageBox.warning(None, "Warning", "Please select a project first.")
            self.log_message("Provider selection failed: No project selected.")
            return

        # Define paths for the EC2 .tf file and tfvars file
        tf_dir = os.path.join(os.getcwd(), "terraform")  # Directory containing ec2.tf and terraform_ec2.tfvars
        ec2_tf_path = os.path.join(tf_dir, "ec2.tf")  # Path to ec2.tf
        tfvars_path = os.path.join(tf_dir, "terraform_ec2.tfvars")  # Path to terraform_ec2.tfvars

        # Define the destination paths in the project directory
        project_path = os.path.join("terraform_projects", selected_project)
        main_tf_path = os.path.join(project_path, "main.tf")  # main.tf in the project directory
        project_tfvars_path = os.path.join(project_path, "terraform.tfvars")  # terraform.tfvars in the project directory

        # Create module folders for VPC and EC2 if they don't exist
        vpc_folder_path = os.path.join(project_path, "modules", "vpc")
        ec2_folder_path = os.path.join(project_path, "modules", "ec2")

        os.makedirs(vpc_folder_path, exist_ok=True)
        os.makedirs(ec2_folder_path, exist_ok=True)

        vpc_main_tf_path = os.path.join(vpc_folder_path, "vpc.tf")
        ec2_main_tf_path = os.path.join(ec2_folder_path, "ec2.tf")

        try:
            # Read the contents of the ec2.tf file
            with open(ec2_tf_path, 'r') as ec2_tf_file:
                ec2_tf_content = ec2_tf_file.read()

            # Extract VPC and EC2 module blocks
            vpc_module_block = self.extract_module_block(ec2_tf_content, 'myapp-vpc')
            ec2_module_block = self.extract_module_block(ec2_tf_content, 'ec2')

            if not vpc_module_block:
                self.log_message("Error: VPC module block not found in ec2.tf.")
                QMessageBox.critical(None, "Error", "VPC module block not found in ec2.tf.")
                return

            if not ec2_module_block:
                self.log_message("Error: EC2 module block not found in ec2.tf.")
                QMessageBox.critical(None, "Error", "EC2 module block not found in ec2.tf.")
                return

            # Write the VPC module files
            self.write_module_file(vpc_main_tf_path, vpc_module_block)
            self.log_message(f"Copied VPC content to {vpc_main_tf_path} as part of VPC module")

            # Write the EC2 module files
            self.write_module_file(ec2_main_tf_path, ec2_module_block)
            self.log_message(f"Copied EC2 content to {ec2_main_tf_path} as part of EC2 module")

            # Copy the terraform_ec2.tfvars file to the project folder as terraform.tfvars
            if os.path.exists(tfvars_path):
                shutil.copyfile(tfvars_path, project_tfvars_path)
                self.log_message(f"Copied terraform_ec2.tfvars to project as terraform.tfvars")
            else:
                self.log_message(f"Warning: terraform_ec2.tfvars not found at {tfvars_path}")

            # Write the root main.tf file in the project folder, referencing both modules
            root_main_tf_content = self.create_root_main_tf(provider="EC2")
            with open(main_tf_path, 'w') as main_tf_file:
                main_tf_file.write(root_main_tf_content)
            self.log_message("Created main.tf to include both VPC and EC2 modules")

            # Extract variables from both VPC and EC2 content and display them in the editor
            variables = self.extract_variables(vpc_module_block) + self.extract_variables(ec2_module_block)
            self.display_variables_in_editor(variables)

        except FileNotFoundError as e:
            self.log_message(f"Error: {e}")
            QMessageBox.critical(None, "Error", f"Failed to load EC2 module files: {e}")
        except Exception as e:
            self.log_message(f"Error loading EC2 modules: {e}")
            QMessageBox.critical(None, "Error", f"Failed to load EC2 modules: {e}")

    def load_eks_modules(self):
        """
        Load the EKS modules, create folders and files, and move terraform.tfvars.
        """
        selected_project = self.project_option.currentText()
        if not selected_project:
            QMessageBox.warning(None, "Warning", "Please select a project first.")
            self.log_message("Provider selection failed: No project selected.")
            return

        # Define paths for the EKS .tf file and tfvars file
        tf_dir = os.path.join(os.getcwd(), "terraform")  # Directory containing eks.tf and terraform_eks.tfvars
        eks_tf_path = os.path.join(tf_dir, "eks.tf")  # Path to eks.tf
        tfvars_path = os.path.join(tf_dir, "terraform_eks.tfvars")  # Path to terraform_eks.tfvars

        # Define the destination paths in the project directory
        project_path = os.path.join("terraform_projects", selected_project)
        main_tf_path = os.path.join(project_path, "main.tf")  # main.tf in the project directory
        project_tfvars_path = os.path.join(project_path, "terraform.tfvars")  # terraform.tfvars in the project directory

        # Create module folders for VPC and EKS if they don't exist
        vpc_folder_path = os.path.join(project_path, "modules", "vpc")
        eks_folder_path = os.path.join(project_path, "modules", "eks")

        os.makedirs(vpc_folder_path, exist_ok=True)
        os.makedirs(eks_folder_path, exist_ok=True)

        vpc_main_tf_path = os.path.join(vpc_folder_path, "vpc.tf")
        eks_main_tf_path = os.path.join(eks_folder_path, "eks.tf")

        try:
            # Read the contents of the eks.tf file
            with open(eks_tf_path, 'r') as eks_tf_file:
                eks_tf_content = eks_tf_file.read()

            # Extract VPC and EKS module blocks
            vpc_module_block = self.extract_module_block(eks_tf_content, 'myapp-vpc')
            eks_module_block = self.extract_module_block(eks_tf_content, 'eks')

            if not vpc_module_block:
                self.log_message("Error: VPC module block not found in eks.tf.")
                QMessageBox.critical(None, "Error", "VPC module block not found in eks.tf.")
                return

            if not eks_module_block:
                self.log_message("Error: EKS module block not found in eks.tf.")
                QMessageBox.critical(None, "Error", "EKS module block not found in eks.tf.")
                return

            # Write the VPC module files
            self.write_module_file(vpc_main_tf_path, vpc_module_block)
            self.log_message(f"Copied VPC content to {vpc_main_tf_path} as part of VPC module")

            # Write the EKS module files
            self.write_module_file(eks_main_tf_path, eks_module_block)
            self.log_message(f"Copied EKS content to {eks_main_tf_path} as part of EKS module")

            # Copy the terraform_eks.tfvars file to the project folder as terraform.tfvars
            if os.path.exists(tfvars_path):
                shutil.copyfile(tfvars_path, project_tfvars_path)
                self.log_message(f"Copied terraform_eks.tfvars to project as terraform.tfvars")
            else:
                self.log_message(f"Warning: terraform_eks.tfvars not found at {tfvars_path}")

            # Write the root main.tf file in the project folder, referencing both modules
            root_main_tf_content = self.create_root_main_tf(provider="EKS")
            with open(main_tf_path, 'w') as main_tf_file:
                main_tf_file.write(root_main_tf_content)
            self.log_message("Created main.tf to include both VPC and EKS modules")

            # Extract variables from both VPC and EKS content and display them in the editor
            variables = self.extract_variables(vpc_module_block) + self.extract_variables(eks_module_block)
            self.display_variables_in_editor(variables)

        except FileNotFoundError as e:
            self.log_message(f"Error: {e}")
            QMessageBox.critical(None, "Error", f"Failed to load EKS module files: {e}")
        except Exception as e:
            self.log_message(f"Error loading EKS modules: {e}")
            QMessageBox.critical(None, "Error", f"Failed to load EKS modules: {e}")

    def extract_module_block(self, content: str, module_name: str) -> str:
        """
        Extracts the Terraform module block for a given module name.

        :param content: The entire Terraform configuration as a string.
        :param module_name: The name of the module to extract.
        :return: The module block as a string.
        """
        # Regex to match module blocks, including nested braces
        pattern = rf'module\s+"{module_name}"\s+\{{'
        match = re.search(pattern, content)
        if not match:
            return ""

        start_index = match.start()
        brace_count = 0
        end_index = start_index

        for i, char in enumerate(content[start_index:], start=start_index):
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    end_index = i
                    break

        return content[start_index:end_index + 1]

    def write_module_file(self, file_path: str, module_block: str):
        """Write the module block to the specified file."""
        with open(file_path, 'w') as f:
            f.write(module_block)

    def create_root_main_tf(self, provider: str = "EKS") -> str:
        """
        Creates the root main.tf content that references both VPC and the selected provider module.

        :param provider: The provider module to reference ("EKS" or "EC2").
        :return: The root main.tf content as a string.
        """
        if provider == "EKS":
            module_reference = """
module "eks" {
  source  = "./modules/eks"
  cluster_name    = var.cluster_name
  cluster_version = var.cluster_version

  vpc_id     = module.myapp-vpc.vpc_id
  subnet_ids = module.myapp-vpc.private_subnets

  tags = var.eks_tags

  node_groups = var.node_groups
}
"""
        elif provider == "EC2":
            module_reference = """
module "ec2" {
  source  = "./modules/ec2"
  # Add EC2-specific variables here
  # Example:
  # instance_count = var.instance_count
  # instance_type  = var.instance_type
}
"""
        else:
            module_reference = ""

        root_main_tf = f"""
# Load VPC Module
module "myapp-vpc" {{
  source  = "./modules/vpc"
  name    = "myapp-vpc"
  cidr    = var.vpc_cidr_block

  private_subnets = var.private_subnet_cidr_blocks
  public_subnets  = var.public_subnet_cidr_blocks

  azs = data.aws_availability_zones.available.names

  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true

  tags = {{
    "kubernetes.io/cluster/myapp-eks-cluster" = "shared"
  }}

  public_subnet_tags = {{
    "kubernetes.io/cluster/myapp-eks-cluster" = "shared"
    "kubernetes.io/role/elb"                  = 1
  }}

  private_subnet_tags = {{
    "kubernetes.io/cluster/myapp-eks-cluster" = "shared"
    "kubernetes.io/role/internal-elb"         = 1
  }}
}}

{module_reference}

# Other project configurations can go here
"""
        return root_main_tf

    def clear_configuration_editor(self):
        """Clear the configuration editor."""
        self.config_editor.clear()

    def extract_variables(self, tf_content: str) -> List[str]:
        """Extract variable declarations from the .tf content."""
        variables = []
        # Regex to match variable blocks
        pattern = r'variable\s+"([^"]+)"\s+\{([^}]+)\}'
        matches = re.findall(pattern, tf_content, re.DOTALL)
        for var_name, var_body in matches:
            variables.append(var_name)
        return variables

    def display_variables_in_editor(self, variables: List[str]):
        """Display variables in the configuration editor."""
        self.config_editor.clear()
        for var in variables:
            self.config_editor.appendPlainText(f'variable "{var}" {{\n  description = ""\n  type        = string\n}}\n')

