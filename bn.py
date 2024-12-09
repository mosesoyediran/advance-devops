*** Terminating app due to uncaught exception 'NSInternalInconsistencyException', reason: 'NSWindow should only be instantiated on the main thread!'
*** First throw call stack: thread as advance for create node group import concurrent.futures
import json
import os
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor

import boto3
import botocore
import yaml
from botocore.exceptions import ClientError
from PyQt5.QtCore import (Q_ARG, QMetaObject, QObject, Qt, QTimer, pyqtSignal,
                          pyqtSlot)
from PyQt5.QtWidgets import (QButtonGroup, QCheckBox, QComboBox, QFileDialog,
                             QHBoxLayout, QInputDialog, QLabel, QLineEdit,
                             QPushButton, QRadioButton, QTabWidget, QTextEdit,
                             QVBoxLayout, QWidget)

from aws.eks_cluster_tab import ClusterManagementTab


class SignalManager(QObject):
    message_signal = pyqtSignal(str)
    clear_signal = pyqtSignal()


class EKSTab(QWidget):
    def __init__(self, session):
        super().__init__()
        self.session = session
        self.eks_client = session.client('eks')
        self.ec2_client = session.client('ec2')  # For VPC and Subnet Operations
        self.iam_client = session.client('iam')  # For querying IAM roles
        self.cloudformation_client = session.client('cloudformation')
        self.sts_client = session.client('sts')
        self.signal_manager = SignalManager()
        self.executor = ThreadPoolExecutor(max_workers=5)
        self.script_directory = os.path.dirname(os.path.realpath(__file__))
        self.hardcoded_vpc_yaml_path = os.path.join(self.script_directory, "amazon-eks-ipv6-vpc-public-private-subnets.yaml")
        self.initUI()
        self.connect_signals()
        self.stack_id = None
        self.signal_manager.message_signal.connect(self.show_message)

    def initUI(self):
        main_layout = QVBoxLayout()  # Stack items vertically

        # Create a widget to hold the radio buttons
        radio_widget = QWidget()
        radio_layout = QHBoxLayout(radio_widget)
        
        # Add radio buttons for "Cluster" and "Node" selection at the top
        self.radio_button_group = QButtonGroup(self)
        self.cluster_radio_button = QRadioButton("Cluster", self)
        self.node_radio_button = QRadioButton("Node", self)
        self.cluster_radio_button.setChecked(True)  # Default to "Cluster" view
        self.radio_button_group.addButton(self.cluster_radio_button)
        self.radio_button_group.addButton(self.node_radio_button)

        # Connect radio buttons to toggle UI sections
        self.cluster_radio_button.toggled.connect(self.toggle_mode)
        self.node_radio_button.toggled.connect(self.toggle_mode)

        # Add radio buttons to the layout with minimal spacing
        radio_layout.addWidget(self.cluster_radio_button)
        radio_layout.addWidget(self.node_radio_button)
        radio_layout.addStretch(1)  # Push radio buttons to the left
        radio_layout.setSpacing(10)  # Adjust the spacing between buttons
        radio_layout.setContentsMargins(0, 0, 0, 0)  # Remove margins

        # Add the radio buttons to the top of the main layout
        main_layout.addWidget(radio_widget)

        # Tab widget for EKS operations and Cluster Management
        self.tabs = QTabWidget(self)

        # Create the "EKS Management" sub-tab
        eks_management_tab = QWidget()
        eks_management_layout = QHBoxLayout(eks_management_tab)
        self.create_eks_management_interface(eks_management_layout)

        # Add the EKS management sub-tab
        self.tabs.addTab(eks_management_tab, "EKS Management")

        # Add Cluster Management tab
        self.cluster_management_tab = ClusterManagementTab(self.session)
        self.tabs.addTab(self.cluster_management_tab, "Cluster Management")

        # Add the main tabs widget to the main layout
        main_layout.addWidget(self.tabs)

        # Set the main layout for EKSTab
        self.setLayout(main_layout)

        # Populate AWS regions, versions, roles, and policies
        self.populate_regions()
        self.populate_versions_and_roles()
        self.populate_policies()

    def toggle_mode(self):
        """Toggle between Cluster and Node views."""
        if self.cluster_radio_button.isChecked():
            # Show cluster-related section
            self.cluster_section_widget.setVisible(True)
            self.node_group_section_widget.setVisible(False)
            
            # Show "Select Cluster" and "Select Cluster Version" labels and dropdowns
            self.cluster_label.setVisible(True)
            self.cluster_selection_dropdown.setVisible(True)
            self.eks_version_label.setVisible(True)
            self.eks_version_dropdown.setVisible(True)
        else:
            # Show node-related section
            self.cluster_section_widget.setVisible(False)
            self.node_group_section_widget.setVisible(True)
            
            # Hide "Select Cluster" and "Select Cluster Version" labels and dropdowns
            self.cluster_label.setVisible(False)  # Add this line to hide the cluster label
            self.cluster_selection_dropdown.setVisible(False)
            self.eks_version_label.setVisible(False)  # Add this line to hide the EKS version label
            self.eks_version_dropdown.setVisible(False)



    def create_eks_management_interface(self, main_layout):
        # ====== Cluster Section ======
        self.cluster_section_widget = QWidget()  # Use QWidget for visibility control
        self.cluster_section = QVBoxLayout(self.cluster_section_widget)
        self.cluster_section_widget.setVisible(True)  # Initially visible
        
        self.cluster_section.addWidget(QLabel("VPC Setup Options:"))
        # Checkbox to use recommended EKS VPC
        self.eks_checkbox = QCheckBox("Use Amazon EKS Recommended VPC")
        self.cluster_section.addWidget(self.eks_checkbox)

        # Upload Button for custom YAML file
        self.upload_button = QPushButton("Upload Custom VPC YAML File")
        self.upload_button.clicked.connect(self.upload_yaml)
        self.cluster_section.addWidget(self.upload_button)

        # Execute VPC creation
        self.create_vpc_button = QPushButton("Create VPC")
        self.create_vpc_button.clicked.connect(self.create_vpc)
        self.cluster_section.addWidget(self.create_vpc_button)

        # Cluster Actions
        self.cluster_section.addWidget(QLabel("Cluster Actions:"))

        # ======= Add Endpoint Configuration Radio Buttons =======
        self.cluster_section.addWidget(QLabel("Select Endpoint Configuration:"))

        self.endpoint_group = QButtonGroup(self)  # Group to hold the radio buttons
        self.public_radio = QRadioButton("Public Only", self)
        self.private_radio = QRadioButton("Private Only", self)
        self.both_radio = QRadioButton("Public and Private", self)

        self.endpoint_group.addButton(self.public_radio)
        self.endpoint_group.addButton(self.private_radio)
        self.endpoint_group.addButton(self.both_radio)

        # Set default option
        self.public_radio.setChecked(True)

        self.cluster_section.addWidget(self.public_radio)
        self.cluster_section.addWidget(self.private_radio)
        self.cluster_section.addWidget(self.both_radio)

        # Cluster action dropdown and button
        self.cluster_action_dropdown = QComboBox(self)
        self.cluster_action_dropdown.addItems([
            "Create Cluster", "Delete Cluster", "Describe Cluster",
            "Update Cluster Version", "Update Cluster Config"
        ])
        self.cluster_execute_button = QPushButton("Execute Cluster Action", self)
        self.cluster_execute_button.clicked.connect(self.execute_cluster_action)

        self.cluster_section.addWidget(self.cluster_action_dropdown)
        self.cluster_section.addWidget(self.cluster_execute_button)

        # ====== Node Group Section (Initially hidden) ======
        self.node_group_section_widget = QWidget()  # Use QWidget for visibility control
        self.node_group_section = QVBoxLayout(self.node_group_section_widget)
        self.node_group_section_widget.setVisible(False)  # Initially hidden
        
        # Node Group Actions
        self.node_group_section.addWidget(QLabel("Node Group Actions:"))

        self.nodegroup_action_dropdown = QComboBox(self)
        self.nodegroup_action_dropdown.addItems([
            "Create Node Group", "Delete Node Group", "Describe Node Group"
        ])
        self.nodegroup_execute_button = QPushButton("Execute Node Group Action", self)
        self.nodegroup_execute_button.clicked.connect(self.execute_nodegroup_action)

        self.node_group_section.addWidget(self.nodegroup_action_dropdown)
        self.node_group_section.addWidget(self.nodegroup_execute_button)
        
        # Initially show only the cluster section
        self.node_group_section_widget.setVisible(False)

        # ====== EKS Role Management Section (Group Components Together) ======
        self.cluster_section.addWidget(QLabel("EKS Role Management:"))

        # Radio buttons for selecting between Node or Cluster role creation
        self.role_type_group = QButtonGroup(self)
        self.cluster_role_radio = QRadioButton("Cluster Role", self)
        self.node_role_radio = QRadioButton("Node Role", self)

        self.role_type_group.addButton(self.cluster_role_radio)
        self.role_type_group.addButton(self.node_role_radio)

        # Set default to Cluster Role
        self.cluster_role_radio.setChecked(True)

        self.cluster_section.addWidget(self.cluster_role_radio)
        self.cluster_section.addWidget(self.node_role_radio)

        # Role Management Dropdowns and Actions
        role_layout = QVBoxLayout()  # Grouping EKS Role Management and Policy Selection

        # Policy dropdown for selecting IAM policies
        self.policy_dropdown = QComboBox(self)
        role_layout.addWidget(QLabel("Select Policy:"))
        role_layout.addWidget(self.policy_dropdown)

        self.role_action_dropdown = QComboBox(self)
        role_layout.addWidget(QLabel("Select Role Action:"))
        self.role_action_dropdown.addItems(["Create EKS Role", "Delete EKS Role"])
        role_layout.addWidget(self.role_action_dropdown)

        self.role_execute_button = QPushButton("Execute Role Action", self)
        self.role_execute_button.clicked.connect(self.execute_role_action)
        role_layout.addWidget(self.role_execute_button)

        self.cluster_section.addLayout(role_layout)

        # ====== Middle Column (Selection Panel) ======
        selection_panel = QVBoxLayout()

        # Region Selection Dropdown
        self.region_selection_dropdown = QComboBox(self)
        self.region_selection_dropdown.currentIndexChanged.connect(self.on_region_selected)

        # Cluster Selection Dropdown
        self.cluster_selection_dropdown = QComboBox(self)
        self.cluster_selection_dropdown.currentIndexChanged.connect(self.on_cluster_selected)

        # Node Group Selection Dropdown (Populated after cluster is selected)
        self.nodegroup_selection_dropdown = QComboBox(self)

        # Dropdowns for EKS Version, IAM Role, VPCs, and Subnets
        self.eks_version_dropdown = QComboBox(self)
        self.eks_role_dropdown = QComboBox(self)

        # VPC Selection
        self.vpc_dropdown = QComboBox(self)
        self.vpc_dropdown.currentIndexChanged.connect(self.on_vpc_selected)

        # Layout for selection panel
        
        selection_panel.addWidget(QLabel("Select Region:"))
        selection_panel.addWidget(self.region_selection_dropdown)

        
        self.cluster_label = QLabel("Select Cluster:")
        selection_panel.addWidget(self.cluster_label)
        selection_panel.addWidget(self.cluster_selection_dropdown)

        selection_panel.addWidget(QLabel("Select Node Group:"))
        selection_panel.addWidget(self.nodegroup_selection_dropdown)

        self.eks_version_label = QLabel("EKS Version:")
        selection_panel.addWidget(self.eks_version_label)
        selection_panel.addWidget(self.eks_version_dropdown)

        selection_panel.addWidget(QLabel("EKS IAM Role:"))
        selection_panel.addWidget(self.eks_role_dropdown)

        selection_panel.addWidget(QLabel("VPC Selection:"))
        selection_panel.addWidget(self.vpc_dropdown)
        
        
       
        
        

        # ====== Right Column (Output Panel) ======
        output_panel = QVBoxLayout()
        self.eks_output_area = QTextEdit(self)
        self.eks_output_area.setReadOnly(True)
        output_panel.addWidget(self.eks_output_area)
        
        
        
        
        
        
        
        
        
        # 1. AMI Type Selection (Fetched asynchronously)
        self.node_group_section.addWidget(QLabel("AMI Type:"))
        self.ami_type_dropdown = QComboBox(self)
        self.node_group_section.addWidget(self.ami_type_dropdown)
        self.fetch_ami_types()

        # 2. Instance Type Selection (Fetched asynchronously)
        self.node_group_section.addWidget(QLabel("Instance Type:"))
        self.instance_type_dropdown = QComboBox(self)
        self.node_group_section.addWidget(self.instance_type_dropdown)
        self.fetch_instance_types()  # Trigger async fetching of instance types

        # 3. Disk Type and Size
        self.node_group_section.addWidget(QLabel("Disk Size (GB):"))
        self.disk_size_input = QLineEdit(self)
        self.disk_size_input.setPlaceholderText("e.g., 20")
        self.node_group_section.addWidget(self.disk_size_input)

        # 4. Scaling Configuration
        self.node_group_section.addWidget(QLabel("Scaling Configuration:"))
        scaling_layout = QHBoxLayout()

        self.min_size_input = QLineEdit(self)
        self.min_size_input.setPlaceholderText("Min Size")
        scaling_layout.addWidget(self.min_size_input)

        self.max_size_input = QLineEdit(self)
        self.max_size_input.setPlaceholderText("Max Size")
        scaling_layout.addWidget(self.max_size_input)

        self.desired_size_input = QLineEdit(self)
        self.desired_size_input.setPlaceholderText("Desired Size")
        scaling_layout.addWidget(self.desired_size_input)

        self.node_group_section.addLayout(scaling_layout)

        # 5. SSH Key Pair Selection
        self.node_group_section.addWidget(QLabel("SSH Key Pair:"))
        self.ssh_checkbox = QCheckBox("Allow SSH access to the nodes", self)
        self.ssh_checkbox.toggled.connect(self.toggle_ssh_key_dropdown)
        self.node_group_section.addWidget(self.ssh_checkbox)

        self.ssh_key_dropdown = QComboBox(self)
        self.ssh_key_dropdown.addItems(self.fetch_ssh_keys())  # Fetch available SSH keys
        self.ssh_key_dropdown.setVisible(False)  # Hide initially
        self.node_group_section.addWidget(self.ssh_key_dropdown)

        # 6. Security Group Selection
        self.node_group_section.addWidget(QLabel("Security Group:"))
        self.security_group_all_radio = QRadioButton("All Security Groups", self)
        self.security_group_specific_radio = QRadioButton("Select Security Group", self)
        self.node_group_section.addWidget(self.security_group_all_radio)
        self.node_group_section.addWidget(self.security_group_specific_radio)

        self.security_group_dropdown = QComboBox(self)
        self.security_group_dropdown.addItems(self.fetch_security_groups())  # Fetch security groups
        self.security_group_dropdown.setVisible(False)  # Hidden until "Select Security Group" is chosen
        self.security_group_specific_radio.toggled.connect(self.toggle_security_group_dropdown)
        self.node_group_section.addWidget(self.security_group_dropdown)

        

        # Create Node Group Button
        self.create_nodegroup_button = QPushButton("Create Node Group", self)
        self.create_nodegroup_button.clicked.connect(self.create_node_group)
        self.node_group_section.addWidget(self.create_nodegroup_button)
            
            
        #**********#    
            

        # Adding the three columns to the main layout
        main_layout.addWidget(self.cluster_section_widget, 1)  # Left Column (Cluster/NodeGroup/Role Management)
        main_layout.addWidget(self.node_group_section_widget, 1)  # Node Group Section (Hidden initially)
        main_layout.addLayout(selection_panel, 1)  # Middle Column (Selection Panel)
        main_layout.addLayout(output_panel, 2)  # Right Column (Output Panel)



    
    
        
        
    def upload_yaml(self):
        # File dialog to upload a custom YAML file
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(self, "Select YAML File", "", "YAML Files (*.yaml *.yml)")

        if file_path:
            self.custom_vpc_yaml_path = file_path
            self.show_message(f"Custom VPC YAML loaded from {file_path}")

    def create_vpc(self):
        if self.eks_checkbox.isChecked():
            # Use the hardcoded Amazon EKS YAML file
            if os.path.exists(self.hardcoded_vpc_yaml_path):
                vpc_name, ok = QInputDialog.getText(self, "VPC Name", "Enter a name for the VPC:")
                if ok and vpc_name:
                    self.create_vpc_from_yaml(self.hardcoded_vpc_yaml_path, vpc_name)
                else:
                    self.show_message("VPC creation cancelled.")
            else:
                self.show_message(f"YAML file not found at {self.hardcoded_vpc_yaml_path}")
        else:
            # Use the uploaded custom YAML file
            if hasattr(self, 'custom_vpc_yaml_path'):
                vpc_name, ok = QInputDialog.getText(self, "VPC Name", "Enter a name for the VPC:")
                if ok and vpc_name:
                    self.create_vpc_from_yaml(self.custom_vpc_yaml_path, vpc_name)
                else:
                    self.show_message("VPC creation cancelled.")
            else:
                self.show_message("Please upload a custom YAML file or select the recommended EKS VPC option.")

    def create_vpc_from_yaml(self, yaml_file_path, vpc_name):
        try:
            # Use cfn-flip to process the YAML file and convert it to JSON for CloudFormation
            command = f"cfn-flip {yaml_file_path}"
            result = subprocess.run(command, shell=True, capture_output=True, text=True)

            if result.returncode != 0:
                raise Exception(result.stderr)

            # The converted JSON template
            template_json = result.stdout

            # Create CloudFormation stack with selected region
            self.create_cloudformation_stack(vpc_name, template_json)

        except Exception as e:
            self.show_message(f"Error processing YAML file: {str(e)}")

    def create_cloudformation_stack(self, stack_name, template_body):
        try:
            # Ensure that CloudFormation client is created with the selected region
            self.cloudformation_client = boto3.client('cloudformation', region_name=self.region_name)

            response = self.cloudformation_client.create_stack(
                StackName=stack_name,
                TemplateBody=template_body,
                Capabilities=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM'],
            )
            self.stack_id = response['StackId']
            self.show_message(f"VPC Stack creation started in {self.region_name}. Stack ID: {self.stack_id}")

            # Start monitoring the stack creation status
            self.monitor_stack_creation(self.stack_id)

        except Exception as e:
            self.show_message(f"Error creating CloudFormation stack: {str(e)}")


            
            
    def monitor_stack_creation(self, stack_id):
        self.stack_timer = QTimer(self)
        self.stack_timer.timeout.connect(lambda: self.check_stack_status(stack_id))
        self.stack_timer.start(10000)  # Check every 10 seconds

    def check_stack_status(self, stack_id):
        try:
            response = self.cloudformation_client.describe_stacks(StackName=stack_id)
            stack_status = response['Stacks'][0]['StackStatus']
            self.show_message(f"Current Stack Status: {stack_status}")

            if stack_status == 'CREATE_COMPLETE':
                self.show_message(f"VPC stack creation completed successfully.")
                self.stop_monitoring_stack()

                # Retrieve VPC ID from the CloudFormation outputs
                outputs = response['Stacks'][0].get('Outputs', [])
                self.show_message(f"Stack Outputs: {outputs}")  # Debugging line to print outputs
                vpc_id = None
                for output in outputs:
                    if output['OutputKey'] == 'VpcId':  # Make sure the key matches your CloudFormation Output
                        vpc_id = output['OutputValue']
                        break

                if vpc_id:
                    self.update_vpc_dropdown(vpc_id)
                else:
                    self.show_message("VPC ID not found in stack outputs.")

            elif 'FAILED' in stack_status or 'ROLLBACK' in stack_status:
                self.show_message(f"VPC stack creation failed with status: {stack_status}")
                self.stop_monitoring_stack()

        except Exception as e:
            self.show_message(f"Error checking stack status: {str(e)}")
            
    def fetch_cloudformation_stacks(self):
        """Fetch all CloudFormation stacks and list their names."""
        try:
            cloudformation_client = self.session.client('cloudformation')
            stacks = cloudformation_client.describe_stacks()['Stacks']

            stack_names = [stack['StackName'] for stack in stacks]  # Get all stack names
            if stack_names:
                self.update_vpc_dropdown(stack_names)
            else:
                self.update_vpc_dropdown([])

        except ClientError as e:
            self.signal_manager.message_signal.emit(f"Error fetching CloudFormation stacks: {str(e)}")


    def fetch_stack_details(self, stack_name):
        """Fetch detailed information about the selected CloudFormation stack and store the relevant details."""
        try:
            # Use describe_stacks to get details about the stack
            response = self.cloudformation_client.describe_stacks(StackName=stack_name)
            stack = response['Stacks'][0]  # Get the first (and likely only) stack in the response
            
            # Get the stack status
            stack_status = stack.get('StackStatus', 'Unknown')
            self.show_message(f"Stack Status for {stack_name}: {stack_status}")
            
            # Optionally, display stack outputs (if there are any)
            outputs = stack.get('Outputs', [])
            self.vpc_id = None
            self.public_subnets = []
            self.private_subnets = []
            self.security_groups = []
            
            for output in outputs:
                if output['OutputKey'] == 'VPC':
                    self.vpc_id = output['OutputValue']
                elif output['OutputKey'] == 'SubnetsPublic':
                    self.public_subnets = output['OutputValue'].split(',')
                elif output['OutputKey'] == 'SubnetsPrivate':
                    self.private_subnets = output['OutputValue'].split(',')
                elif output['OutputKey'] == 'SecurityGroups':
                    self.security_groups = output['OutputValue'].split(',')

            # Display fetched details in the output area
            if self.vpc_id:
                self.show_message(f"Fetched VPC ID: {self.vpc_id}")
            if self.public_subnets or self.private_subnets:
                self.show_message(f"Fetched Public Subnets: {', '.join(self.public_subnets)}")
                self.show_message(f"Fetched Private Subnets: {', '.join(self.private_subnets)}")
            if self.security_groups:
                self.show_message(f"Fetched Security Groups: {', '.join(self.security_groups)}")

        except ClientError as e:
            self.signal_manager.message_signal.emit(f"Error fetching stack details: {str(e)}")







    def stop_monitoring_stack(self):
        if hasattr(self, 'stack_timer'):
            self.stack_timer.stop()
            
            
    def on_vpc_selected(self):
        selected_stack = self.vpc_dropdown.currentText()
        if selected_stack != "Select VPC...":
            self.show_message(f"Selected CloudFormation Stack: {selected_stack}")
            # Fetch stack details and store them for automatic use
            self.fetch_stack_details(selected_stack)


                
                
    def update_vpc_dropdown(self, stack_names):
        """Update the VPC dropdown with a list of CloudFormation stacks."""
        self.vpc_dropdown.clear()
        if stack_names:
            self.vpc_dropdown.addItems(stack_names)
            self.show_message(f"Stacks {stack_names} added to the dropdown.")
        else:
            self.vpc_dropdown.addItem("No stacks found.")

    
                
                

    def connect_signals(self):
        self.signal_manager.message_signal.connect(self.show_message)

    def run_in_thread(self, target, *args):
        thread = threading.Thread(target=target, args=args)
        thread.start()

    def run_in_executor(self, func, *args):
        self.executor.submit(func, *args)

    def update_dropdown(self, dropdown, items, empty_message):
        if items:
            dropdown.clear()
            dropdown.addItems(items)
        else:
            dropdown.clear()
            dropdown.addItem(empty_message)

    def show_message(self, message):
        QMetaObject.invokeMethod(self.eks_output_area, "append", Qt.QueuedConnection, Q_ARG(str, message))

    def populate_regions(self):
        self.run_in_thread(self._fetch_regions)

    def _fetch_regions(self):
        try:
            response = self.ec2_client.describe_regions()
            regions = [region['RegionName'] for region in response['Regions']]
            if not regions:
                regions = ["No regions found"]
            self.region_selection_dropdown.addItems(regions)
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error fetching regions: {str(e)}")

    def on_region_selected(self):
        selected_region = self.region_selection_dropdown.currentText()

        if selected_region != "No regions found":
            self.vpc_dropdown.clear()
            self.vpc_dropdown.addItem("Select VPC...")
            self.region_name = selected_region
            self.eks_client = boto3.client('eks', region_name=selected_region)
            self.ec2_client = boto3.client('ec2', region_name=selected_region)
            
            # Update AMI and Instance Types dynamically for the new region
            self.fetch_ami_types()  # Fetch asynchronously
            self.fetch_instance_types()  # Fetch asynchronously

            
            self.populate_clusters()
            self.fetch_cloudformation_stacks()
        else:
            self.cluster_selection_dropdown.clear()
            self.cluster_selection_dropdown.addItem("No clusters found")


    def populate_versions_and_roles(self):
        self.run_in_executor(self._fetch_eks_versions_and_roles)

    def _fetch_eks_versions_and_roles(self):
        try:
            # Query Kubernetes versions
            response = self.eks_client.describe_addon_versions()
            kubernetes_versions = set()
            for addon in response.get('addons', []):
                for version_info in addon.get('addonVersions', []):
                    for compatibility in version_info.get('compatibilities', []):
                        cluster_version = compatibility.get('clusterVersion')
                        if cluster_version:
                            kubernetes_versions.add(cluster_version)

            # Populate EKS versions dropdown
            if kubernetes_versions:
                sorted_versions = sorted(kubernetes_versions, reverse=True)
                self.update_dropdown(self.eks_version_dropdown, sorted_versions, "No EKS versions found")
            else:
                self.update_dropdown(self.eks_version_dropdown, [], "No EKS versions found")

            # Fetch all IAM roles
            eks_related_roles = []
            next_marker = None

            while True:
                if next_marker:
                    roles_response = self.iam_client.list_roles(Marker=next_marker)
                else:
                    roles_response = self.iam_client.list_roles()

                # Filter roles that have trust relationship with EKS
                for role in roles_response['Roles']:
                    role_name = role['RoleName']
                    # Get the trust policy document to check if it's trusted by eks.amazonaws.com
                    role_trust = self.iam_client.get_role(RoleName=role_name)['Role']['AssumeRolePolicyDocument']
                    for statement in role_trust['Statement']:
                        if 'eks.amazonaws.com' in statement.get('Principal', {}).get('Service', []):
                            eks_related_roles.append(role_name)

                if roles_response.get('IsTruncated'):
                    next_marker = roles_response['Marker']
                else:
                    break

            # Update the EKS IAM Role dropdown with EKS-related roles
            if eks_related_roles:
                self.update_dropdown(self.eks_role_dropdown, eks_related_roles, "No EKS roles found")
            else:
                self.update_dropdown(self.eks_role_dropdown, [], "No EKS roles found")

        except botocore.exceptions.ClientError as e:
            error_message = f"Error fetching versions or roles: {str(e)}"
            self.signal_manager.message_signal.emit(error_message)


    def populate_clusters(self):
        self.run_in_thread(self._fetch_clusters)

    def _fetch_clusters(self):
        try:
            clusters = self.eks_client.list_clusters()['clusters']
            if not clusters:
                clusters = ["No clusters found"]
            self.cluster_selection_dropdown.clear()
            self.cluster_selection_dropdown.addItems(clusters)
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error fetching clusters: {str(e)}")
            
            
    def start_cluster_polling(self):
        self.cluster_polling_timer = QTimer(self)
        self.cluster_polling_timer.timeout.connect(self.populate_clusters)
        self.cluster_polling_timer.start(30000)  # Refresh every 30 seconds

    def stop_cluster_polling(self):
        if hasattr(self, 'cluster_polling_timer'):
            self.cluster_polling_timer.stop()


    def on_cluster_selected(self):
        selected_cluster = self.cluster_selection_dropdown.currentText()
        if selected_cluster != "No clusters found":
            self.run_in_thread(self.list_nodegroups, selected_cluster)
        else:
            self.nodegroup_selection_dropdown.clear()
            self.nodegroup_selection_dropdown.addItem("No node groups found")

    


    def execute_cluster_action(self):
        action = self.cluster_action_dropdown.currentText()

        if action == "Create Cluster":
            self.prompt_create_cluster()  # No threading for GUI interaction
        elif action == "Delete Cluster":
            self.prompt_delete_cluster()  # No threading for GUI interaction
        elif action == "Describe Cluster":
            self.prompt_describe_cluster()  # No threading for GUI interaction
        elif action == "Update Cluster Version":
            self.prompt_update_cluster_version()  # No threading for GUI interaction
        elif action == "Update Cluster Config":
            self.prompt_update_cluster_config()  # No threading for GUI interaction

        
            
            
        

    def prompt_create_cluster(self):
        cluster_name, ok = QInputDialog.getText(self, "Create Cluster", "Enter Cluster Name:")
        if ok and cluster_name:
            self.run_in_thread(self.create_cluster, cluster_name)

    def prompt_delete_cluster(self):
        # Get the currently selected cluster from the dropdown
        cluster_name = self.cluster_selection_dropdown.currentText()

        if cluster_name and cluster_name != "No clusters found":
            # Run the delete cluster function using the selected cluster
            self.run_in_thread(self.delete_cluster, cluster_name)
        else:
            self.signal_manager.message_signal.emit("No cluster selected or found.")


    def prompt_describe_cluster(self):
        # Get the currently selected cluster from the dropdown
        cluster_name = self.cluster_selection_dropdown.currentText()

        if cluster_name and cluster_name != "No clusters found":
            # Run the describe cluster function using the selected cluster
            self.run_in_thread(self.describe_cluster, cluster_name)
        else:
            self.signal_manager.message_signal.emit("No cluster selected or found.")


    def prompt_update_cluster_version(self):
        # Get the currently selected cluster from the dropdown
        cluster_name = self.cluster_selection_dropdown.currentText()

        if cluster_name and cluster_name != "No clusters found":
            # Run the update cluster version function using the selected cluster
            self.run_in_thread(self.update_cluster_version, cluster_name)
        else:
            self.signal_manager.message_signal.emit("No cluster selected or found.")


    def prompt_update_cluster_config(self):
        # Get the currently selected cluster from the dropdown
        cluster_name = self.cluster_selection_dropdown.currentText()

        if cluster_name and cluster_name != "No clusters found":
            # Run the update cluster config function using the selected cluster
            self.run_in_thread(self.update_cluster_config, cluster_name)
        else:
            self.signal_manager.message_signal.emit("No cluster selected or found.")


    def create_cluster(self, cluster_name):
        version = self.eks_version_dropdown.currentText()
        role_name = self.eks_role_dropdown.currentText()

        # Automatically use the subnets and security groups fetched from the selected stack
        vpc_id = self.vpc_id
        subnet_ids = self.public_subnets + self.private_subnets  # Combine public and private subnets
        security_group_ids = self.security_groups

        # Determine the endpoint configuration based on user's selection
        endpoint_public_access = False
        endpoint_private_access = False

        if self.public_radio.isChecked():
            endpoint_public_access = True
            endpoint_private_access = False
        elif self.private_radio.isChecked():
            endpoint_public_access = False
            endpoint_private_access = True
        elif self.both_radio.isChecked():
            endpoint_public_access = True
            endpoint_private_access = True

        # Fetch the AWS account ID dynamically
        account_id = self.sts_client.get_caller_identity()['Account']  # Fetch the account ID dynamically

        # Run the AWS operation in a thread to avoid freezing the UI
        self.run_in_thread(
            self._create_cluster_on_aws,
            cluster_name,
            version,
            role_name,
            subnet_ids,
            security_group_ids,
            endpoint_public_access,
            endpoint_private_access,
            account_id  # Pass the account ID to the thread
        )

    def _create_cluster_on_aws(self, cluster_name, version, role_name, subnet_ids, security_group_ids, endpoint_public_access, endpoint_private_access, account_id):
        try:
            # Use the dynamically fetched account ID in the roleArn
            self.eks_client.create_cluster(
                name=cluster_name,
                version=version,
                roleArn=f"arn:aws:iam::{account_id}:role/{role_name}",  # Dynamically set the account ID
                resourcesVpcConfig={
                    'subnetIds': subnet_ids,
                    'securityGroupIds': security_group_ids,
                    'endpointPublicAccess': endpoint_public_access,
                    'endpointPrivateAccess': endpoint_private_access
                }
            )
            self.signal_manager.message_signal.emit(f"Cluster {cluster_name} creation started.")
            self.start_cluster_polling()
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error creating cluster: {str(e)}")





    def delete_cluster(self, cluster_name):
        try:
            self.eks_client.delete_cluster(name=cluster_name)
            self.signal_manager.message_signal.emit(f"Cluster {cluster_name} deletion started.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error deleting cluster: {str(e)}")

    def describe_cluster(self, cluster_name):
        try:
            response = self.eks_client.describe_cluster(name=cluster_name)
            cluster_info = response['cluster']
            info = (f"Cluster Name: {cluster_info['name']}\n"
                    f"Status: {cluster_info['status']}\n"
                    f"Version: {cluster_info['version']}\n"
                    f"Endpoint: {cluster_info['endpoint']}")
            self.signal_manager.message_signal.emit(info)
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error describing cluster: {str(e)}")

    def update_cluster_version(self, cluster_name):
        version = self.eks_version_dropdown.currentText()
        try:
            self.eks_client.update_cluster_version(name=cluster_name, version=version)
            self.signal_manager.message_signal.emit(f"Cluster {cluster_name} update to version {version} started.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error updating cluster version: {str(e)}")

    def update_cluster_config(self, cluster_name):
        # Extract the current values from the radio buttons
        endpoint_public_access = False
        endpoint_private_access = False

        # Set values based on selected radio button
        if self.public_radio.isChecked():
            endpoint_public_access = True
            endpoint_private_access = False
        elif self.private_radio.isChecked():
            endpoint_public_access = False
            endpoint_private_access = True
        elif self.both_radio.isChecked():
            endpoint_public_access = True
            endpoint_private_access = True

        try:
            # Update the cluster configuration with the values from the radio buttons
            self.eks_client.update_cluster_config(
                name=cluster_name,
                resourcesVpcConfig={
                    'endpointPublicAccess': endpoint_public_access,
                    'endpointPrivateAccess': endpoint_private_access
                }
            )
            self.signal_manager.message_signal.emit(f"Cluster {cluster_name} config update started.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error updating cluster config: {str(e)}")

    def execute_nodegroup_action(self):
        action = self.nodegroup_action_dropdown.currentText()

        if action == "Create Node Group":
            self.run_in_thread(self.prompt_create_nodegroup)
        elif action == "Delete Node Group":
            self.run_in_thread(self.prompt_delete_nodegroup)
        elif action == "Describe Node Group":
            self.run_in_thread(self.prompt_describe_nodegroup)

    def prompt_create_nodegroup(self):
        cluster_name, ok = QInputDialog.getText(self, "Create Node Group", "Enter Cluster Name:")
        if ok and cluster_name:
            nodegroup_name, ok = QInputDialog.getText(self, "Create Node Group", "Enter Node Group Name:")
            if ok and nodegroup_name:
                self.run_in_thread(self.create_nodegroup, cluster_name, nodegroup_name)
                
    def create_node_group(self, cluster_name, nodegroup_name):
        # Submit the task to a background thread
        self.executor.submit(self._create_node_group_on_aws, cluster_name, nodegroup_name)

    def _create_node_group_on_aws(self, cluster_name, nodegroup_name):
        """This method runs in a background thread, handles AWS calls, and emits signals to update the UI."""
        try:
            # Fetch the selected security group from the dropdown
            selected_security_group = self.security_group_dropdown.currentText()

            # Fetch VPC ID based on the selected security group
            vpc_id = self.fetch_vpc_id_from_security_group(selected_security_group)

            if not vpc_id:
                QMetaObject.invokeMethod(self, "show_message", Qt.QueuedConnection, Q_ARG(str, f"Could not find VPC for security group {selected_security_group}."))
                return

            # Fetch all subnets for the VPC
            subnets = self.fetch_subnets_from_vpc(vpc_id)
            if not subnets:
                QMetaObject.invokeMethod(self, "show_message", Qt.QueuedConnection, Q_ARG(str, f"No subnets found for VPC {vpc_id}."))
                return

            # Fetch the AWS account ID dynamically
            account_id = self.sts_client.get_caller_identity()['Account']

            # Perform the Node Group creation on AWS
            self.eks_client.create_nodegroup(
                clusterName=cluster_name,
                nodegroupName=nodegroup_name,
                scalingConfig={
                    'minSize': int(self.min_size_input.text()),
                    'maxSize': int(self.max_size_input.text()),
                    'desiredSize': int(self.desired_size_input.text())
                },
                subnets=subnets,
                nodeRole=f"arn:aws:iam::{account_id}:role/{self.eks_role_dropdown.currentText()}",
                amiType=self.ami_type_dropdown.currentText(),
                instanceTypes=[self.instance_type_dropdown.currentText()],
                remoteAccess={'ec2SshKey': self.ssh_key_dropdown.currentText()} if self.ssh_checkbox.isChecked() else {}
            )

            # Emit success message on the main thread
            QMetaObject.invokeMethod(self, "show_message", Qt.QueuedConnection, Q_ARG(str, f"Node group {nodegroup_name} creation started."))

        except botocore.exceptions.ClientError as e:
            # Emit error message on the main thread
            QMetaObject.invokeMethod(self, "show_message", Qt.QueuedConnection, Q_ARG(str, f"Error creating node group: {str(e)}"))






    def list_nodegroups(self, cluster_name):
        try:
            nodegroups = self.eks_client.list_nodegroups(clusterName=cluster_name)['nodegroups']
            if not nodegroups:
                nodegroups = ["No node groups found"]
            self.nodegroup_selection_dropdown.clear()
            self.nodegroup_selection_dropdown.addItems(nodegroups)
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error listing node groups: {str(e)}")

    def prompt_delete_nodegroup(self):
        cluster_name, ok = QInputDialog.getText(self, "Delete Node Group", "Enter Cluster Name:")
        if ok and cluster_name:
            nodegroup_name, ok = QInputDialog.getText(self, "Delete Node Group", "Enter Node Group Name:")
            if ok and nodegroup_name:
                self.run_in_thread(self.delete_nodegroup, cluster_name, nodegroup_name)

    def delete_nodegroup(self, cluster_name, nodegroup_name):
        try:
            self.eks_client.delete_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
            self.signal_manager.message_signal.emit(f"Node group {nodegroup_name} deletion started.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error deleting node group: {str(e)}")

    def prompt_describe_nodegroup(self):
        cluster_name, ok = QInputDialog.getText(self, "Describe Node Group", "Enter Cluster Name:")
        if ok and cluster_name:
            nodegroup_name, ok = QInputDialog.getText(self, "Describe Node Group", "Enter Node Group Name:")
            if ok and nodegroup_name:
                self.run_in_thread(self.describe_nodegroup, cluster_name, nodegroup_name)

    def describe_nodegroup(self, cluster_name, nodegroup_name):
        try:
            response = self.eks_client.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
            nodegroup_info = response['nodegroup']
            info = (f"Node Group Name: {nodegroup_info['nodegroupName']}\n"
                    f"Status: {nodegroup_info['status']}\n"
                    f"AMI Type: {nodegroup_info['amiType']}")
            self.signal_manager.message_signal.emit(info)
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error describing node group: {str(e)}")

    
            
            
     
    # ======= Populating EKS Policies Dropdown =======
    def populate_policies(self):
        # Pre-defined list of policies related to EKS
        policies = [
            "AmazonEKSClusterPolicy",
            "AmazonEKSServicePolicy",
            "AmazonEKSFargatePodExecutionRolePolicy",
            "AmazonEKSNodePolicy"
        ]
        self.update_dropdown(self.policy_dropdown, policies, "No policies found")
        
        

    # ======= EKS Role Actions (Create and Delete) =======
    def execute_role_action(self):
        action = self.role_action_dropdown.currentText()

        if action == "Create EKS Role":
            if self.cluster_role_radio.isChecked():
                self.prompt_create_eks_role(is_node_role=False)
            elif self.node_role_radio.isChecked():
                self.prompt_create_eks_role(is_node_role=True)
        elif action == "Delete EKS Role":
            self.prompt_delete_eks_role()


    # Function to create an EKS role
    def prompt_create_eks_role(self, is_node_role):
        # Get the role name directly on the main thread
        role_name, ok = QInputDialog.getText(self, "Create EKS Role", "Enter Role Name:")

        if ok and role_name:
            if is_node_role:
                self.create_node_role(role_name)
            else:
                self.create_role_and_attach_policy(role_name)
            self._fetch_eks_versions_and_roles()

    def create_node_role(self, role_name):
        """Create a role for Node and attach recommended policies."""
        try:
            # Step 1: Create the node role
            self._create_eks_iam_role(role_name)

            # Step 2: Attach recommended node policies
            recommended_policies = [
                "AmazonEKSWorkerNodePolicy",
                "AmazonEC2ContainerRegistryReadOnly",
                "AmazonEKS_CNI_Policy"
            ]
            for policy in recommended_policies:
                self._attach_eks_policies(role_name, policy)
                self.show_message(f"Attached {policy} to {role_name}")

            self.show_message(f"Node role {role_name} created successfully!")

        except ClientError as e:
            self.show_message(f"Error creating node role: {str(e)}")

    def create_role_and_attach_policy(self, role_name):
        try:
            # Step 1: Create the role
            self._create_eks_iam_role(role_name)
            self.signal_manager.message_signal.emit(f"Role {role_name} creation successful!")

            # Step 2: Attach the selected policy to the role
            selected_policy = self.policy_dropdown.currentText()  # This can be accessed safely
            self._attach_eks_policies(role_name, selected_policy)
            self.signal_manager.message_signal.emit(f"Policy {selected_policy} attached to {role_name}")
            
            self._fetch_eks_versions_and_roles()

        except ClientError as e:
            self.signal_manager.message_signal.emit(f"Error: {str(e)}")


    def _create_eks_iam_role(self, role_name):
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "eks.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ]
        }

        try:
            response = self.iam_client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Description="Role to allow EKS to manage clusters",
                MaxSessionDuration=3600
            )
            self.signal_manager.message_signal.emit(f"Role {role_name} created successfully!")
            return response

        except ClientError as e:
            self.signal_manager.message_signal.emit(f"Error creating role: {str(e)}")
            raise


    def _attach_eks_policies(self, role_name, policy_name):
        try:
            policy_arn = f"arn:aws:iam::aws:policy/{policy_name}"
            self.iam_client.attach_role_policy(
                RoleName=role_name,
                PolicyArn=policy_arn
            )
            self.signal_manager.message_signal.emit(f"Attached {policy_arn} to {role_name}")
        except ClientError as e:
            self.signal_manager.message_signal.emit(f"Error attaching policy {policy_arn}: {str(e)}")


    # Function to delete an EKS role
    def prompt_delete_eks_role(self):
        # Get the IAM role selected from the dropdown
        role_name = self.eks_role_dropdown.currentText()
        
        if role_name and role_name != "No EKS roles found":
            try:
                # Step 1: Detach all attached policies
                attached_policies = self.iam_client.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
                for policy in attached_policies:
                    self.iam_client.detach_role_policy(RoleName=role_name, PolicyArn=policy['PolicyArn'])
                    self.signal_manager.message_signal.emit(f"Detached policy {policy['PolicyName']} from role {role_name}")
                
                # Step 2: Now delete the IAM role
                self.iam_client.delete_role(RoleName=role_name)
                self.signal_manager.message_signal.emit(f"Role {role_name} deleted successfully!")
            except ClientError as e:
                self.signal_manager.message_signal.emit(f"Error deleting role: {str(e)}")
        else:
            self.signal_manager.message_signal.emit("No valid role selected for deletion.")




    ###################################
    def fetch_ssh_keys(self):
        try:
            response = self.ec2_client.describe_key_pairs()
            return [key['KeyName'] for key in response['KeyPairs']]
        except botocore.exceptions.ClientError as e:
            self.show_message(f"Error fetching SSH key pairs: {str(e)}")
            return []





    def fetch_security_groups(self):
        try:
            response = self.ec2_client.describe_security_groups()
            return [group['GroupName'] for group in response['SecurityGroups']]
        except botocore.exceptions.ClientError as e:
            self.show_message(f"Error fetching security groups: {str(e)}")
            return []


    def fetch_vpc_id_from_security_group(self, security_group_name):
        try:
            response = self.ec2_client.describe_security_groups(GroupNames=[security_group_name])
            return response['SecurityGroups'][0]['VpcId']
        except botocore.exceptions.ClientError as e:
            self.show_message(f"Error fetching VPC ID for security group {security_group_name}: {str(e)}")
            return None
        
    def fetch_subnets_from_vpc(self, vpc_id):
        try:
            response = self.ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
            return [subnet['SubnetId'] for subnet in response['Subnets']]
        except botocore.exceptions.ClientError as e:
            self.show_message(f"Error fetching subnets for VPC {vpc_id}: {str(e)}")
            return []




    def toggle_ssh_key_dropdown(self):
        self.ssh_key_dropdown.setVisible(self.ssh_checkbox.isChecked())


    def toggle_security_group_dropdown(self):
        self.security_group_dropdown.setVisible(self.security_group_specific_radio.isChecked())
        
        
    # Fetch AMI types using ThreadPoolExecutor
    # Fetch AMI types using ThreadPoolExecutor
    # Fetch AMI types using ThreadPoolExecutor
    def fetch_ami_types(self):
        """Fetch AMI types in a background thread and update UI on the main thread."""
        def _fetch_ami_types():
            try:
                # Fetching AMI info
                os_filters = {
                    "Amazon Linux": [{'Name': 'name', 'Values': ['amzn2-ami-hvm-*']}],
                    "Ubuntu": [{'Name': 'name', 'Values': ['ubuntu/images/hvm-ssd/ubuntu-*-*']}],
                    "Debian": [{'Name': 'name', 'Values': ['debian-*-*']}]
                }

                ami_info = []

                for os_name, filters in os_filters.items():
                    response = self.ec2_client.describe_images(Owners=['amazon'], Filters=filters)
                    for image in response['Images']:
                        ami_name = image.get('Name', 'Unnamed')
                        ami_id = image['ImageId']
                        ami_info.append(f"{os_name}: {ami_name} ({ami_id})")

                return ami_info
            except botocore.exceptions.ClientError:
                return []

        # Execute in a thread pool, callback to update UI on main thread
        future = self.executor.submit(_fetch_ami_types)
        future.add_done_callback(lambda f: QMetaObject.invokeMethod(self, "update_ami_types_ui", Qt.QueuedConnection, Q_ARG(list, f.result())))

    def fetch_instance_types(self):
        """Fetch instance types in a background thread and update UI on the main thread."""
        def _fetch_instance_types():
            try:
                response = self.ec2_client.describe_instance_types()
                return [instance['InstanceType'] for instance in response['InstanceTypes']]
            except botocore.exceptions.ClientError:
                return []

        # Execute in a thread pool, callback to update UI on main thread
        future = self.executor.submit(_fetch_instance_types)
        future.add_done_callback(lambda f: QMetaObject.invokeMethod(self, "update_instance_types_ui", Qt.QueuedConnection, Q_ARG(list, f.result())))

    # Callbacks to update the UI with fetched data
   # This helper method schedules the actual UI update to run on the main thread.
    @pyqtSlot(list)
    def _update_ami_types_main_thread(self, ami_types):
        QMetaObject.invokeMethod(self, "_update_ami_types", Qt.QueuedConnection, Q_ARG(list, ami_types))

    @pyqtSlot(list)
    def _update_instance_types_main_thread(self, instance_types):
        QMetaObject.invokeMethod(self, "_update_instance_types", Qt.QueuedConnection, Q_ARG(list, instance_types))

    # Callbacks to update the UI with fetched data
    @pyqtSlot(list)
    def update_ami_types_ui(self, ami_types):
        """Update AMI dropdown UI safely on the main thread."""
        self.ami_type_dropdown.clear()
        if ami_types:
            self.ami_type_dropdown.addItems(ami_types)
        else:
            self.ami_type_dropdown.addItem("No AMI types found")

    @pyqtSlot(list)
    def update_instance_types_ui(self, instance_types):
        """Update instance type dropdown UI safely on the main thread."""
        self.instance_type_dropdown.clear()
        if instance_types:
            self.instance_type_dropdown.addItems(instance_types)
        else:
            self.instance_type_dropdown.addItem("No instance types found")




