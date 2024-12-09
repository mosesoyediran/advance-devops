import json
import re
import sys
import threading

import boto3
import botocore
from botocore.exceptions import ClientError, ParamValidationError
from PyQt5.QtCore import Q_ARG, QMetaObject, QObject, Qt, pyqtSignal
from PyQt5.QtWidgets import (QApplication, QComboBox, QFileDialog, QFormLayout,
                             QGroupBox, QHBoxLayout, QInputDialog, QLabel,
                             QLineEdit, QListWidget, QListWidgetItem,
                             QMessageBox, QPushButton, QTextEdit, QVBoxLayout,
                             QWidget)


class SignalManager(QObject):
    message_signal = pyqtSignal(str)
    clear_signal = pyqtSignal()
    

class MultiSelectComboBox(QComboBox):
    def __init__(self, parent=None):
        super(MultiSelectComboBox, self).__init__(parent)
        # Disable default ComboBox behavior
        self.setEditable(True)
        self.lineEdit().setReadOnly(True)
        self.lineEdit().setPlaceholderText("Select Subnets")

        # Create a QListWidget as a popup for multi-selection
        self.list_widget = QListWidget()
        self.list_widget.setWindowFlags(Qt.Popup)
        self.list_widget.setSelectionMode(QListWidget.MultiSelection)

        # Set up signals
        self.lineEdit().mousePressEvent = self.show_popup

    def add_item(self, text):
        """Add an item with a checkbox to the list."""
        item = QListWidgetItem(self.list_widget)
        item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
        item.setCheckState(Qt.Unchecked)
        item.setText(text)

    def show_popup(self, event):
        """Show the popup with the list widget."""
        self.list_widget.setGeometry(self.geometry())
        self.list_widget.show()

    def selected_items(self):
        """Return a list of selected items' texts."""
        return [item.text() for item in self.list_widget.findItems('*', Qt.MatchWildcard) if item.checkState() == Qt.Checked]

    def hidePopup(self):
        """Update combo box display when the popup is closed."""
        selected_texts = ", ".join(self.selected_items())
        self.lineEdit().setText(selected_texts)
        super().hidePopup()


class ELBTab(QWidget):
    def __init__(self, session):
        super().__init__()
        self.current_session = session
        self.elbv2_client = session.client('elbv2')
        self.ec2_client = session.client('ec2')
        self.signal_manager = SignalManager()
        self.initUI()
        self.connect_signals()
        self.load_regions()

    def initUI(self):
        main_layout = QHBoxLayout()

        # Left Column: Configuration and Actions
        left_column = QVBoxLayout()
        config_layout = QFormLayout()
        
        # Group Box for Management (Region, VPC, Security Group, Subnets)
        management_group = QGroupBox("Management")
        management_layout = QFormLayout()

        # Reduce margins and spacing for a compact look
        management_layout.setContentsMargins(5, 5, 5, 5)
        management_layout.setSpacing(5)

        # Region Selection
        self.region_dropdown = QComboBox(self)
        management_layout.addRow(QLabel("Select Region:"), self.region_dropdown)

        # VPC Selection
        self.vpc_dropdown = QComboBox(self)
        management_layout.addRow(QLabel("Select VPC:"), self.vpc_dropdown)

        # Security Group Selection
        self.security_group_dropdown = QComboBox(self)
        management_layout.addRow(QLabel("Select Security Group:"), self.security_group_dropdown)

        # Subnets Selection (QListWidget for multi-select with compact height)
        self.subnet_list = QListWidget(self)
        self.subnet_list.setSelectionMode(QListWidget.MultiSelection)
        self.subnet_list.setMaximumHeight(50)  # Compact height for subnets list
        management_layout.addRow(QLabel("Select Subnets:"), self.subnet_list)

        # Set the compact layout for the group box
        management_group.setLayout(management_layout)

        # Make the group box as compact as possible
        management_group.setMaximumHeight(200)  # Adjust as needed for compactness

        config_layout.addRow(management_group)
        
        
        

        # Configure Load Balancer
        # Group Box for Action Management
        action_group = QGroupBox("Action Management")
        action_layout = QFormLayout()

        # Compact look for action group
        action_layout.setContentsMargins(5, 5, 5, 5)
        action_layout.setSpacing(5)

        # Load Balancer Dropdown
        self.elb_dropdown = QComboBox(self)
        action_layout.addRow(QLabel("Select ELB:"), self.elb_dropdown)

        # Load Balancer Type
        self.lb_type_dropdown = QComboBox(self)
        self.lb_type_dropdown.addItems(["application", "network", "gateway"])
        action_layout.addRow(QLabel("Load Balancer Type:"), self.lb_type_dropdown)

        # Scheme
        self.lb_scheme_dropdown = QComboBox(self)
        self.lb_scheme_dropdown.addItems(["internet-facing", "internal"])
        action_layout.addRow(QLabel("Scheme:"), self.lb_scheme_dropdown)

        # Action Dropdown
        self.action_dropdown = QComboBox(self)
        self.action_dropdown.addItems([
            "Load Balancer: Create", "Load Balancer: Describe",  "Load Balancer: Delete",
            "Listener: Create", "Listener: Delete",
            "Target Group: Create", "Target Group: Delete",
            "Health Check: Configure"
        ])
        action_layout.addRow(QLabel("Select Action:"), self.action_dropdown)

        # Execute Button
        self.execute_action_button = QPushButton("Execute Action", self)
        action_layout.addRow(self.execute_action_button)

        # Set layout for action group
        action_group.setLayout(action_layout)
        action_group.setMaximumHeight(200)  # Adjust as needed for compactness

        # Add both management and action groups to the configuration layout
        config_layout = QVBoxLayout()
        config_layout.addWidget(management_group)
        config_layout.addWidget(action_group)

        left_column.addLayout(config_layout)

        # Right Column: Output Area
        right_column = QVBoxLayout()
        self.output_area = QTextEdit(self)
        self.output_area.setReadOnly(True)
        right_column.addWidget(QLabel("ELB Action Output:"))
        right_column.addWidget(self.output_area)

        # Add columns to the main layout
        main_layout.addLayout(left_column, 2)
        main_layout.addLayout(right_column, 3)
        self.setLayout(main_layout)
        
        

    def connect_signals(self):
        self.signal_manager.message_signal.connect(self.show_message)
        self.signal_manager.clear_signal.connect(self.clear_output_area)

        # Connect region change to update clients and load VPCs
        self.region_dropdown.currentIndexChanged.connect(self.update_region_clients)

        # Connect VPC change to load subnets and security groups
        self.vpc_dropdown.currentIndexChanged.connect(self.load_subnets_and_security_groups)
        # Connect execute button to its function
        self.execute_action_button.clicked.connect(self.execute_action)
        

        

    def run_action_in_thread(self):
        # Run action execution in a separate thread
        thread = threading.Thread(target=self.execute_action)
        thread.start()
        
        
    def update_region_clients(self):
        # Update boto3 client for the selected region
        selected_region = self.region_dropdown.currentText()
        self.elbv2_client = self.current_session.client('elbv2', region_name=selected_region)
        self.ec2_client = self.current_session.client('ec2', region_name=selected_region)
        self.load_vpcs()
        self.load_elbs()

    def load_regions(self):
        try:
            ec2 = self.current_session.client('ec2')
            response = ec2.describe_regions()
            regions = [region['RegionName'] for region in response['Regions']]
            self.region_dropdown.addItems(regions)
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error loading regions: {str(e)}")

    def load_vpcs(self):
        try:
            response = self.ec2_client.describe_vpcs()
            vpcs = response.get('Vpcs', [])
            self.vpc_dropdown.clear()
            for vpc in vpcs:
                vpc_id = vpc['VpcId']
                self.vpc_dropdown.addItem(vpc_id)
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error loading VPCs: {str(e)}")

    def load_subnets_for_vpc(self):
        # Clear subnet list before adding new ones
        self.subnet_list.clear()

        # Get the selected VPC ID
        selected_vpc_id = self.vpc_dropdown.currentText()
        try:
            response = self.ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [selected_vpc_id]}])
            subnets = response.get('Subnets', [])
            for subnet in subnets:
                subnet_id = subnet['SubnetId']
                self.subnet_list.addItem(subnet_id)
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error loading subnets for VPC '{selected_vpc_id}': {str(e)}")

            
    def load_subnets_and_security_groups(self):
        self.load_subnets_for_vpc()
        self.load_security_groups()
            
    def load_security_groups(self):
        # Clear security group dropdown before adding new ones
        self.security_group_dropdown.clear()

        # Get the selected VPC ID
        selected_vpc_id = self.vpc_dropdown.currentText()
        try:
            response = self.ec2_client.describe_security_groups(Filters=[{'Name': 'vpc-id', 'Values': [selected_vpc_id]}])
            security_groups = response.get('SecurityGroups', [])
            for sg in security_groups:
                sg_id = sg['GroupId']
                self.security_group_dropdown.addItem(sg_id)
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error loading security groups for VPC '{selected_vpc_id}': {str(e)}")


    # Load Balancer Management
    def load_elbs(self):
        # Clear the ELB dropdown before populating
        self.elb_dropdown.clear()

        try:
            # Fetch the list of ELBs in the selected region
            paginator = self.elbv2_client.get_paginator('describe_load_balancers')
            load_balancers = []

            for page in paginator.paginate():
                for lb in page['LoadBalancers']:
                    lb_name = lb['LoadBalancerName']
                    load_balancers.append(lb_name)
            
            # Populate the ELB dropdown
            if load_balancers:
                self.elb_dropdown.addItems(load_balancers)
                self.signal_manager.message_signal.emit(f"Loaded {len(load_balancers)} load balancers.")
            else:
                self.signal_manager.message_signal.emit("No load balancers found in the selected region.")
        
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error loading ELBs: {str(e)}")

    def execute_action(self):
        action = self.action_dropdown.currentText()

        if action == "Load Balancer: Create":
            # Get the name for the Load Balancer
            self.prompt_for_lb_name()
        elif action == "Load Balancer: Describe":
            self.describe_load_balancer()
        elif action == "Load Balancer: Delete":
            self.delete_load_balancer()
        elif action == "Listener: Create":
            self.create_listener()
        elif action == "Listener: Delete":
            self.delete_listener()
        elif action == "Target Group: Create":
            self.create_target_group()
        elif action == "Target Group: Delete":
            self.delete_target_group()
        elif action == "Health Check: Configure":
            self.configure_health_check()



    def run_create_lb_in_thread(self, lb_name):
        # Start the create_load_balancer function in a new thread
        thread = threading.Thread(target=self.create_load_balancer, args=(lb_name,))
        thread.setDaemon(True)  # Ensures thread does not block the application exit
        thread.start()

        
    def prompt_for_lb_name(self):
        lb_name, ok = QInputDialog.getText(self, "Create Load Balancer", "Enter load balancer name:")

        if ok and lb_name.strip():
            # Proceed to create the load balancer on a separate thread
            self.run_create_lb_in_thread(lb_name.strip())
        else:
            # Signal if the input is not valid or canceled
            self.signal_manager.message_signal.emit("Load Balancer creation canceled or name is invalid.")


    
    
    def create_load_balancer(self, lb_name):
        # Get values from the dropdowns
        lb_type = self.lb_type_dropdown.currentText()
        scheme = self.lb_scheme_dropdown.currentText()
        
        # Get all selected subnets from QListWidget
        subnets = [item.text() for item in self.subnet_list.selectedItems()]
        security_groups = [self.security_group_dropdown.currentText()]  # Using dropdown for security groups
        ip_address_type = 'ipv4'  # Set to ipv4 by default

        # Validate that at least two subnets are selected
        if len(subnets) < 2:
            self.signal_manager.message_signal.emit("At least two subnets must be selected.")
            return

        self.signal_manager.message_signal.emit(
            f"Creating Load Balancer '{lb_name}' of type '{lb_type}' with scheme '{scheme}' in subnets {subnets}..."
        )

        # Execute the creation of the load balancer using boto3
        try:
            response = self.elbv2_client.create_load_balancer(
                Name=lb_name,
                Subnets=subnets,
                SecurityGroups=security_groups if lb_type == 'application' else None,  # Only needed for ALB
                Scheme=scheme,
                Type=lb_type,
                IpAddressType=ip_address_type
            )
            lb_arn = response['LoadBalancers'][0]['LoadBalancerArn']
            self.signal_manager.message_signal.emit(f"Load Balancer '{lb_name}' created successfully. ARN: {lb_arn}")
            self.load_elbs()  # Refresh ELBs dropdown after creation
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error creating load balancer: {str(e)}")
            
            
        
    def describe_load_balancer(self):
        # Get the selected load balancer name from the ELB dropdown
        selected_elb = self.elb_dropdown.currentText()
        
        if not selected_elb:
            self.signal_manager.message_signal.emit("No Load Balancer selected to describe.")
            return

        self.signal_manager.message_signal.emit(f"Fetching details for Load Balancer '{selected_elb}'...")

        try:
            # Describe the load balancer using its name
            response = self.elbv2_client.describe_load_balancers(Names=[selected_elb])
            lb = response['LoadBalancers'][0]

            # Extract key details for display
            details = (
                f"Load Balancer Name: {lb['LoadBalancerName']}\n"
                f"ARN: {lb['LoadBalancerArn']}\n"
                f"DNS Name: {lb['DNSName']}\n"
                f"Type: {lb['Type']}\n"
                f"Scheme: {lb['Scheme']}\n"
                f"State: {lb['State']['Code']}\n"
                f"VPC: {lb['VpcId']}\n"
                f"Availability Zones:\n"
            )

            for az in lb['AvailabilityZones']:
                details += f"  - Zone: {az['ZoneName']}, Subnet: {az['SubnetId']}\n"

            # Emit the formatted details to the output area
            self.signal_manager.message_signal.emit(details)

        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error describing Load Balancer '{selected_elb}': {str(e)}")







    def delete_load_balancer(self):
        # Get the selected load balancer name from the ELB dropdown
        selected_elb = self.elb_dropdown.currentText()
        
        if not selected_elb:
            self.signal_manager.message_signal.emit("No Load Balancer selected for deletion.")
            return

        self.signal_manager.message_signal.emit(f"Deleting Load Balancer '{selected_elb}'...")

        try:
            # Get the ARN of the selected load balancer
            response = self.elbv2_client.describe_load_balancers(Names=[selected_elb])
            load_balancer_arn = response['LoadBalancers'][0]['LoadBalancerArn']
            
            # Delete the load balancer
            self.elbv2_client.delete_load_balancer(LoadBalancerArn=load_balancer_arn)
            
            self.signal_manager.message_signal.emit(f"Load Balancer '{selected_elb}' deleted successfully.")
            
            # Refresh the ELB dropdown after deletion
            self.load_elbs()
        
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error deleting Load Balancer '{selected_elb}': {str(e)}")


    def create_listener(self):
        # Step 1: Get the selected ELB and ensure it's not empty
        selected_elb = self.elb_dropdown.currentText()
        if not selected_elb:
            self.signal_manager.message_signal.emit("No Load Balancer selected to add a listener.")
            return
        
        # Step 2: Get user input for protocol and port
        protocol, port, target_group_arn = self.get_listener_details()
        
        # If any of the details are missing or canceled, stop further execution
        if not protocol or not port or not target_group_arn:
            self.signal_manager.message_signal.emit("Listener creation canceled or details are invalid.")
            return

        self.signal_manager.message_signal.emit(f"Adding a listener to Load Balancer '{selected_elb}' with protocol {protocol} and port {port}...")

        try:
            # Step 3: Describe the load balancer to get its ARN
            response = self.elbv2_client.describe_load_balancers(Names=[selected_elb])
            lb_arn = response['LoadBalancers'][0]['LoadBalancerArn']

            # Step 4: Create listener
            response = self.elbv2_client.create_listener(
                LoadBalancerArn=lb_arn,
                Protocol=protocol,
                Port=int(port),
                DefaultActions=[
                    {
                        'Type': 'forward',
                        'TargetGroupArn': target_group_arn
                    }
                ]
            )
            
            listener_arn = response['Listeners'][0]['ListenerArn']
            self.signal_manager.message_signal.emit(f"Listener created successfully. ARN: {listener_arn}")
            
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error adding listener to Load Balancer '{selected_elb}': {str(e)}")

    def get_listener_details(self):
        # Prompt user for protocol
        protocol, protocol_ok = QInputDialog.getItem(
            self, "Select Protocol", "Choose protocol for the listener:",
            ["HTTP", "HTTPS", "TCP"], 0, False
        )
        
        if not protocol_ok:
            return None, None, None
        
        # Prompt user for port
        port, port_ok = QInputDialog.getText(
            self, "Listener Port", "Enter port for the listener (e.g., 80, 443):"
        )
        
        if not port_ok or not port.isdigit():
            self.signal_manager.message_signal.emit("Invalid or missing port.")
            return None, None, None

        # Prompt user to select a target group
        target_group_arn, target_group_ok = self.get_target_group_arn()
        
        if not target_group_ok:
            self.signal_manager.message_signal.emit("Invalid or missing target group ARN.")
            return None, None, None

        return protocol, port, target_group_arn

    def get_target_group_arn(self):
        # Example method to fetch available target groups
        target_groups = self.fetch_target_groups()

        # Check if there are any target groups to select from
        if not target_groups:
            self.signal_manager.message_signal.emit("No target groups available for selection.")
            return None, False

        # Allow user to select a target group from a dropdown
        target_group_arn, ok = QInputDialog.getItem(
            self, "Select Target Group", "Choose a target group for the listener:",
            target_groups, 0, False
        )
        return target_group_arn, ok


    def delete_listener(self):
        # Step 1: Get the selected ELB
        selected_elb = self.elb_dropdown.currentText()
        if not selected_elb:
            self.signal_manager.message_signal.emit("No Load Balancer selected to delete a listener.")
            return

        try:
            # Step 2: Describe the load balancer to get its ARN
            response = self.elbv2_client.describe_load_balancers(Names=[selected_elb])
            lb_arn = response['LoadBalancers'][0]['LoadBalancerArn']
            
            # Step 3: Describe listeners associated with this load balancer
            response = self.elbv2_client.describe_listeners(LoadBalancerArn=lb_arn)
            listeners = response['Listeners']
            
            if not listeners:
                self.signal_manager.message_signal.emit(f"No listeners found for Load Balancer '{selected_elb}'.")
                return
            
            # Step 4: Prompt user to select a listener to delete
            listener_arn, ok = self.prompt_for_listener_choice(listeners)
            
            if not ok or not listener_arn:
                self.signal_manager.message_signal.emit("Listener deletion canceled or invalid choice.")
                return

            # Step 5: Delete the listener
            self.elbv2_client.delete_listener(ListenerArn=listener_arn)
            self.signal_manager.message_signal.emit(f"Listener '{listener_arn}' deleted successfully.")

        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error deleting listener: {str(e)}")


    def prompt_for_listener_choice(self, listeners):
        # Prepare a list of listener descriptions for the user to choose from
        listener_choices = [f"{listener['Protocol']} on port {listener['Port']}" for listener in listeners]
        
        # Display a dialog to choose the listener to delete
        listener_choice, ok = QInputDialog.getItem(
            self, "Select Listener", "Choose a listener to delete:", listener_choices, 0, False
        )
        
        # If user makes a valid choice, get the corresponding ARN
        if ok and listener_choice:
            # Find the listener with the matching description
            for listener in listeners:
                description = f"{listener['Protocol']} on port {listener['Port']}"
                if description == listener_choice:
                    return listener['ListenerArn'], True
                    
        return None, False


    def create_target_group(self):
        # Step 1: Get necessary parameters for target group creation
        self.signal_manager.message_signal.emit("Collecting parameters for Target Group creation...")

        vpc_id = self.vpc_dropdown.currentText()
        if not vpc_id:
            self.signal_manager.message_signal.emit("No VPC selected. Please select a VPC to create a Target Group.")
            return
        
        # Step 2: Prompt user for the target group name, protocol, and port
        tg_name, ok = QInputDialog.getText(self, "Create Target Group", "Enter target group name:")
        if not ok or not tg_name.strip():
            self.signal_manager.message_signal.emit("Target Group creation canceled or invalid name.")
            return
        
        protocol, ok = QInputDialog.getItem(
            self, "Target Group Protocol", "Select protocol:", ["HTTP", "HTTPS", "TCP", "UDP"], 0, False
        )
        if not ok or not protocol:
            self.signal_manager.message_signal.emit("Target Group creation canceled or invalid protocol.")
            return

        port, ok = QInputDialog.getInt(self, "Target Group Port", "Enter target group port:", 80, 1, 65535, 1)
        if not ok:
            self.signal_manager.message_signal.emit("Target Group creation canceled or invalid port.")
            return

        # Step 3: Set default health check configuration
        health_protocol = "HTTP" if protocol in ["HTTP", "HTTPS"] else "TCP"
        health_path = "/"
        health_interval = 30  # Default to 30 seconds

        # Step 4: Create target group
        try:
            response = self.elbv2_client.create_target_group(
                Name=tg_name.strip(),
                Protocol=protocol,
                Port=port,
                VpcId=vpc_id,
                HealthCheckProtocol=health_protocol,
                HealthCheckPath=health_path if health_protocol == "HTTP" else None,
                HealthCheckIntervalSeconds=health_interval,
                TargetType='instance'  # Assuming target type is EC2 instances; can be 'ip' or 'lambda'
            )

            tg_arn = response['TargetGroups'][0]['TargetGroupArn']
            self.signal_manager.message_signal.emit(f"Target Group '{tg_name}' created successfully. ARN: {tg_arn}")

        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error creating target group: {str(e)}")



    def configure_health_check(self):
        self.signal_manager.message_signal.emit("Configuring Health Check for Target Group...")

        vpc_id = self.vpc_dropdown.currentText()
        if not vpc_id:
            self.signal_manager.message_signal.emit("No VPC selected. Please select a VPC to configure health check.")
            return

        try:
            # Get all target groups
            response = self.elbv2_client.describe_target_groups()
            target_groups = response.get('TargetGroups', [])

            # Filter target groups associated with the selected VPC
            tg_names = [tg['TargetGroupName'] for tg in target_groups if tg['VpcId'] == vpc_id]

            if not tg_names:
                self.signal_manager.message_signal.emit("No Target Groups found in the selected VPC.")
                return

            # Prompt user to select the target group to configure
            tg_name, ok = QInputDialog.getItem(self, "Configure Health Check", "Select Target Group:", tg_names, 0, False)
            if not ok or not tg_name:
                self.signal_manager.message_signal.emit("Health Check configuration canceled.")
                return
            
            # Find the ARN of the selected target group
            tg_arn = next(tg['TargetGroupArn'] for tg in target_groups if tg['TargetGroupName'] == tg_name)

            # Gather health check parameters
            health_protocol, ok = QInputDialog.getItem(
                self, "Health Check Protocol", "Select protocol:", ["HTTP", "HTTPS", "TCP"], 0, False
            )
            if not ok or not health_protocol:
                self.signal_manager.message_signal.emit("Health Check configuration canceled or invalid protocol.")
                return

            health_path = "/"
            if health_protocol in ["HTTP", "HTTPS"]:
                health_path, ok = QInputDialog.getText(self, "Health Check Path", "Enter health check path (e.g., /health):")
                if not ok or not health_path.strip():
                    self.signal_manager.message_signal.emit("Health Check configuration canceled or invalid path.")
                    return

            health_interval, ok = QInputDialog.getInt(self, "Health Check Interval", "Enter health check interval (seconds):", 30, 5, 300, 5)
            if not ok:
                self.signal_manager.message_signal.emit("Health Check configuration canceled or invalid interval.")
                return

            # Update the target group health check settings
            self.elbv2_client.modify_target_group(
                TargetGroupArn=tg_arn,
                HealthCheckProtocol=health_protocol,
                HealthCheckPath=health_path if health_protocol in ["HTTP", "HTTPS"] else None,
                HealthCheckIntervalSeconds=health_interval
            )

            self.signal_manager.message_signal.emit(f"Health Check configured successfully for Target Group '{tg_name}'.")
        
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error configuring health check: {str(e)}")

        
    def delete_target_group(self):
        self.signal_manager.message_signal.emit("Fetching Target Groups for deletion...")
        
        # Fetch all target groups in the selected VPC
        vpc_id = self.vpc_dropdown.currentText()
        if not vpc_id:
            self.signal_manager.message_signal.emit("No VPC selected. Please select a VPC to delete a Target Group.")
            return
        
        try:
            # Get all target groups
            response = self.elbv2_client.describe_target_groups()
            target_groups = response.get('TargetGroups', [])
            
            # Filter target groups associated with the selected VPC
            tg_names = [tg['TargetGroupName'] for tg in target_groups if tg['VpcId'] == vpc_id]
            
            if not tg_names:
                self.signal_manager.message_signal.emit("No Target Groups found in the selected VPC.")
                return
            
            # Prompt user to select the target group to delete
            tg_name, ok = QInputDialog.getItem(self, "Delete Target Group", "Select Target Group:", tg_names, 0, False)
            if not ok or not tg_name:
                self.signal_manager.message_signal.emit("Target Group deletion canceled.")
                return
            
            # Find the ARN of the selected target group
            tg_arn = next(tg['TargetGroupArn'] for tg in target_groups if tg['TargetGroupName'] == tg_name)

            # Delete the target group
            self.elbv2_client.delete_target_group(TargetGroupArn=tg_arn)
            self.signal_manager.message_signal.emit(f"Target Group '{tg_name}' deleted successfully.")
        
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error deleting target group: {str(e)}")


    def show_message(self, message):
        QMetaObject.invokeMethod(
            self.output_area, "append", Qt.QueuedConnection, Q_ARG(str, message)
        )

    def clear_output_area(self):
        QMetaObject.invokeMethod(self.output_area, "clear", Qt.QueuedConnection)
