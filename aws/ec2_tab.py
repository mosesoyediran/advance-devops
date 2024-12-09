import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

import boto3
import botocore
from PyQt5.QtCore import Q_ARG, QMetaObject, QObject, Qt, QTimer, pyqtSignal
from PyQt5.QtWidgets import (QComboBox, QFormLayout, QHBoxLayout, QInputDialog,
                             QLabel, QLineEdit, QPushButton, QTableWidget,
                             QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget)


class SignalManager(QObject):
    message_signal = pyqtSignal(str)
    clear_signal = pyqtSignal()
    keypair_signal = pyqtSignal(list)
    sg_details_signal = pyqtSignal(tuple)


class EC2Tab(QWidget):
    def __init__(self, session):
        super().__init__()
        self.session = session
        self.ec2_client = session.client('ec2')
        self.signal_manager = SignalManager()
        self.executor = ThreadPoolExecutor(max_workers=5) 
        self.ingress_rules = []  # For custom ingress rules
        self.egress_rules = []   # For custom egress rules
        self.ami_details_map = {}
        self.initUI()
        self.connect_signals()

    def initUI(self):
        main_layout = QHBoxLayout()

        # ========== First Column (Action Buttons) ==========
        action_column = QVBoxLayout()

        # Key Pair Actions
        keypair_action_layout = QVBoxLayout()
        keypair_action_layout.addWidget(QLabel("Key Pair Actions"))
        self.keypair_action_dropdown = QComboBox(self)
        self.keypair_action_dropdown.addItems(["Create Key Pair", "Delete Key Pair"])
        self.execute_keypair_action_button = QPushButton("Execute Key Pair Action", self)
        self.execute_keypair_action_button.clicked.connect(self.execute_keypair_action)
        keypair_action_layout.addWidget(self.keypair_action_dropdown)
        keypair_action_layout.addWidget(self.execute_keypair_action_button)
        action_column.addLayout(keypair_action_layout)
        
        
        
        # VPC/Subnet Actions
        vpc_action_layout = QVBoxLayout()
        vpc_action_layout.addWidget(QLabel("VPC/Subnet Actions"))
        self.vpc_action_dropdown = QComboBox(self)
        self.vpc_action_dropdown.addItems([
            "Create VPC", "Delete VPC", "Update VPC", "Create Subnet", "Delete Subnet"
        ])
        self.execute_vpc_action_button = QPushButton("Execute VPC/Subnet Action", self)
        self.execute_vpc_action_button.clicked.connect(self.execute_vpc_action)
        vpc_action_layout.addWidget(self.vpc_action_dropdown)
        vpc_action_layout.addWidget(self.execute_vpc_action_button)
        action_column.addLayout(vpc_action_layout)

        # Security Group Actions
        sg_action_layout = QVBoxLayout()
        sg_action_layout.addWidget(QLabel("Security Group Actions"))
        self.sg_action_dropdown = QComboBox(self)
        self.sg_action_dropdown.addItems([
            "Create Security Group", "Describe Security Groups", "Delete Security Group",
            "Open Port", "Close Port"
        ])
        self.sg_action_dropdown.currentIndexChanged.connect(self.toggle_sg_inputs)

        # Port and CIDR Inputs
        self.sg_port_input = QLineEdit(self)
        self.sg_port_input.setPlaceholderText("Enter Port Number (e.g., 22)")
        self.sg_cidr_input = QLineEdit(self)
        self.sg_cidr_input.setPlaceholderText("Enter CIDR IP (e.g., 0.0.0.0/0)")
        self.sg_port_input.setVisible(False)
        self.sg_cidr_input.setVisible(False)

        # Security Group Protocol Selection
        self.protocol_dropdown = QComboBox(self)
        self.protocol_dropdown.addItems(["tcp", "udp", "icmp", "All"])
        self.protocol_dropdown.setCurrentText("tcp")  # Default to tcp

        # ICMP type and code fields (for ICMP protocol)
        self.icmp_type_input = QLineEdit(self)
        self.icmp_type_input.setPlaceholderText("Enter ICMP Type")
        self.icmp_type_input.setVisible(False)

        self.icmp_code_input = QLineEdit(self)
        self.icmp_code_input.setPlaceholderText("Enter ICMP Code")
        self.icmp_code_input.setVisible(False)

        sg_action_layout.addWidget(QLabel("Select Protocol:"))
        sg_action_layout.addWidget(self.protocol_dropdown)
        sg_action_layout.addWidget(self.sg_port_input)
        sg_action_layout.addWidget(self.sg_cidr_input)
        sg_action_layout.addWidget(self.icmp_type_input)
        sg_action_layout.addWidget(self.icmp_code_input)

        # Execute Button
        self.execute_sg_action_button = QPushButton("Execute Security Group Action", self)
        self.execute_sg_action_button.clicked.connect(self.execute_sg_action)
        sg_action_layout.addWidget(self.sg_action_dropdown)
        sg_action_layout.addWidget(self.execute_sg_action_button)
        action_column.addLayout(sg_action_layout)

        # Pre-configured Rule Templates
        self.rule_templates_dropdown = QComboBox(self)
        self.rule_templates_dropdown.addItems([
            "SSH (TCP 22)", "HTTP (TCP 80)", "HTTPS (TCP 443)"
        ])
        self.rule_templates_dropdown.currentIndexChanged.connect(self.apply_template)
        sg_action_layout.addWidget(QLabel("Rule Templates:"))
        sg_action_layout.addWidget(self.rule_templates_dropdown)

        action_column.addLayout(sg_action_layout)

        # EC2 Actions
        ec2_action_layout = QVBoxLayout()
        ec2_action_layout.addWidget(QLabel("EC2 Instance Actions"))
        self.ec2_action_dropdown = QComboBox(self)
        self.ec2_action_dropdown.addItems([
            "Create EC2 Instance", "Stop EC2 Instance", "Terminate EC2 Instance",
            "Describe EC2 Instance", "Get EC2 Public IP", "Reboot EC2 Instance","Show Running Instances",
            "Stop Running Instances","Start EC2 Instance", "Describe All Instances", "Link New Key Pair","Show Instance Status Checks",
            "Monitor EC2 Usage (CPU/Network Metrics)", "Stop All Running Instances", "Terminate All Stopped Instances",
            " Backup EC2 Instance (Create AMI)", "Resize EC2 Instance", "Tagging Multiple EC2 Instances","Schedule EC2 Instance Start/Stop",
            "Detailed Billing Information"
        ])
        self.execute_ec2_action_button = QPushButton("Execute EC2 Action", self)
        self.execute_ec2_action_button.clicked.connect(self.execute_ec2_action)
        ec2_action_layout.addWidget(self.ec2_action_dropdown)
        ec2_action_layout.addWidget(self.execute_ec2_action_button)
        action_column.addLayout(ec2_action_layout)

        # Tag Actions
        tag_action_layout = QVBoxLayout()
        tag_action_layout.addWidget(QLabel("Tag Actions"))
        self.tag_action_dropdown = QComboBox(self)
        self.tag_action_dropdown.addItems(["Create Tag", "Delete Tag"])
        self.execute_tag_action_button = QPushButton("Execute Tag Action", self)
        self.execute_tag_action_button.clicked.connect(self.execute_tag_action)
        tag_action_layout.addWidget(self.tag_action_dropdown)
        tag_action_layout.addWidget(self.execute_tag_action_button)

        action_column.addLayout(tag_action_layout)

        # Volume Actions
        volume_action_layout = QVBoxLayout()
        volume_action_layout.addWidget(QLabel("Volume Actions"))
        self.volume_action_dropdown = QComboBox(self)
        self.volume_action_dropdown.addItems([
            "Attach Volume to EC2", "Detach Volume from EC2", "List Volumes",
            "Increase Volume Size", "Create Snapshot"
        ])
        self.execute_volume_action_button = QPushButton("Execute Volume Action", self)
        self.execute_volume_action_button.clicked.connect(self.execute_volume_action)
        volume_action_layout.addWidget(self.volume_action_dropdown)
        volume_action_layout.addWidget(self.execute_volume_action_button)
        action_column.addLayout(volume_action_layout)

        # ========== Second Column (Custom Rules and Resources) ==========
        selection_column = QVBoxLayout()

        # EC2 Instance Dropdown (First)
        self.instance_dropdown = QComboBox(self)
        selection_column.addWidget(QLabel("Select EC2 Instance:"))
        selection_column.addWidget(self.instance_dropdown)

        # Region selection (Second)
        self.region_dropdown = QComboBox(self)
        self.region_dropdown.currentIndexChanged.connect(self.change_region)
        selection_column.addWidget(QLabel("Select Region:"))
        selection_column.addWidget(self.region_dropdown)
        
        # AMI Search Textbox
        self.ami_search_box = QLineEdit(self)
        self.ami_search_box.setPlaceholderText("Search AMI by Name...")
        selection_column.addWidget(QLabel("Search AMI:"))
        selection_column.addWidget(self.ami_search_box)
        self.ami_search_box.textChanged.connect(self.filter_amis)


        # **AMI Dropdown Initialization** (with respective OS) (Third)
        self.ami_dropdown = QComboBox(self)
        selection_column.addWidget(QLabel("Select AMI:"))
        selection_column.addWidget(self.ami_dropdown)
        self.ami_dropdown.currentIndexChanged.connect(self.on_ami_selected)
        self.ami_dropdown.currentIndexChanged.connect(self.load_ami_details)



        # Security Group Dropdown (Fourth)
        self.security_group_dropdown = QComboBox(self)
        selection_column.addWidget(QLabel("Select Security Group:"))
        selection_column.addWidget(self.security_group_dropdown)  
        self.security_group_dropdown.currentIndexChanged.connect(self.describe_security_groups)
        
        selection_column.addWidget(self.security_group_dropdown)
        
        

        # Instance Type Dropdown (FIFTH)
        self.instance_type_dropdown = QComboBox(self)
        selection_column.addWidget(QLabel("Select Instance Type:"))
        selection_column.addWidget(self.instance_type_dropdown)
        
        
        # VPC Dropdown (SIXTH)
        self.vpc_dropdown = QComboBox(self)
        selection_column.addWidget(QLabel("Select VPC:"))
        selection_column.addWidget(self.vpc_dropdown)
        #self.vpc_dropdown.currentIndexChanged.connect(self.refresh_subnets)
        self.vpc_dropdown.currentIndexChanged.connect(self.on_vpc_selected)

        # Subnet Dropdown (Seventh)
        self.subnet_dropdown = QComboBox(self)
        selection_column.addWidget(QLabel("Select Subnet:"))
        selection_column.addWidget(self.subnet_dropdown)
        self.subnet_dropdown.currentIndexChanged.connect(self.on_subnet_selected)


        # Tag Dropdowns (EIGHTH)
        self.tag_list_dropdown = QComboBox(self)
        selection_column.addWidget(QLabel("Tags:"))
        selection_column.addWidget(self.tag_list_dropdown)

        # Key Pair Inputs (NINTH)
        self.keypair_list_dropdown = QComboBox(self)
        selection_column.addWidget(QLabel("Available Key Pairs:"))
        selection_column.addWidget(self.keypair_list_dropdown)

        # Refresh EC2 Resources (at the bottom)
        self.refresh_dropdowns_button = QPushButton("Refresh EC2 Resources", self)
        self.refresh_dropdowns_button.clicked.connect(self.refresh_dropdowns)
        selection_column.addWidget(self.refresh_dropdowns_button)

        

        # ========== Third Column (Output Area) ==========
        output_column = QVBoxLayout()
        self.output_area = QTextEdit(self)
        self.output_area.setReadOnly(True)
        output_column.addWidget(QLabel("EC2 Action Output:"))
        output_column.addWidget(self.output_area)

        # Adding columns to the main layout (ensure it's done only once)
        main_layout.addLayout(action_column, 1)
        main_layout.addLayout(selection_column, 1)
        main_layout.addLayout(output_column, 2)

        # Set the main layout for the widget
        self.setLayout(main_layout)

        # Populate regions and resources when the tab is loaded
        self.populate_regions()
        self.refresh_dropdowns()
        self.executor.submit(self._fetch_amis)
        # Filter AMIs immediately after fetching
        self.filter_amis()
        self.refresh_vpcs()




    def connect_signals(self):
        self.signal_manager.message_signal.connect(self.show_message)
        self.signal_manager.clear_signal.connect(self.clear_output_area)
        self.signal_manager.keypair_signal.connect(self.update_keypair_dropdown)
        self.signal_manager.sg_details_signal.connect(self.handle_sg_details)

    def run_in_thread(self, target, *args, **kwargs):
        thread = threading.Thread(target=target, args=args, kwargs=kwargs)
        thread.start()
        
     

    # ========== Region and Resource Population ==========
    def populate_regions(self):
        self.clear_output_area()
        self.run_in_thread(self._populate_regions)

    def _populate_regions(self):
        try:
            ec2_client = self.session.client('ec2')
            regions_response = ec2_client.describe_regions()
            region_names = [region['RegionName'] for region in regions_response['Regions']]
            
            # Directly populate the region dropdown without using QMetaObject.invokeMethod
            self.region_dropdown.clear()
            self.region_dropdown.addItems(region_names)
            
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error populating regions: {str(e)}")

    def change_region(self):
        selected_region = self.region_dropdown.currentText()
        
        if selected_region != self.session.region_name:  # Only change session if region actually changes
            self.session = boto3.Session(region_name=selected_region)
            self.ec2_client = self.session.client('ec2')
            
            # Instead of calling refresh_dropdowns(), refresh only AMIs and instances
            self.refresh_ami_list() 
            self._refresh_vpcs()
            self.refresh_dropdowns()
            
            
            
    def refresh_ami_list(self):
        """Refresh AMI list based on the selected region."""
        selected_region = self.region_dropdown.currentText()  # Get the currently selected region
        self.ec2_client = boto3.client('ec2', region_name=selected_region)  # Update the EC2 client for the region

        self.run_in_thread(self._fetch_amis) 


    def refresh_dropdowns(self):
        self.clear_output_area()
        self.clear_dropdowns()
        self.run_in_thread(self._refresh_dropdowns)
        self.refresh_keypairs()

    def clear_output_area(self):
        QMetaObject.invokeMethod(self.output_area, "clear", Qt.QueuedConnection)

    def clear_dropdowns(self):
        self.instance_dropdown.clear()
        self.ami_dropdown.clear()
        self.instance_type_dropdown.clear()
        self.security_group_dropdown.clear()
        self.keypair_list_dropdown.clear()
        self.tag_list_dropdown.clear()
        
    def _refresh_dropdowns(self):
        instance_list = []
        ami_list = []
        instance_type_list = []
        security_group_list = []
        keypair_list = []
        tag_list = []

        try:
            # Get the selected region from the dropdown
            region_name = self.region_dropdown.currentText()
            if region_name:
                # Update EC2 client with the selected region
                self.ec2_client = boto3.client('ec2', region_name=region_name)

            # --- Fetch EC2 instances across the entire region ---
            instances_response = self.ec2_client.describe_instances()
            for reservation in instances_response['Reservations']:
                for instance in reservation['Instances']:
                    instance_list.append(instance['InstanceId'])

            # --- Fetch AMIs (owned by self or Amazon) ---
            ami_details_map = {}  # Store AMI details
            amis_response = self.ec2_client.describe_images(Owners=['self', 'amazon'])
            for ami in amis_response['Images']:
                ami_list.append(ami['ImageId'])  # Only add the AMI ID to the list
                ami_details_map[ami['ImageId']] = ami  # Store detailed information

            # Save AMI details for later use
            self.ami_details_map = ami_details_map

            # --- Fetch available instance types ---
            instance_types_response = self.ec2_client.describe_instance_type_offerings(LocationType='region')
            for instance_type in instance_types_response['InstanceTypeOfferings']:
                instance_type_list.append(instance_type['InstanceType'])

            # --- Fetch security groups ---
            security_groups_response = self.ec2_client.describe_security_groups()
            for sg in security_groups_response['SecurityGroups']:
                security_group_list.append(sg['GroupId'])  # Only add the security group ID

            # --- Fetch available key pairs ---
            keypairs_response = self.ec2_client.describe_key_pairs()
            for keypair in keypairs_response['KeyPairs']:
                keypair_list.append(keypair['KeyName'])  # Only add the keypair name

            # --- Fetch tags for all instances ---
            if instance_list:
                instance_ids = [instance.split(" ")[0] for instance in instance_list]
                tags_response = self.ec2_client.describe_tags(Filters=[
                    {'Name': 'resource-id', 'Values': instance_ids}
                ])
                for tag in tags_response['Tags']:
                    tag_list.append(f"{tag['Key']}={tag['Value']}")

            # --- Update the dropdowns with the fetched data ---
            self.update_dropdowns([instance_list, ami_list, instance_type_list, security_group_list, keypair_list, tag_list])

            # Notify the user that the resources have been refreshed
            self.signal_manager.message_signal.emit("EC2 resources refreshed successfully.")
        
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error: {str(e)}")



            
    def on_ami_selected(self):
        selected_ami_id = self.ami_dropdown.currentText()
        
        if selected_ami_id in self.ami_details_map:
            ami_details = self.ami_details_map[selected_ami_id]
            details_output = f"""
            AMI ID: {ami_details['ImageId']}
            Name: {ami_details.get('Name', 'N/A')}
            Description: {ami_details.get('Description', 'N/A')}
            Architecture: {ami_details.get('Architecture', 'N/A')}
            Creation Date: {ami_details.get('CreationDate', 'N/A')}
            State: {ami_details.get('State', 'N/A')}
            Public: {ami_details.get('Public', 'N/A')}
            """
            
            # Show the AMI details in the output area
            self.signal_manager.message_signal.emit(details_output)
        else:
            self.signal_manager.message_signal.emit(None)
            
            
    def load_ami_details(self):
        """
        Load and display details of the selected AMI.
        """
        selected_ami_id = self.ami_dropdown.currentData()  # Get the selected AMI ID from the dropdown

        # If there's a valid selected AMI
        if selected_ami_id and selected_ami_id in self.ami_details_map:
            ami_details = self.ami_details_map[selected_ami_id]

            # Clear the output area before showing new details
            self.clear_output_area()

            # Display the selected AMI details (name, ID, description, creation date, etc.)
            ami_info = f"AMI ID: {selected_ami_id}\n"
            ami_info += f"Name: {ami_details.get('Name', 'No Name')}\n"
            ami_info += f"Description: {ami_details.get('Description', 'No Description')}\n"
            ami_info += f"Creation Date: {ami_details.get('CreationDate', 'No Date')}\n"

            # Display the details in the output area
            QMetaObject.invokeMethod(self.output_area, "append", Qt.QueuedConnection, Q_ARG(str, ami_info))
        else:
            # Clear the output area if no valid AMI is selected
            self.clear_output_area()


    def filter_amis(self):
        """
        Filter AMIs based on the text entered in the search box.
        """
        search_text = self.ami_search_box.text().lower()  # Get the search text and convert to lowercase
        self.ami_dropdown.clear()  # Clear the current AMI dropdown options

        # Filter AMIs by name that contains the search text
        filtered_amis = [
            ami_id for ami_id, details in self.ami_details_map.items()
            if search_text in details.get('Name', '').lower()
        ]

        # Populate the AMI dropdown with the filtered list
        if filtered_amis:
            for ami_id in filtered_amis:
                ami_name = self.ami_details_map[ami_id].get('Name', 'No Name')
                self.ami_dropdown.addItem(f"{ami_id} - {ami_name}", ami_id)
        else:
            self.ami_dropdown.addItem("No AMIs Found")  # Show this if no results match the search

        # Debugging: Optional - Display a message showing how many AMIs were found
        QTimer.singleShot(0, lambda: self.output_area.append(f"Filtered AMIs: {len(filtered_amis)}"))

            
    def _fetch_amis(self):
        """
        Fetch available AMIs specific to the selected region and populate the AMI dropdown.
        """
        try:
            # Fetch the selected region for querying AMIs
            region_name = self.region_dropdown.currentText() or 'us-east-1'  # Default to 'us-east-1' if none selected

            # Initialize EC2 client (ensure region is set correctly)
            ec2_client = boto3.client('ec2', region_name=region_name)

            # Fetch only AMIs that are available in the selected region
            response = ec2_client.describe_images(
                Owners=['self', 'amazon'],
                Filters=[
                    {'Name': 'state', 'Values': ['available']},  # Only available AMIs
                    {'Name': 'image-type', 'Values': ['machine']}  # Ensure it's an instance AMI, not a snapshot
                ]
            )

            # Prepare the list of AMIs
            ami_list = [(image['ImageId'], image.get('Name', 'No Name')) for image in response['Images']]

            # Debug: Output the number of AMIs found in the output_area (ensure this happens on the UI thread)
            QTimer.singleShot(0, lambda: self.output_area.append(f"Total AMIs found in {region_name}: {len(ami_list)}"))

            # Populate the AMI dropdown safely
            QTimer.singleShot(0, lambda: self.ami_dropdown.clear())  # Clear the dropdown in the UI thread
            for ami_id, name in ami_list:
                # Use lambda with default arguments to ensure variables are captured correctly in the loop
                QTimer.singleShot(0, lambda ami_id=ami_id, name=name: self.ami_dropdown.addItem(f"{ami_id} - {name}", ami_id))

            # Handle case where no AMIs are found
            if not ami_list:
                QTimer.singleShot(0, lambda: self.ami_dropdown.addItem("No AMIs Found"))

        except botocore.exceptions.ClientError as e:
            # Handle the error safely by updating the output_area in the UI thread
            QTimer.singleShot(0, lambda: self.output_area.append(f"Error fetching AMIs: {str(e)}"))



            
    


    def populate_ami_dropdown(self, ami_list):
        self.ami_dropdown.clear()  # Clear old items
        for ami_id, name in ami_list:
            self.ami_dropdown.addItem(f"{ami_id} - {name}", ami_id)
            
    # ========== VPC/Subnet Operations ==========
            
    def execute_vpc_action(self):
        action = self.vpc_action_dropdown.currentText()

        if action == "Create VPC":
            cidr_block = self.get_cidr_block_input("Create VPC")
            if cidr_block:
                self.run_in_thread(self.create_vpc, cidr_block)

        elif action == "Delete VPC":
            vpc_id = self.get_selected_vpc_id()
            if vpc_id:
                self.run_in_thread(self.delete_vpc, vpc_id)

        elif action == "Update VPC":
            vpc_id = self.get_selected_vpc_id()
            if vpc_id:
                # For simplicity, we can allow updating DNS attributes for now
                self.run_in_thread(self.update_vpc_dns_attributes, vpc_id)

        elif action == "Create Subnet":
            vpc_id = self.get_selected_vpc_id()
            cidr_block = self.get_cidr_block_input("Create Subnet")
            if vpc_id and cidr_block:
                self.run_in_thread(self.create_subnet, vpc_id, cidr_block)

        elif action == "Delete Subnet":
            subnet_id = self.get_selected_subnet_id()
            if subnet_id:
                self.run_in_thread(self.delete_subnet, subnet_id)
                
                
    def get_cidr_block_input(self, title):
        cidr_block, ok = QInputDialog.getText(self, title, "Enter CIDR Block (e.g., 10.0.0.0/16):")
        if not ok or not cidr_block:
            self.signal_manager.message_signal.emit(f"{title} canceled or invalid CIDR block provided.")
            return None
        return cidr_block
    
    


            
    def refresh_vpcs(self):
        """
        Refresh the VPCs manually or after a region change.
        """
        self.vpc_dropdown.clear()  # Clear existing VPC entries
        self.vpc_dropdown.setVisible(False)  # Hide VPC dropdown while loading
        self.signal_manager.message_signal.emit("Loading VPCs...")
        self.run_in_thread(self._refresh_vpcs)  # Run VPC loading in a separate thread



    def _refresh_vpcs(self):
        try:
            vpc_list = []
            response = self.ec2_client.describe_vpcs()

            for vpc in response['Vpcs']:
                vpc_id = vpc['VpcId']
                cidr_block = vpc['CidrBlock']
                vpc_list.append(f"{vpc_id} - {cidr_block}")
            
            # Update the VPC dropdown on the main thread
            QTimer.singleShot(0, lambda: self.update_vpc_dropdown(vpc_list))

        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error fetching VPCs: {str(e)}")




    
            
    def update_vpc_dropdown(self, vpc_list):
        """
        Update the VPC dropdown with the VPCs fetched.
        """
        self.vpc_dropdown.clear()  # Clear the dropdown first
        if vpc_list:
            for vpc in vpc_list:
                vpc_id, cidr_block = vpc.split(" - ", 1)  # Split the string to get VPC ID and CIDR block
                self.vpc_dropdown.addItem(f"{vpc_id}")
                # Set tooltip for each individual item to show full VPC info
                index = self.vpc_dropdown.count() - 1  # Get the index of the recently added item
                self.vpc_dropdown.setItemData(index, vpc, Qt.ToolTipRole)  # Set the tooltip as full VPC info
        else:
            self.vpc_dropdown.addItem("No VPCs Found")  # Fallback if no VPCs are found
        
        # Show the dropdown after VPCs are loaded
        self.vpc_dropdown.setVisible(True)
        self.signal_manager.message_signal.emit("VPCs loaded successfully.")



            
            
    def create_vpc(self, cidr_block):
        try:
            response = self.ec2_client.create_vpc(CidrBlock=cidr_block)
            vpc_id = response['Vpc']['VpcId']

            # Optionally, enable DNS support and DNS hostnames
            self.ec2_client.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={'Value': True})
            self.ec2_client.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={'Value': True})

            self.signal_manager.message_signal.emit(f"VPC created with ID: {vpc_id} and CIDR block {cidr_block}")
            self.refresh_vpcs()  # Refresh the VPC list after creation
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error creating VPC: {str(e)}")

            
    def delete_vpc(self, vpc_id):
        try:
            self.ec2_client.delete_vpc(VpcId=vpc_id)
            self.signal_manager.message_signal.emit(f"VPC {vpc_id} deleted successfully.")
            self.refresh_vpcs()  # Refresh VPC list after deletion
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error deleting VPC: {str(e)}")
            
    def get_selected_vpc_id(self):
        selected_vpc = self.vpc_dropdown.currentText()  # Get the VPC ID from the dropdown
        if not selected_vpc:
            self.signal_manager.message_signal.emit("No VPC selected.")
            return None
        return selected_vpc
    
    
    def on_vpc_selected(self):
        """Handle VPC selection and refresh subnets."""
        selected_vpc_id = self.vpc_dropdown.currentText()  # Get the selected VPC ID from the dropdown

        if not selected_vpc_id:
            self.signal_manager.message_signal.emit("No VPC selected.")
            return

        # Emit VPC details to the output area
        try:
            response = self.ec2_client.describe_vpcs(VpcIds=[selected_vpc_id])
            vpc = response['Vpcs'][0]
            vpc_details = (f"VPC ID: {vpc['VpcId']}\n"
                        f"CIDR Block: {vpc.get('CidrBlock', 'N/A')}\n"
                        f"State: {vpc.get('State', 'N/A')}\n"
                        f"Is Default: {vpc.get('IsDefault', 'N/A')}")
            self.signal_manager.message_signal.emit(vpc_details)

            # Refresh subnets for the selected VPC
            self.refresh_subnets(selected_vpc_id)

        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'InvalidVpcID.NotFound':
                self.signal_manager.message_signal.emit(f"VPC {selected_vpc_id} not found.")
            else:
                self.signal_manager.message_signal.emit(f"Error fetching VPC details: {str(e)}")








    def create_subnet(self, vpc_id, cidr_block):
        try:
            # Get the VPC details to fetch the CIDR block of the VPC
            vpc_response = self.ec2_client.describe_vpcs(VpcIds=[vpc_id])
            vpc_cidr_block = vpc_response['Vpcs'][0]['CidrBlock']

            # Get existing subnets for the selected VPC
            subnets_response = self.ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
            existing_subnet_cidrs = [subnet['CidrBlock'] for subnet in subnets_response['Subnets']]

            # Validate if the subnet CIDR is within the VPC CIDR range
            if not self.is_cidr_in_vpc_range(cidr_block, vpc_cidr_block):
                self.signal_manager.message_signal.emit(
                    f"Error: The CIDR {cidr_block} is not within the VPC CIDR range {vpc_cidr_block}."
                )
                return

            # Check for conflicts with existing subnets
            if self.is_cidr_conflict(cidr_block, existing_subnet_cidrs):
                self.signal_manager.message_signal.emit(
                    f"Error: The CIDR {cidr_block} conflicts with an existing subnet CIDR."
                )
                return

            # Proceed with subnet creation if validation passes
            response = self.ec2_client.create_subnet(VpcId=vpc_id, CidrBlock=cidr_block)
            subnet_id = response['Subnet']['SubnetId']
            self.signal_manager.message_signal.emit(
                f"Subnet {subnet_id} created with CIDR block {cidr_block} in VPC {vpc_id}"
            )
              
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error creating Subnet: {str(e)}")
            
    def is_cidr_in_vpc_range(self, subnet_cidr, vpc_cidr):
        """
        Validate if the given subnet CIDR is within the VPC's CIDR range.
        """
        try:
            vpc_network = ipaddress.IPv4Network(vpc_cidr)
            subnet_network = ipaddress.IPv4Network(subnet_cidr)
            return subnet_network.subnet_of(vpc_network)
        except ValueError:
            return False
        
    def is_cidr_conflict(self, subnet_cidr, existing_subnet_cidrs):
        """
        Check if the subnet CIDR conflicts with any existing subnet CIDRs.
        """
        try:
            subnet_network = ipaddress.IPv4Network(subnet_cidr)
            for existing_cidr in existing_subnet_cidrs:
                existing_network = ipaddress.IPv4Network(existing_cidr)
                # Check if the new subnet overlaps with an existing subnet
                if subnet_network.overlaps(existing_network):
                    return True
            return False
        except ValueError:
            return False
         
            
    def refresh_subnets(self, vpc_id):
        """Refresh the subnet list for the selected VPC."""
        if vpc_id:
            self.run_in_thread(self._refresh_subnets, vpc_id)
        else:
            self.signal_manager.message_signal.emit("No VPC selected.")


    def _refresh_subnets(self, vpc_id):
        """Fetch and update the subnets for the given VPC ID."""
        try:
            if not vpc_id:
                self.signal_manager.message_signal.emit("No VPC selected to refresh subnets.")
                return

            subnet_list = []
            response = self.ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
            for subnet in response['Subnets']:
                subnet_id = subnet['SubnetId']
                cidr_block = subnet['CidrBlock']
                availability_zone = subnet['AvailabilityZone']
                subnet_list.append(f"{subnet_id} - {cidr_block} - {availability_zone}")

            # Update the UI with the subnet list
            QTimer.singleShot(0, lambda: self.update_subnet_dropdown(subnet_list))
            self.signal_manager.message_signal.emit("Subnets refreshed successfully.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error fetching subnets: {str(e)}")

    def update_subnet_dropdown(self, subnet_list):
        """Update the subnet dropdown with the fetched subnets."""
        self.subnet_dropdown.clear()  # Clear the current dropdown

        if subnet_list:
            for subnet in subnet_list:
                # Subnets should follow the format: subnet_id - cidr_block (availability_zone)
                subnet_id, cidr_block_az = subnet.split(" - ", 1)  # Split into ID and the rest
                self.subnet_dropdown.addItem(f"{subnet_id} - {cidr_block_az}", subnet_id)
        else:
            self.subnet_dropdown.addItem("No Subnets Found")



            
    def on_subnet_selected(self):
        selected_subnet = self.subnet_dropdown.currentText()

        if not selected_subnet or selected_subnet == "No Subnets Found":
            self.signal_manager.message_signal.emit("No Subnet selected.")
            return

        try:
            # Here, the format should be: "subnet_id - cidr_block (availability_zone)"
            subnet_id, cidr_block_az = selected_subnet.split(" - ", 1)
            cidr_block, az = cidr_block_az.split(" (", 1)
            az = az.rstrip(")")  # Remove the closing parenthesis from AZ

            # Now we have all the values, and we can use them
            self.signal_manager.message_signal.emit(
                f"Subnet ID: {subnet_id}\nCIDR Block: {cidr_block}\nAvailability Zone: {az}"
            )
        except ValueError:
            self.signal_manager.message_signal.emit("Error processing selected subnet format.")




            
    def delete_subnet(self, subnet_id):
        try:
            self.ec2_client.delete_subnet(SubnetId=subnet_id)
            self.signal_manager.message_signal.emit(f"Subnet {subnet_id} deleted successfully.")
            self.refresh_subnets()  # Refresh subnets after deletion
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error deleting Subnet: {str(e)}")


    

    def get_selected_subnet_id(self):
        selected_subnet = self.subnet_dropdown.currentData()  # Use currentData() for selected subnet ID
        if not selected_subnet:
            self.signal_manager.message_signal.emit("No Subnet selected.")
            return None
        return selected_subnet




    def update_dropdowns(self, data):
        """
        Update the instance, AMI, instance type, security group, keypair, and tag dropdowns with data.
        """
        instance_list, ami_list, instance_type_list, security_group_list, keypair_list, tag_list = data

        # Clear the dropdowns
        self.instance_dropdown.clear()
        self.ami_dropdown.clear()
        self.instance_type_dropdown.clear()
        self.security_group_dropdown.clear()
        self.keypair_list_dropdown.clear()
        self.tag_list_dropdown.clear()

        # Populate instance dropdown
        if instance_list:
            self.instance_dropdown.addItems(instance_list)
        else:
            self.instance_dropdown.addItem("No EC2 instances found")

        # Populate AMI dropdown
        if ami_list:
            self.ami_dropdown.addItems(ami_list)
        else:
            self.ami_dropdown.addItem("No AMIs found")

        # Populate instance type dropdown
        if instance_type_list:
            self.instance_type_dropdown.addItems(instance_type_list)
        else:
            self.instance_type_dropdown.addItem("No Instance Types found")

        # Populate security group dropdown
        if security_group_list:
            self.security_group_dropdown.addItems(security_group_list)
        else:
            self.security_group_dropdown.addItem("No Security Groups found")

        # Populate keypair dropdown
        if keypair_list:
            self.keypair_list_dropdown.addItems(keypair_list)
        else:
            self.keypair_list_dropdown.addItem("No Key Pairs found")

        # Populate tag dropdown
        if tag_list:
            self.tag_list_dropdown.addItems(tag_list)
        else:
            self.tag_list_dropdown.addItem("No Tags found")

    def show_message(self, message):
        QMetaObject.invokeMethod(self.output_area, "append", Qt.QueuedConnection, Q_ARG(str, message))

    # ========== Key Pair Operations ==========
    def execute_keypair_action(self):
        action = self.keypair_action_dropdown.currentText()
        if action == "Create Key Pair":
            keypair_name, ok = QInputDialog.getText(self, "Create Key Pair", "Enter Key Pair Name:")
            if not ok or not keypair_name:
                return
            self.run_in_thread(self.create_keypair, keypair_name)
        elif action == "Delete Key Pair":
            keypair_name = self.keypair_list_dropdown.currentText()
            self.run_in_thread(self.delete_keypair, keypair_name)
        
        elif action == "Download Key Pair":
            self.run_in_thread(self.download_keypair)

    def create_keypair(self, keypair_name):
        try:
            # Create a new key pair
            response = self.ec2_client.create_key_pair(KeyName=keypair_name)

            # Get the private key (KeyMaterial)
            private_key = response['KeyMaterial']

            # Save the private key as a .pem file in the current directory
            pem_file_path = f"{keypair_name}.pem"
            with open(pem_file_path, 'w') as file:
                file.write(private_key)

            # Set the appropriate permissions for the .pem file (Linux systems)
            import os
            os.chmod(pem_file_path, 0o400)

            # Notify user of successful key pair creation and download
            self.signal_manager.message_signal.emit(f"Key pair '{keypair_name}' created and downloaded to {pem_file_path}")
            self.refresh_keypairs()  # Refresh the key pair list after creation
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'InvalidKeyPair.Duplicate':
                self.signal_manager.message_signal.emit(f"Key pair '{keypair_name}' already exists and cannot be re-downloaded.")
            else:
                self.signal_manager.message_signal.emit(f"Error creating key pair: {str(e)}")


    def delete_keypair(self, keypair_name):
        try:
            self.ec2_client.delete_key_pair(KeyName=keypair_name)
            self.signal_manager.message_signal.emit(f"Key Pair deleted: {keypair_name}")
            self.refresh_keypairs()  # Refresh key pair list after deletion
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error deleting Key Pair: {str(e)}")
            
    


    def refresh_keypairs(self):
        self.run_in_thread(self._refresh_keypairs)

    def _refresh_keypairs(self):
        try:
            keypair_list = []
            keypairs_response = self.ec2_client.describe_key_pairs()
            for keypair in keypairs_response['KeyPairs']:
                keypair_list.append(keypair['KeyName'])
                
            
            
            # Emit the signal with the key pairs list to update the UI on the main thread
            QTimer.singleShot(0, lambda: self.update_keypair_dropdown(keypair_list))
            self.signal_manager.message_signal.emit("Key pairs refreshed successfully.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error fetching key pairs: {str(e)}")

            
    def update_keypair_dropdown(self, keypair_list):
        self.keypair_list_dropdown.clear()  # Clear the dropdown
        if keypair_list:
            self.keypair_list_dropdown.addItems(keypair_list)  # Add new items if available
        else:
            self.keypair_list_dropdown.addItem("No Key Pairs Found")  # If no key pairs found


    # ========== Security Group Operations ==========
    
    def apply_template(self):
        selected_template = self.rule_templates_dropdown.currentText()
        if selected_template == "SSH (TCP 22)":
            self.sg_port_input.setText("22")
            self.protocol_dropdown.setCurrentText("tcp")
        elif selected_template == "HTTP (TCP 80)":
            self.sg_port_input.setText("80")
            self.protocol_dropdown.setCurrentText("tcp")
        elif selected_template == "HTTPS (TCP 443)":
            self.sg_port_input.setText("443")
            self.protocol_dropdown.setCurrentText("tcp")
            
            
            
    def toggle_sg_inputs(self):
        action = self.sg_action_dropdown.currentText()
        protocol = self.protocol_dropdown.currentText()

        if action in ["Open Port", "Close Port"]:
            self.sg_port_input.setVisible(True)
            self.sg_cidr_input.setVisible(True)

            if protocol == "icmp":
                self.icmp_type_input.setVisible(True)
                self.icmp_code_input.setVisible(True)
            else:
                self.icmp_type_input.setVisible(False)
                self.icmp_code_input.setVisible(False)
        else:
            self.sg_port_input.setVisible(False)
            self.sg_cidr_input.setVisible(False)
            self.icmp_type_input.setVisible(False)
            self.icmp_code_input.setVisible(False)
            
        # Handle Security Group Dropdown and Rules Table visibility for "Describe Security Groups"
        if action == "Describe Security Groups":
            self.describe_security_groups()
            
    def is_valid_cidr(self, cidr_ip):
        try:
            ipaddress.IPv4Network(cidr_ip, strict=False)
            return True
        except ValueError:
            return False

    def execute_sg_action(self):
        action = self.sg_action_dropdown.currentText()
        port_number = self.sg_port_input.text()
        cidr_ip = self.sg_cidr_input.text() or "0.0.0.0/0"  # Default CIDR IP

        # Validate CIDR block
        if not self.is_valid_cidr(cidr_ip):
            self.signal_manager.message_signal.emit("Invalid CIDR IP entered.")
            return

        # Get the protocol (default to tcp)
        protocol = self.protocol_dropdown.currentText()
        protocol = protocol if protocol != "All" else "-1"

        self.signal_manager.clear_signal.emit()
        self.run_in_thread(self._execute_sg_action, action, port_number, cidr_ip, protocol)

    def _execute_sg_action(self, action, port_number, cidr_ip, protocol):
        try:
            # Execute the selected action
            sg_id = self.security_group_dropdown.currentText()
            
            if action == "Create Security Group":
                self.create_security_group(cidr_ip)
            elif action == "Describe Security Groups":
                self.describe_security_groups()
            elif action == "Delete Security Group":
                self.delete_security_group()
            elif action == "Open Port":
                self.open_port(port_number, cidr_ip, protocol)
            elif action == "Close Port":
                self.close_port(port_number, cidr_ip, protocol)
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error: {str(e)}")

    def create_security_group(self, cidr_ip):
        sg_name, ok = QInputDialog.getText(self, "Create Security Group", "Enter Security Group Name:")
        vpc_id = self.vpc_dropdown.currentText().split(" ")[0]
        if not ok or not sg_name or not vpc_id:
            return
        try:
            response = self.ec2_client.create_security_group(
                GroupName=sg_name,
                Description="Custom Security Group",
                VpcId=vpc_id
            )
            self.signal_manager.message_signal.emit(f"Security Group {sg_name} created in VPC {vpc_id}")
            self.refresh_security_groups()
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error creating Security Group: {str(e)}")


    def describe_security_groups(self):
        sg_id = self.security_group_dropdown.currentText()
        if not sg_id:
            self.signal_manager.message_signal.emit("No Security Group selected.")
            return

        def fetch_sg_details():
            """Fetch the security group details and associated subnets in a background thread."""
            try:
                # Describe security group
                response = self.ec2_client.describe_security_groups(GroupIds=[sg_id])
                details = response['SecurityGroups'][0]
                vpc_id = details.get('VpcId')

                # Describe subnets in the same VPC
                subnets_response = self.ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
                subnets = subnets_response['Subnets']

                # Emit the security group details and associated subnets
                self.signal_manager.sg_details_signal.emit((details, subnets))  # Emit both details and subnets

            except botocore.exceptions.ClientError as e:
                self.signal_manager.message_signal.emit(f"Error describing Security Group: {str(e)}")

        # Run the security group fetching in a thread
        self.run_in_thread(fetch_sg_details)


    def handle_sg_details(self, data):
        """Update the output area with security group and subnet details."""
        details, subnets = data  # Unpack the details and subnets
        self.output_area.clear()

        # Display security group details
        self.output_area.append(f"Security Group ID: {details['GroupId']}")
        self.output_area.append(f"Security Group Name: {details['GroupName']}")
        self.output_area.append(f"Description: {details['Description']}")
        self.output_area.append(f"VPC ID: {details.get('VpcId', 'None')}\n")

        # Display ingress rules
        self.output_area.append("Ingress Rules:")
        ingress_rules = details.get('IpPermissions', [])
        if ingress_rules:
            for rule in ingress_rules:
                protocol = rule.get('IpProtocol', 'N/A')
                from_port = rule.get('FromPort', 'N/A')
                to_port = rule.get('ToPort', 'N/A')
                cidr_ips = [ip_range['CidrIp'] for ip_range in rule.get('IpRanges', [])]
                self.output_area.append(f"  Protocol: {protocol}, Ports: {from_port}-{to_port}, CIDRs: {', '.join(cidr_ips)}")
        else:
            self.output_area.append("  No Ingress Rules found.\n")

        # Display egress rules
        self.output_area.append("Egress Rules:")
        egress_rules = details.get('IpPermissionsEgress', [])
        if egress_rules:
            for rule in egress_rules:
                protocol = rule.get('IpProtocol', 'N/A')
                from_port = rule.get('FromPort', 'N/A')
                to_port = rule.get('ToPort', 'N/A')
                cidr_ips = [ip_range['CidrIp'] for ip_range in rule.get('IpRanges', [])]
                self.output_area.append(f"  Protocol: {protocol}, Ports: {from_port}-{to_port}, CIDRs: {', '.join(cidr_ips)}")
        else:
            self.output_area.append("  No Egress Rules found.\n")

        # Display the subnets in the same VPC and populate the subnet dropdown
        self.output_area.append("\nSubnets in the same VPC:")
        subnet_list = []
        if subnets:
            for subnet in subnets:
                subnet_id = subnet['SubnetId']
                cidr_block = subnet['CidrBlock']
                availability_zone = subnet['AvailabilityZone']
                subnet_list.append(f"{subnet_id} - {cidr_block} ({availability_zone})")
                self.output_area.append(f"  Subnet ID: {subnet_id}, CIDR Block: {cidr_block}, AZ: {availability_zone}")

            # Populate the subnet dropdown dynamically
            QTimer.singleShot(0, lambda: self.update_subnet_dropdown(subnet_list))
        else:
            self.output_area.append("  No Subnets found in this VPC.\n")







    def _format_sg_rules(self, rules):
        formatted_rules = []
        for rule in rules:
            protocol = rule.get('IpProtocol', 'N/A')
            from_port = rule.get('FromPort', 'N/A')
            to_port = rule.get('ToPort', 'N/A')
            cidr_ips = [ip_range['CidrIp'] for ip_range in rule.get('IpRanges', [])]
            formatted_rules.append(f"Protocol: {protocol}, Ports: {from_port}-{to_port}, CIDRs: {', '.join(cidr_ips)}")
        return '\n'.join(formatted_rules)

    def delete_security_group(self):
        sg_name = self.security_group_dropdown.currentText()
        try:
            self.ec2_client.delete_security_group(GroupName=sg_name)
            self.signal_manager.message_signal.emit(f"Security Group deleted: {sg_name}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error deleting Security Group: {str(e)}")

    def run_in_thread(self, target, *args, **kwargs):
        thread = threading.Thread(target=target, args=args, kwargs=kwargs)
        thread.start()
            
    def get_selected_protocol(self):
        protocol = self.protocol_dropdown.currentText()
        # If "All" is selected, AWS uses '-1' for all protocols
        return protocol if protocol != "All" else "-1"

    def open_port(self, port_number, cidr_ip, protocol):
        sg_id = self.security_group_dropdown.currentText()
        try:
            port_number = int(port_number)

            self.ec2_client.authorize_security_group_ingress(
                GroupId=sg_id,
                IpProtocol=protocol,
                FromPort=port_number,
                ToPort=port_number,
                CidrIp=cidr_ip
            )
            self.signal_manager.message_signal.emit(f"Port {port_number} opened for Security Group: {sg_id} with CIDR {cidr_ip} using {protocol}")
        except ValueError:
            self.signal_manager.message_signal.emit("Invalid port number entered.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error opening port: {str(e)}")

    def close_port(self, port_number, cidr_ip, protocol):
        sg_id = self.security_group_dropdown.currentText()
        try:
            port_number = int(port_number)

            self.ec2_client.revoke_security_group_ingress(
                GroupId=sg_id,
                IpProtocol=protocol,
                FromPort=port_number,
                ToPort=port_number,
                CidrIp=cidr_ip
            )
            self.signal_manager.message_signal.emit(f"Port {port_number} closed for Security Group: {sg_id} with CIDR {cidr_ip} using {protocol}")
        except ValueError:
            self.signal_manager.message_signal.emit("Invalid port number entered.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error closing port: {str(e)}")

    # ========== EC2 Operations ==========
    def execute_ec2_action(self):
        action = self.ec2_action_dropdown.currentText()
        selected_instance = self.instance_dropdown.currentText()
        self.signal_manager.clear_signal.emit()
        
        # Collect inputs where necessary
        if action == "Backup EC2 Instance (Create AMI)":
            ami_name = self.get_ami_name_input()
            if ami_name:
                self.run_in_thread(self.create_ami, selected_instance, ami_name)

        elif action == "Resize EC2 Instance":
            new_instance_type = self.get_instance_type_input()
            if new_instance_type:
                self.run_in_thread(self.resize_instance, selected_instance, new_instance_type)

        elif action == "Tagging Multiple EC2 Instances":
            tag_key, tag_value = self.get_tag_input()
            if tag_key and tag_value:
                self.run_in_thread(self.tag_multiple_instances, [selected_instance], tag_key, tag_value)

        elif action == "Schedule EC2 Instance Start/Stop":
            delay_seconds = self.get_delay_input()
            if delay_seconds is not None:
                self.run_in_thread(self.schedule_instance_action, selected_instance, action, delay_seconds)

        elif action == "Detailed Billing Information":
            self.run_in_thread(self.get_billing_information)

        else:
            # Handle actions that don't need additional inputs
            self.run_in_thread(self._execute_ec2_action, action, selected_instance)
            
        
    def _execute_ec2_action(self, action, selected_instance):
        try:
            if action == "Create EC2 Instance":
                self.create_ec2_instance()
            elif action == "Start EC2 Instance":
                self.start_instance(selected_instance)
            elif action == "Stop EC2 Instance":
                self.stop_instance(selected_instance)
            elif action == "Terminate EC2 Instance":
                self.terminate_instance(selected_instance)
            elif action == "Describe EC2 Instance":
                self.describe_instance(selected_instance)
            elif action == "Describe All Instances":
                self.describe_all_instances()  
            elif action == "Show Instance Status Checks":
                self.show_instance_status_checks()  
            elif action == "Get EC2 Public IP":
                self.get_public_ip(selected_instance)
            elif action == "Reboot EC2 Instance":
                self.reboot_instance(selected_instance)
            elif action == "Show Running Instances":
                self.show_running_instances()
            elif action == "Show Stopped Instances":
                self.show_stopped_instances() 
            elif action == "Monitor EC2 Usage (CPU/Network Metrics)":
                self.get_instance_metrics(selected_instance)
            elif action == "Stop All Running Instances":
                self.stop_all_running_instances()
            elif action == "Terminate All Stopped Instances":
                self.terminate_all_stopped_instances()
            
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error: {str(e)}")
            
    def get_ami_name_input(self):
        ami_name, ok = QInputDialog.getText(self, "Create AMI", "Enter AMI Name:")
        if ok and ami_name:
            return ami_name
        self.signal_manager.message_signal.emit("AMI creation canceled or invalid name provided.")
        return None

    def get_instance_type_input(self):
        new_instance_type, ok = QInputDialog.getText(self, "Resize Instance", "Enter New Instance Type:")
        if ok and new_instance_type:
            return new_instance_type
        self.signal_manager.message_signal.emit("Resize operation canceled or invalid instance type provided.")
        return None

    def get_tag_input(self):
        tag_key, ok = QInputDialog.getText(self, "Tag EC2 Instances", "Enter Tag Key:")
        if not ok or not tag_key:
            self.signal_manager.message_signal.emit("Tagging canceled or invalid key.")
            return None, None
        tag_value, ok = QInputDialog.getText(self, "Tag EC2 Instances", "Enter Tag Value:")
        if not ok or not tag_value:
            self.signal_manager.message_signal.emit("Tagging canceled or invalid value.")
            return None, None
        return tag_key, tag_value

    def get_delay_input(self):
        delay_seconds, ok = QInputDialog.getInt(self, "Schedule Action", "Enter Delay in Seconds:", min=0)
        if ok:
            return delay_seconds
        self.signal_manager.message_signal.emit("Action scheduling canceled.")
        return None
                
    def get_billing_information(self):
        try:
            cost_explorer = self.session.client('ce')
            response = cost_explorer.get_cost_and_usage(
                TimePeriod={'Start': '2023-01-01', 'End': '2023-12-31'},
                Granularity='MONTHLY',
                Metrics=['UnblendedCost'],
                GroupBy=[{'Type': 'DIMENSION', 'Key': 'SERVICE'}]
            )
            
            for result in response['ResultsByTime']:
                for group in result['Groups']:
                    service = group['Keys'][0]
                    cost = group['Metrics']['UnblendedCost']['Amount']
                    self.signal_manager.message_signal.emit(f"Service: {service}, Cost: ${cost}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error retrieving billing information: {str(e)}")

            
    def schedule_instance_action(self, instance_id, action, delay_seconds):
        QTimer.singleShot(delay_seconds * 1000, lambda: self.run_in_thread(self._execute_ec2_action, action, instance_id))
        self.signal_manager.message_signal.emit(f"Scheduled {action} for {instance_id} in {delay_seconds} seconds.")

    def tag_multiple_instances(self, instance_ids, tag_key, tag_value):
        if instance_ids and tag_key and tag_value:
            try:
                self.ec2_client.create_tags(Resources=instance_ids, Tags=[{'Key': tag_key, 'Value': tag_value}])
                self.signal_manager.message_signal.emit(f"Tag {tag_key}={tag_value} applied to instances: {', '.join(instance_ids)}")
            except botocore.exceptions.ClientError as e:
                self.signal_manager.message_signal.emit(f"Error tagging instances: {str(e)}")
        else:
            self.signal_manager.message_signal.emit("Please select instances and provide a tag key/value.")

            
            
    def create_ami(self, instance_id, ami_name):
        if instance_id and ami_name:
            try:
                response = self.ec2_client.create_image(
                    InstanceId=instance_id,
                    Name=ami_name,
                    NoReboot=True  # Ensures the instance is not rebooted during AMI creation
                )
                ami_id = response['ImageId']
                self.signal_manager.message_signal.emit(f"AMI {ami_name} created with ID: {ami_id}")
            except botocore.exceptions.ClientError as e:
                self.signal_manager.message_signal.emit(f"Error creating AMI for {instance_id}: {str(e)}")
        else:
            self.signal_manager.message_signal.emit("Please select an instance and provide an AMI name.")

    def resize_instance(self, instance_id, new_instance_type):
        if instance_id and new_instance_type:
            try:
                # Stop instance if it's running
                self.ec2_client.stop_instances(InstanceIds=[instance_id])
                waiter = self.ec2_client.get_waiter('instance_stopped')
                waiter.wait(InstanceIds=[instance_id])
                
                # Change the instance type
                self.ec2_client.modify_instance_attribute(InstanceId=instance_id, InstanceType={'Value': new_instance_type})
                
                # Restart the instance
                self.ec2_client.start_instances(InstanceIds=[instance_id])
                self.signal_manager.message_signal.emit(f"Resized instance {instance_id} to {new_instance_type} and restarted.")
            except botocore.exceptions.ClientError as e:
                self.signal_manager.message_signal.emit(f"Error resizing instance {instance_id}: {str(e)}")
        else:
            self.signal_manager.message_signal.emit("Please select an instance and provide a new instance type.")

    
            
            
            
    def terminate_all_stopped_instances(self):
        try:
            response = self.ec2_client.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['stopped']}])
            stopped_instance_ids = [instance['InstanceId'] for reservation in response['Reservations'] for instance in reservation['Instances']]
            
            if stopped_instance_ids:
                self.ec2_client.terminate_instances(InstanceIds=stopped_instance_ids)
                self.signal_manager.message_signal.emit(f"Terminating instances: {', '.join(stopped_instance_ids)}")
            else:
                self.signal_manager.message_signal.emit("No stopped instances to terminate.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error terminating stopped instances: {str(e)}")

            
    def stop_all_running_instances(self):
        try:
            response = self.ec2_client.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
            running_instance_ids = [instance['InstanceId'] for reservation in response['Reservations'] for instance in reservation['Instances']]
            
            if running_instance_ids:
                self.ec2_client.stop_instances(InstanceIds=running_instance_ids)
                self.signal_manager.message_signal.emit(f"Stopping instances: {', '.join(running_instance_ids)}")
            else:
                self.signal_manager.message_signal.emit("No running instances to stop.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error stopping running instances: {str(e)}")
     
    def get_instance_metrics(self, instance_id, metric_name="CPUUtilization"):
        if instance_id:
            try:
                cloudwatch = self.session.client('cloudwatch')
                response = cloudwatch.get_metric_statistics(
                    Namespace='AWS/EC2',
                    MetricName=metric_name,
                    Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                    StartTime=datetime.utcnow() - timedelta(minutes=30),  # Last 30 minutes
                    EndTime=datetime.utcnow(),
                    Period=300,
                    Statistics=['Average']
                )
                
                datapoints = response['Datapoints']
                if datapoints:
                    for dp in datapoints:
                        metric_output = f"Time: {dp['Timestamp']}, Average {metric_name}: {dp['Average']}"
                        self.signal_manager.message_signal.emit(metric_output)
                else:
                    self.signal_manager.message_signal.emit(f"No data points for {metric_name}.")
            except botocore.exceptions.ClientError as e:
                self.signal_manager.message_signal.emit(f"Error retrieving {metric_name} for {instance_id}: {str(e)}")
        else:
            self.signal_manager.message_signal.emit("No instance selected.")       
            
    def show_running_instances(self):
        """Fetch and display running EC2 instances."""
        try:
            # Fetch all EC2 instances and filter only those that are running
            response = self.ec2_client.describe_instances(
                Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
            )
            running_instances = []
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance.get('InstanceId')
                    instance_type = instance.get('InstanceType')
                    public_ip = instance.get('PublicIpAddress', 'No Public IP')
                    running_instances.append(f"Instance ID: {instance_id}, Type: {instance_type}, Public IP: {public_ip}")

            if running_instances:
                # Display each running instance in the output area
                for instance_info in running_instances:
                    QTimer.singleShot(0, lambda instance_info=instance_info: self.output_area.append(instance_info))
            else:
                QTimer.singleShot(0, lambda: self.output_area.append("No running instances found."))

        except botocore.exceptions.ClientError as e:
            QTimer.singleShot(0, lambda: self.output_area.append(f"Error fetching running instances: {str(e)}"))
            
    def show_stopped_instances(self):
        """Fetch and display stopped EC2 instances."""
        try:
            response = self.ec2_client.describe_instances(
                Filters=[{'Name': 'instance-state-name', 'Values': ['stopped']}]
            )
            stopped_instances = []
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance.get('InstanceId')
                    instance_type = instance.get('InstanceType')
                    stopped_instances.append(f"Instance ID: {instance_id}, Type: {instance_type}")

            if stopped_instances:
                for instance_info in stopped_instances:
                    QTimer.singleShot(0, lambda instance_info=instance_info: self.output_area.append(instance_info))
            else:
                QTimer.singleShot(0, lambda: self.output_area.append("No stopped instances found."))

        except botocore.exceptions.ClientError as e:
            QTimer.singleShot(0, lambda: self.output_area.append(f"Error fetching stopped instances: {str(e)}"))
            
    def start_instance(self, instance_id):
        if instance_id:
            try:
                self.ec2_client.start_instances(InstanceIds=[instance_id])
                self.signal_manager.message_signal.emit(f"Starting instance: {instance_id}")
            except botocore.exceptions.ClientError as e:
                self.signal_manager.message_signal.emit(f"Error starting instance: {str(e)}")
        else:
            self.signal_manager.message_signal.emit("No instance selected.")

            
    def show_instance_status_checks(self):
        try:
            response = self.ec2_client.describe_instance_status(IncludeAllInstances=True)
            for instance in response['InstanceStatuses']:
                instance_id = instance['InstanceId']
                system_status = instance['SystemStatus']['Status']
                instance_status = instance['InstanceStatus']['Status']
                status_checks = (f"Instance ID: {instance_id}, "
                                f"System Status: {system_status}, "
                                f"Instance Status: {instance_status}")
                self.signal_manager.message_signal.emit(status_checks)
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error fetching status checks: {str(e)}")
            
    def describe_all_instances(self):
        try:
            response = self.ec2_client.describe_instances()
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    instance_state = instance['State']['Name']
                    public_ip = instance.get('PublicIpAddress', 'No Public IP')
                    launch_time = instance['LaunchTime']
                    instance_type = instance['InstanceType']
                    instance_details = (f"Instance ID: {instance_id}, State: {instance_state}, "
                                        f"Type: {instance_type}, Public IP: {public_ip}, "
                                        f"Launch Time: {launch_time}")
                    self.signal_manager.message_signal.emit(instance_details)
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error describing all instances: {str(e)}")



    def create_ec2_instance(self):
        ami_id = self.ami_dropdown.currentText().split(" ")[0]  # Extract only AMI ID
        instance_type = self.instance_type_dropdown.currentText()
        security_group_id = self.security_group_dropdown.currentText()
        subnet_id = self.subnet_dropdown.currentText().split(" ")[0]
        keypair_name = self.keypair_list_dropdown.currentText()  # Get selected key pair

        if not ami_id or not instance_type or not security_group_id or not subnet_id or not keypair_name:
            self.signal_manager.message_signal.emit("Please select AMI, Instance Type, Subnet, Security Group, and Key Pair.")
            return

        try:
            response = self.ec2_client.run_instances(
                ImageId=ami_id,
                InstanceType=instance_type,
                MaxCount=1,
                MinCount=1,
                SecurityGroupIds=[security_group_id],
                SubnetId=subnet_id,
                KeyName=keypair_name  # Assign the selected key pair
            )
            instance_id = response['Instances'][0]['InstanceId']
            self.signal_manager.message_signal.emit(f"EC2 Instance created: {instance_id}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error creating EC2 instance: {str(e)}")



    def stop_instance(self, instance_id):
        if instance_id:
            try:
                self.ec2_client.stop_instances(InstanceIds=[instance_id])
                self.signal_manager.message_signal.emit(f"Stopping instance: {instance_id}")
            except botocore.exceptions.ClientError as e:
                self.signal_manager.message_signal.emit(f"Error stopping instance: {str(e)}")
        else:
            self.signal_manager.message_signal.emit("No instance selected.")

    def terminate_instance(self, instance_id):
        if instance_id:
            try:
                self.ec2_client.terminate_instances(InstanceIds=[instance_id])
                self.signal_manager.message_signal.emit(f"Terminating instance: {instance_id}")
            except botocore.exceptions.ClientError as e:
                self.signal_manager.message_signal.emit(f"Error terminating instance: {str(e)}")
        else:
            self.signal_manager.message_signal.emit("No instance selected.")

    def describe_instance(self, instance_id):
        if instance_id:
            try:
                response = self.ec2_client.describe_instances(InstanceIds=[instance_id])
                instance_details = response['Reservations'][0]['Instances'][0]
                
                # Extract relevant information for user-friendly display
                instance_id = instance_details.get('InstanceId', 'N/A')
                image_id = instance_details.get('ImageId', 'N/A')
                instance_type = instance_details.get('InstanceType', 'N/A')
                launch_time = instance_details.get('LaunchTime', 'N/A')
                availability_zone = instance_details['Placement'].get('AvailabilityZone', 'N/A')
                state = instance_details['State'].get('Name', 'N/A')
                private_ip = instance_details.get('PrivateIpAddress', 'N/A')
                public_ip = instance_details.get('PublicIpAddress', 'N/A')
                subnet_id = instance_details.get('SubnetId', 'N/A')
                vpc_id = instance_details.get('VpcId', 'N/A')
                security_groups = ', '.join([sg['GroupName'] for sg in instance_details.get('SecurityGroups', [])])
                block_device_mappings = ', '.join([bdm['Ebs']['VolumeId'] for bdm in instance_details.get('BlockDeviceMappings', [])])

                # Additional details requested
                private_dns = instance_details.get('PrivateDnsName', 'N/A')
                public_dns = instance_details.get('PublicDnsName', 'N/A')
                platform_details = instance_details.get('PlatformDetails', 'N/A')

                # Extract tags
                tags = instance_details.get('Tags', [])
                formatted_tags = ', '.join([f"{tag['Key']}={tag['Value']}" for tag in tags]) if tags else "No Tags"

                # Format details for output
                formatted_details = (f"Instance ID: {instance_id}\n"
                                    f"Image ID (AMI): {image_id}\n"
                                    f"Instance Type: {instance_type}\n"
                                    f"Launch Time: {launch_time}\n"
                                    f"Availability Zone: {availability_zone}\n"
                                    f"State: {state}\n"
                                    f"Private IP Address: {private_ip}\n"
                                    f"Public IP Address: {public_ip}\n"
                                    f"Private DNS Name: {private_dns}\n"
                                    f"Public DNS Name: {public_dns}\n"
                                    f"Platform Details: {platform_details}\n"
                                    f"Subnet ID: {subnet_id}\n"
                                    f"VPC ID: {vpc_id}\n"
                                    f"Security Groups: {security_groups}\n"
                                    f"Block Devices: {block_device_mappings}\n"
                                    f"Tags: {formatted_tags}\n")  # Add tags to the output

                # Display the formatted details in the output area
                self.signal_manager.message_signal.emit(formatted_details)

            except botocore.exceptions.ClientError as e:
                self.signal_manager.message_signal.emit(f"Error describing instance: {str(e)}")
        else:
            self.signal_manager.message_signal.emit("No instance selected.")
            




    def get_public_ip(self, instance_id):
        if instance_id:
            try:
                response = self.ec2_client.describe_instances(InstanceIds=[instance_id])
                public_ip = response['Reservations'][0]['Instances'][0].get('PublicIpAddress', 'No Public IP')
                self.signal_manager.message_signal.emit(f"Instance {instance_id} Public IP: {public_ip}")
            except botocore.exceptions.ClientError as e:
                self.signal_manager.message_signal.emit(f"Error getting public IP: {str(e)}")
        else:
            self.signal_manager.message_signal.emit("No instance selected.")

    def reboot_instance(self, instance_id):
        if instance_id:
            try:
                self.ec2_client.reboot_instances(InstanceIds=[instance_id])
                self.signal_manager.message_signal.emit(f"Rebooting instance: {instance_id}")
            except botocore.exceptions.ClientError as e:
                self.signal_manager.message_signal.emit(f"Error rebooting instance: {str(e)}")
        else:
            self.signal_manager.message_signal.emit("No instance selected.")

    # ========== Tag Operations ==========
    def execute_tag_action(self):
        action = self.tag_action_dropdown.currentText()
        resource_id = self.instance_dropdown.currentText()  # Assume tag is applied to an EC2 instance

        if action == "Create Tag":
            tag_key, ok = QInputDialog.getText(self, "Create Tag", "Enter Tag Key:")
            if not ok or not tag_key:
                return
            tag_value, ok = QInputDialog.getText(self, "Create Tag", "Enter Tag Value:")
            if ok and tag_value:
                self.run_in_thread(self.create_tag, resource_id, tag_key, tag_value)
        elif action == "Delete Tag":
            selected_tag = self.tag_list_dropdown.currentText()
            if selected_tag:
                tag_key = selected_tag.split('=')[0]  # Extract the key from 'key=value'
                self.run_in_thread(self.delete_tag, resource_id, tag_key)

    def create_tag(self, resource_id, tag_key, tag_value):
        try:
            self.ec2_client.create_tags(Resources=[resource_id], Tags=[{'Key': tag_key, 'Value': tag_value}])
            self.signal_manager.message_signal.emit(f"Tag created: {tag_key}={tag_value} for {resource_id}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error creating tag: {str(e)}")

    def delete_tag(self, resource_id, tag_key):
        try:
            self.ec2_client.delete_tags(Resources=[resource_id], Tags=[{'Key': tag_key}])
            self.signal_manager.message_signal.emit(f"Tag {tag_key} deleted from {resource_id}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error deleting tag: {str(e)}")

    # ========== Volume Operations ==========
    def execute_volume_action(self):
        action = self.volume_action_dropdown.currentText()
        self.signal_manager.clear_signal.emit()
        self.run_in_thread(self._execute_volume_action, action)

    def _execute_volume_action(self, action):
        try:
            if action == "Attach Volume to EC2":
                self.attach_volume()
            elif action == "Detach Volume from EC2":
                self.detach_volume()
            elif action == "List Volumes":
                self.list_volumes()
            elif action == "Increase Volume Size":
                self.increase_volume_size()
            elif action == "Create Snapshot":
                self.create_snapshot()
            elif action == "List Snapshots":
                self.list_snapshots()
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error: {str(e)}")

    def attach_volume(self):
        volume_id, ok = QInputDialog.getText(self, "Attach Volume", "Enter Volume ID:")
        instance_id = self.instance_dropdown.currentText()
        if instance_id and ok and volume_id:
            try:
                self.ec2_client.attach_volume(
                    VolumeId=volume_id,
                    InstanceId=instance_id,
                    Device='/dev/sdf'
                )
                self.signal_manager.message_signal.emit(f"Volume {volume_id} attached to instance {instance_id}")
            except botocore.exceptions.ClientError as e:
                self.signal_manager.message_signal.emit(f"Error attaching volume: {str(e)}")
        else:
            self.signal_manager.message_signal.emit("No instance or volume selected.")

    def detach_volume(self):
        volume_id, ok = QInputDialog.getText(self, "Detach Volume", "Enter Volume ID:")
        if ok and volume_id:
            try:
                self.ec2_client.detach_volume(VolumeId=volume_id)
                self.signal_manager.message_signal.emit(f"Volume {volume_id} detached")
            except botocore.exceptions.ClientError as e:
                self.signal_manager.message_signal.emit(f"Error detaching volume: {str(e)}")
        else:
            self.signal_manager.message_signal.emit("No volume selected.")

    def list_volumes(self):
        try:
            response = self.ec2_client.describe_volumes()
            volumes_info = [
                f"Volume {volume['VolumeId']} - Size: {volume['Size']} GB - State: {volume['State']}" 
                for volume in response['Volumes']
            ]
            self.signal_manager.message_signal.emit("\n".join(volumes_info))
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error listing volumes: {str(e)}")

    def increase_volume_size(self):
        volume_id, ok = QInputDialog.getText(self, "Increase Volume Size", "Enter Volume ID:")
        new_size, size_ok = QInputDialog.getInt(self, "Increase Volume Size", "Enter New Size (GB):", min=1)
        if ok and size_ok and volume_id:
            try:
                self.ec2_client.modify_volume(VolumeId=volume_id, Size=new_size)
                self.signal_manager.message_signal.emit(f"Volume {volume_id} size increased to {new_size} GB")
            except botocore.exceptions.ClientError as e:
                self.signal_manager.message_signal.emit(f"Error increasing volume size: {str(e)}")
        else:
            self.signal_manager.message_signal.emit("No volume selected or invalid size.")

    def create_snapshot(self):
        volume_id, ok = QInputDialog.getText(self, "Create Snapshot", "Enter Volume ID:")
        description, desc_ok = QInputDialog.getText(self, "Snapshot Description", "Enter Snapshot Description:")
        if ok and desc_ok and volume_id:
            try:
                response = self.ec2_client.create_snapshot(VolumeId=volume_id, Description=description or "Snapshot for volume")
                snapshot_id = response['SnapshotId']
                self.signal_manager.message_signal.emit(f"Snapshot {snapshot_id} created for volume {volume_id}")
            except botocore.exceptions.ClientError as e:
                self.signal_manager.message_signal.emit(f"Error creating snapshot: {str(e)}")
        else:
            self.signal_manager.message_signal.emit("No volume selected or description provided.")

    def list_snapshots(self):
        try:
            response = self.ec2_client.describe_snapshots(OwnerIds=['self'])
            snapshots_info = [
                f"Snapshot {snapshot['SnapshotId']} - Volume: {snapshot['VolumeId']} - State: {snapshot['State']}" 
                for snapshot in response['Snapshots']
            ]
            self.signal_manager.message_signal.emit("\n".join(snapshots_info))
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error listing snapshots: {str(e)}")

