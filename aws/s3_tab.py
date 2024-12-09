import threading
import uuid

import boto3
import botocore
from botocore.exceptions import ParamValidationError
from PyQt5.QtCore import Q_ARG, QMetaObject, QObject, Qt, pyqtSignal
from PyQt5.QtWidgets import (QComboBox, QFileDialog, QFormLayout, QHBoxLayout,
                             QInputDialog, QLabel, QLineEdit, QPushButton,
                             QTextEdit, QVBoxLayout, QWidget)


class SignalManager(QObject):
    message_signal = pyqtSignal(str)
    dropdown_signal = pyqtSignal(list)
    clear_signal = pyqtSignal()


class S3Tab(QWidget):
    def __init__(self, session):
        super().__init__()
        self.session = session
        self.s3_client = session.client('s3')
        self.s3_resource = session.resource('s3')
        self.signal_manager = SignalManager()
        self.initUI()
        self.connect_signals()

    def initUI(self):
        main_layout = QHBoxLayout()

        # Left Column: S3 Management Section
        left_column = QVBoxLayout()
        management_layout = QFormLayout()

        # Dropdown for S3 Users, Policies, Regions
        self.user_dropdown = QComboBox(self)
        self.user_dropdown.currentIndexChanged.connect(self.display_user_buckets)
        self.policy_dropdown = QComboBox(self)
        self.region_dropdown = QComboBox(self)
        self.refresh_s3_resources_button = QPushButton("Refresh S3 Resources", self)
        self.refresh_s3_resources_button.clicked.connect(self.refresh_s3_resources)

        management_layout.addRow(QLabel("Select S3 User:"), self.user_dropdown)
        management_layout.addRow(QLabel("Select S3 Policy:"), self.policy_dropdown)
        management_layout.addRow(QLabel("Select AWS Region:"), self.region_dropdown)
        management_layout.addRow(self.refresh_s3_resources_button)


        # Bucket Management Actions
        bucket_management_layout = QFormLayout()

        # Dropdown for selecting bucket
        self.bucket_dropdown = QComboBox(self)

        # Add the bucket dropdown before initializing the action dropdown
        bucket_management_layout.addRow(QLabel("Bucket Management"))
        bucket_management_layout.addRow(QLabel("Select Bucket:"), self.bucket_dropdown)

        # Action dropdown for managing buckets
        self.bucket_action_dropdown = QComboBox(self)
        self.bucket_action_dropdown.addItems([
            "Create Bucket", "List All Buckets", "Delete Bucket", "Download Non-Empty Buckets", "List All Files in Bucket"
        ])

        # Button to execute selected bucket action
        self.execute_bucket_action_button = QPushButton("Execute Bucket Action", self)
        self.execute_bucket_action_button.clicked.connect(self.execute_bucket_action)

        # Now add the action dropdown and execute button
        bucket_management_layout.addRow(self.bucket_action_dropdown)
        bucket_management_layout.addRow(self.execute_bucket_action_button)


        # Object Management Actions
        object_management_layout = QFormLayout()

        # Set up the layout before creating the widgets
        object_management_layout.addRow(QLabel("Object Management"))

        # Dropdown for selecting files in a bucket
        self.file_dropdown = QComboBox(self)

        # Action dropdown for managing objects in a bucket
        self.object_action_dropdown = QComboBox(self)
        self.object_action_dropdown.addItems([
            "Upload File", "Upload Image with Web Config", "Download File", "Delete Object from Bucket", "Filter Object", "Object Summary"
        ])

        # Button to execute selected object action
        self.execute_object_action_button = QPushButton("Execute Object Action", self)
        self.execute_object_action_button.clicked.connect(self.execute_object_action)

        # Add elements to the layout in the correct order
        object_management_layout.addRow(QLabel("Select File:"), self.file_dropdown)  # File dropdown first
        object_management_layout.addRow(self.object_action_dropdown)  # Action dropdown after file selection
        object_management_layout.addRow(self.execute_object_action_button)

        # Add logic to load files into file dropdown when a bucket is selected
        self.bucket_dropdown.currentIndexChanged.connect(self.load_files_for_bucket)




        # Policy Management Actions
        policy_management_layout = QFormLayout()
        self.policy_action_dropdown = QComboBox(self)
        self.policy_action_dropdown.addItems([
            "Add Bucket Policy", "Get Bucket Policy", "Delete Bucket Policy", "Delete Attached Policy"
        ])

        self.policy_input = QTextEdit(self)
        self.policy_input.setPlaceholderText("Enter policy document (JSON)")

        self.execute_policy_action_button = QPushButton("Execute Policy Action", self)
        self.execute_policy_action_button.clicked.connect(self.execute_policy_action)

        policy_management_layout.addRow(QLabel("Policy Management"))
        policy_management_layout.addRow(self.policy_action_dropdown)
        policy_management_layout.addRow(QLabel("Policy Document:"), self.policy_input)
        policy_management_layout.addRow(self.execute_policy_action_button)

        # Encryption Management Actions
        encryption_management_layout = QFormLayout()
        self.encryption_action_dropdown = QComboBox(self)
        self.encryption_action_dropdown.addItems([
            "Add Encryption", "Check Encryption", "Delete Encryption"
        ])

        self.execute_encryption_action_button = QPushButton("Execute Encryption Action", self)
        self.execute_encryption_action_button.clicked.connect(self.execute_encryption_action)

        encryption_management_layout.addRow(QLabel("Encryption Management"))
        encryption_management_layout.addRow(self.encryption_action_dropdown)
        encryption_management_layout.addRow(self.execute_encryption_action_button)

        # Add layouts to the left column
        left_column.addLayout(management_layout)
        left_column.addLayout(bucket_management_layout)
        left_column.addLayout(object_management_layout)
        left_column.addLayout(policy_management_layout)
        left_column.addLayout(encryption_management_layout)

        # Right Column: Output Area
        right_column = QVBoxLayout()

        self.output_area = QTextEdit(self)
        self.output_area.setReadOnly(True)

        right_column.addWidget(QLabel("S3 Action Output:"))
        right_column.addWidget(self.output_area)

        # Add columns to the main layout with specific stretch factors
        main_layout.addLayout(left_column, 2)
        main_layout.addLayout(right_column, 3)

        self.setLayout(main_layout)

        # Initial load of regions and dropdown values
        self.load_regions()
        self.refresh_s3_resources()
        self.load_buckets_for_region()
        self.load_files_for_bucket()

    def connect_signals(self):
        self.signal_manager.message_signal.connect(self.show_message)
        self.signal_manager.clear_signal.connect(self.clear_output_area)

    def run_in_thread(self, target, *args, **kwargs):
        thread = threading.Thread(target=target, args=args, kwargs=kwargs)
        thread.start()

    def load_regions(self):
        try:
            ec2 = self.session.client('ec2')
            response = ec2.describe_regions()
            regions = [region['RegionName'] for region in response['Regions']]
            self.region_dropdown.addItems(regions)
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error loading regions: {str(e)}")

    def refresh_s3_resources(self):
        self.user_dropdown.clear()
        self.policy_dropdown.clear()
        self.signal_manager.clear_signal.emit()  # Clear the output area on refresh

        try:
            # Query IAM for users
            iam_client = self.session.client('iam')
            users_response = iam_client.list_users()
            users = [user['UserName'] for user in users_response['Users']]
            self.user_dropdown.addItems(users)

            # Query IAM for policies
            policies_response = iam_client.list_policies(Scope='Local')
            policies = [policy['PolicyName'] for policy in policies_response['Policies']]
            self.policy_dropdown.addItems(policies)

            self.signal_manager.message_signal.emit("S3 resources refreshed successfully.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error refreshing S3 resources: {str(e)}")

    def show_message(self, message):
        QMetaObject.invokeMethod(self.output_area, "append", Qt.QueuedConnection, Q_ARG(str, message))

    def clear_output_area(self):
        QMetaObject.invokeMethod(self.output_area, "clear", Qt.QueuedConnection)

    def display_user_buckets(self):
        self.run_in_thread(self._list_all_buckets)
        
    def load_buckets_for_region(self):
        selected_region = self.region_dropdown.currentText().strip()
        
        # Set the S3 client to the selected region
        self.s3_client = self.session.client('s3', region_name=selected_region)
        
        # Clear the bucket dropdown before populating new values
        self.bucket_dropdown.clear()

        try:
            response = self.s3_client.list_buckets()
            buckets = response.get('Buckets', [])
            bucket_names = [bucket['Name'] for bucket in buckets]
            
            # Add buckets to the dropdown if they exist
            if bucket_names:
                self.bucket_dropdown.addItems(bucket_names)
                self.signal_manager.message_signal.emit(f"S3 Buckets:\n{', '.join(bucket_names)}")
            else:
                self.signal_manager.message_signal.emit(f"No buckets found in region '{selected_region}'.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error loading buckets for region '{selected_region}': {str(e)}")



    def _list_all_buckets(self):
        try:
            self.signal_manager.clear_signal.emit()  # Clear the output area before displaying new details

            response = self.s3_client.list_buckets()
            buckets = response.get('Buckets', [])

            if buckets:
                bucket_list = "\n".join([bucket['Name'] for bucket in buckets])
                self.signal_manager.message_signal.emit(f"S3 Buckets:\n{bucket_list}")
            else:
                self.signal_manager.message_signal.emit(f"No buckets found for this account.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error listing buckets: {str(e)}")

    def execute_bucket_action(self):
        action = self.bucket_action_dropdown.currentText()
        bucket_name = None

        # Determine bucket name based on action
        if action == "Create Bucket":
            # Prompt user to enter the bucket name for creation
            bucket_name, ok = QInputDialog.getText(self, "Create Bucket", "Enter bucket name:")
            if not ok or not bucket_name:  # If user cancels or input is empty, stop execution
                self.signal_manager.message_signal.emit("Bucket creation canceled or invalid name provided.")
                return
        else:
            # Use selected bucket from dropdown for other actions
            bucket_name = self.bucket_dropdown.currentText()

        # Execute the corresponding action in a thread
        if action == "Create Bucket":
            self.run_in_thread(self._create_bucket, bucket_name)
        elif action == "List All Buckets":
            self.run_in_thread(self._list_all_buckets)
        elif action == "Delete Bucket":
            self.run_in_thread(self._delete_bucket, bucket_name)
        elif action == "Download Non-Empty Buckets":
            self.run_in_thread(self._download_non_empty)
        elif action == "List All Files in Bucket":
            self.run_in_thread(self._list_all_files_in_bucket, bucket_name)



    

    def _create_bucket(self, bucket_name):
        try:
            region = self.region_dropdown.currentText().strip()
            s3_client = self.session.client('s3', region_name=region)
            
            # Check for bucket availability
            if not self._is_bucket_name_available(s3_client, bucket_name):
                # If the name is not available, append a unique identifier
                bucket_name = f"{bucket_name}-{uuid.uuid4().hex[:8]}"
                self.signal_manager.message_signal.emit(
                    f"Bucket name already exists. Trying with new name: '{bucket_name}'"
                )

            # Create bucket with or without LocationConstraint based on region
            if region == "us-east-1":
                s3_client.create_bucket(Bucket=bucket_name)
            else:
                s3_client.create_bucket(
                    Bucket=bucket_name,
                    CreateBucketConfiguration={'LocationConstraint': region}
                )

            self.signal_manager.message_signal.emit(f"Bucket '{bucket_name}' created successfully in region '{region}'.")
            
            # Reload the bucket dropdown to reflect the new bucket
            self.load_buckets_for_region()
        except ParamValidationError as e:
            self.signal_manager.message_signal.emit(f"Invalid bucket name: {bucket_name}. Error: {str(e)}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error creating bucket: {str(e)}")

    def _is_bucket_name_available(self, s3_client, bucket_name):
        """Check if the bucket name is available globally."""
        try:
            s3_client.head_bucket(Bucket=bucket_name)
            return False  # If the bucket exists, return False
        except botocore.exceptions.ClientError as e:
            error_code = int(e.response['Error']['Code'])
            if error_code == 404:
                return True  # Bucket does not exist, available to create
            return False  # Other errors imply the bucket is not available





    def _delete_bucket(self, bucket_name):
        try:
            self.s3_client.delete_bucket(Bucket=bucket_name)
            self.signal_manager.message_signal.emit(f"Bucket '{bucket_name}' deleted successfully.")
        except ParamValidationError as e:
            self.signal_manager.message_signal.emit(f"Invalid bucket name: {bucket_name}. Error: {str(e)}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error deleting bucket: {str(e)}")

    def _download_non_empty(self):
        try:
            response = self.s3_client.list_buckets()
            buckets = response.get('Buckets', [])
            for bucket in buckets:
                objects = self.s3_client.list_objects_v2(Bucket=bucket['Name'])
                if 'Contents' in objects:
                    for obj in objects['Contents']:
                        self.s3_client.download_file(bucket['Name'], obj['Key'], f"./{obj['Key']}")
                    self.signal_manager.message_signal.emit(f"Downloaded non-empty bucket '{bucket['Name']}'.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error downloading non-empty buckets: {str(e)}")

    def _list_all_files_in_bucket(self, bucket_name):
        try:
            objects = self.s3_client.list_objects_v2(Bucket=bucket_name)
            if 'Contents' in objects:
                file_list = "\n".join([obj['Key'] for obj in objects['Contents']])
                self.signal_manager.message_signal.emit(f"Files in bucket '{bucket_name}':\n{file_list}")
            else:
                self.signal_manager.message_signal.emit(f"No files found in bucket '{bucket_name}'.")
        except ParamValidationError as e:
            self.signal_manager.message_signal.emit(f"Invalid bucket name: {bucket_name}. Error: {str(e)}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error listing files in bucket: {str(e)}")


    # Object Management Functions
    def load_files_for_bucket(self):
        # Clear existing file names
        self.file_dropdown.clear()

        # Get the selected bucket name
        bucket_name = self.bucket_dropdown.currentText().strip()

        if not bucket_name:
            return

        try:
            # Fetch all objects in the selected bucket
            response = self.s3_client.list_objects_v2(Bucket=bucket_name)
            files = response.get('Contents', [])

            # Add file names to the dropdown
            file_names = [file['Key'] for file in files]
            if file_names:
                self.file_dropdown.addItems(file_names)
                self.signal_manager.message_signal.emit(f"Files in bucket '{bucket_name}': {', '.join(file_names)}")
            else:
                self.signal_manager.message_signal.emit(f"No files found in bucket '{bucket_name}'.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error loading files for bucket '{bucket_name}': {str(e)}")


    def execute_object_action(self):
        action = self.object_action_dropdown.currentText()
        
        # Get the bucket name from the dropdown
        bucket_name = self.bucket_dropdown.currentText().strip()
        
        # Get the selected file name from the file dropdown (for actions other than upload)
        file_name = self.file_dropdown.currentText()

        if action == "Upload File":
            # Prompt the user to select a file for upload
            file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Upload")
            if file_path:
                self.upload_file(bucket_name, file_path)
        elif action == "Upload Image with Web Config":
            # Prompt the user to select an image file for upload
            file_path, _ = QFileDialog.getOpenFileName(self, "Select Image File to Upload")
            if file_path:
                self.upload_image_with_web_config(bucket_name, file_path)
        elif action == "Download File":
            self._download_file(bucket_name, file_name)
        elif action == "Delete Object from Bucket":
            self.run_in_thread(self._delete_object_from_bucket, bucket_name, file_name)
        elif action == "Filter Object":
            self.run_in_thread(self._filter_object, bucket_name, file_name)
        elif action == "Object Summary":
            self.run_in_thread(self._object_summary, bucket_name, file_name)


    def upload_file(self, bucket_name):
        file_name = QFileDialog.getOpenFileName(self, "Select file to upload")[0]
        self.run_in_thread(self._upload_file, bucket_name, file_name)

    def _upload_file(self, bucket_name, file_name):
        try:
            if file_name:
                self.s3_client.upload_file(file_name, bucket_name, file_name.split('/')[-1])
                self.signal_manager.message_signal.emit(f"File '{file_name}' uploaded successfully to bucket '{bucket_name}'.")
            else:
                self.signal_manager.message_signal.emit("Upload canceled.")
        except ParamValidationError as e:
            self.signal_manager.message_signal.emit(f"Invalid bucket name: {bucket_name}. Error: {str(e)}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error uploading file: {str(e)}")

    def upload_image_with_web_config(self, bucket_name):
        file_name = QFileDialog.getOpenFileName(self, "Select image to upload")[0]
        acl = self._get_acl_choice()  # Get the selected ACL option
        self.run_in_thread(self._upload_image_with_web_config, bucket_name, file_name, acl)

    def _upload_image_with_web_config(self, bucket_name, file_name, acl):
        try:
            if file_name:
                with open(file_name, 'rb') as f:
                    data = f.read()
                self.s3_client.put_object(
                    ACL=acl,
                    Body=data,
                    Bucket=bucket_name,
                    Key=file_name.split('/')[-1],
                    Metadata={'Content-Type': 'image/jpeg'},
                )
                self.signal_manager.message_signal.emit(f"Image '{file_name}' uploaded successfully to bucket '{bucket_name}' with web config and ACL '{acl}'.")
            else:
                self.signal_manager.message_signal.emit("Upload canceled.")
        except ParamValidationError as e:
            self.signal_manager.message_signal.emit(f"Invalid bucket name: {bucket_name}. Error: {str(e)}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error uploading image: {str(e)}")

    def _get_acl_choice(self):
        acl_choice, ok = QInputDialog.getItem(self, "Select ACL", "Choose ACL for the image:", 
                                              ["private", "public-read", "public-read-write", "authenticated-read"], 0, False)
        if ok and acl_choice:
            return acl_choice
        return "private"  # Default to private if no choice is made

    def _download_file(self, bucket_name, file_name):
        # Step 1: Open the file dialog on the main thread
        save_location = QFileDialog.getSaveFileName(self, "Save file to location")[0]

        if save_location:
            # Step 2: Run the download process in a background thread
            self.run_in_thread(self._download_file_to_location, bucket_name, file_name, save_location)
        else:
            self.signal_manager.message_signal.emit("Download canceled.")

    def _download_file_to_location(self, bucket_name, file_name, save_location):
        try:
            # This part runs in the background thread
            self.s3_client.download_file(bucket_name, file_name, save_location)
            self.signal_manager.message_signal.emit(f"File '{file_name}' downloaded from bucket '{bucket_name}' to '{save_location}'.")
        except ParamValidationError as e:
            self.signal_manager.message_signal.emit(f"Invalid bucket name: {bucket_name}. Error: {str(e)}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error downloading file: {str(e)}")

    def _delete_object_from_bucket(self, bucket_name, file_name):
        try:
            self.s3_client.delete_object(Bucket=bucket_name, Key=file_name)
            self.signal_manager.message_signal.emit(f"Object '{file_name}' deleted from bucket '{bucket_name}'.")
        except ParamValidationError as e:
            self.signal_manager.message_signal.emit(f"Invalid bucket name: {bucket_name}. Error: {str(e)}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error deleting object: {str(e)}")

    def _filter_object(self, bucket_name, prefix):
        try:
            response = self.s3_client.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
            if 'Contents' in response:
                filtered_files = "\n".join([obj['Key'] for obj in response['Contents']])
                self.signal_manager.message_signal.emit(f"Filtered objects:\n{filtered_files}")
            else:
                self.signal_manager.message_signal.emit("No objects found with the given prefix.")
        except ParamValidationError as e:
            self.signal_manager.message_signal.emit(f"Invalid bucket name: {bucket_name}. Error: {str(e)}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error filtering objects: {str(e)}")

    def _object_summary(self, bucket_name, file_name):
        try:
            # Fetch the object summary
            object_summary = self.s3_resource.ObjectSummary(bucket_name, file_name)

            # Fetch additional details about the object
            object_metadata = self.s3_client.head_object(Bucket=bucket_name, Key=file_name)

            # Prepare the summary details
            summary_details = (
                f"Object Summary for '{file_name}':\n"
                f"  Size: {object_summary.size} bytes\n"
                f"  Last Modified: {object_summary.last_modified}\n"
                f"  Storage Class: {object_summary.storage_class}\n"
                f"  ETag: {object_summary.e_tag}\n"
                f"  Key: {object_summary.key}\n"
                f"  Content Type: {object_metadata['ContentType']}\n"
                f"  Expiration: {object_metadata.get('Expiration', 'N/A')}\n"
                f"  Metadata: {object_metadata['Metadata']}\n"
            )

            # Include owner details only if available
            if object_summary.owner:
                owner_details = (
                    f"  Owner: {object_summary.owner.get('DisplayName', 'N/A')} "
                    f"(ID: {object_summary.owner.get('ID', 'N/A')})\n"
                )
                summary_details += owner_details

            # Emit the summary details to the output area
            self.signal_manager.message_signal.emit(summary_details)

        except ParamValidationError as e:
            self.signal_manager.message_signal.emit(f"Invalid bucket name: {bucket_name}. Error: {str(e)}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error fetching object summary: {str(e)}")



    # Policy Management Functions
    def execute_policy_action(self):
        action = self.policy_action_dropdown.currentText()
        bucket_name = self.bucket_dropdown.currentText().strip()
        policy = self.policy_input.toPlainText()

        if action == "Add Bucket Policy":
            self.run_in_thread(self._add_bucket_policy, bucket_name, policy)
        elif action == "Get Bucket Policy":
            self.run_in_thread(self._get_bucket_policy, bucket_name)
        elif action == "Delete Bucket Policy":
            self.run_in_thread(self._delete_bucket_policy, bucket_name)
        elif action == "Delete Attached Policy":
            self.run_in_thread(self._delete_attached_policy, bucket_name)

    def _add_bucket_policy(self, bucket_name, policy):
        try:
            self.s3_client.put_bucket_policy(Bucket=bucket_name, Policy=policy)
            self.signal_manager.message_signal.emit(f"Policy added to bucket '{bucket_name}'.")
        except ParamValidationError as e:
            self.signal_manager.message_signal.emit(f"Invalid bucket name: {bucket_name}. Error: {str(e)}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error adding policy: {str(e)}")

    def _get_bucket_policy(self, bucket_name):
        try:
            response = self.s3_client.get_bucket_policy(Bucket=bucket_name)
            policy = response['Policy']
            self.signal_manager.message_signal.emit(f"Policy for bucket '{bucket_name}':\n{policy}")
        except ParamValidationError as e:
            self.signal_manager.message_signal.emit(f"Invalid bucket name: {bucket_name}. Error: {str(e)}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error getting policy: {str(e)}")

    def _delete_bucket_policy(self, bucket_name):
        try:
            self.s3_client.delete_bucket_policy(Bucket=bucket_name)
            self.signal_manager.message_signal.emit(f"Policy deleted from bucket '{bucket_name}'.")
        except ParamValidationError as e:
            self.signal_manager.message_signal.emit(f"Invalid bucket name: {bucket_name}. Error: {str(e)}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error deleting policy: {str(e)}")

    def _delete_attached_policy(self, bucket_name):
        # Implement this function as per your specific requirements
        pass

    # Encryption Management Functions
    def execute_encryption_action(self):
        action = self.encryption_action_dropdown.currentText()
        bucket_name = self.bucket_dropdown.currentText().strip()

        if action == "Add Encryption":
            self.run_in_thread(self._add_encryption, bucket_name)
        elif action == "Check Encryption":
            self.run_in_thread(self._check_encryption, bucket_name)
        elif action == "Delete Encryption":
            self.run_in_thread(self._delete_encryption, bucket_name)

    def _add_encryption(self, bucket_name):
        try:
            encryption_config = {
                'Rules': [{
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'AES256'
                    }
                }]
            }
            self.s3_client.put_bucket_encryption(
                Bucket=bucket_name,
                ServerSideEncryptionConfiguration=encryption_config
            )
            self.signal_manager.message_signal.emit(f"Encryption added to bucket '{bucket_name}'.")
        except ParamValidationError as e:
            self.signal_manager.message_signal.emit(f"Invalid bucket name: {bucket_name}. Error: {str(e)}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error adding encryption: {str(e)}")

    def _check_encryption(self, bucket_name):
        try:
            response = self.s3_client.get_bucket_encryption(Bucket=bucket_name)
            self.signal_manager.message_signal.emit(f"Encryption configuration for bucket '{bucket_name}':\n{response}")
        except ParamValidationError as e:
            self.signal_manager.message_signal.emit(f"Invalid bucket name: {bucket_name}. Error: {str(e)}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error checking encryption: {str(e)}")

    def _delete_encryption(self, bucket_name):
        try:
            self.s3_client.delete_bucket_encryption(Bucket=bucket_name)
            self.signal_manager.message_signal.emit(f"Encryption removed from bucket '{bucket_name}'.")
        except ParamValidationError as e:
            self.signal_manager.message_signal.emit(f"Invalid bucket name: {bucket_name}. Error: {str(e)}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error deleting encryption: {str(e)}")
