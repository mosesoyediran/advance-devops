import json
import sys
import threading

import boto3
import botocore
from botocore.exceptions import ParamValidationError
from PyQt5.QtCore import Q_ARG, QMetaObject, QObject, Qt, pyqtSignal
from PyQt5.QtWidgets import (QApplication, QComboBox, QFileDialog, QFormLayout,
                             QGroupBox, QHBoxLayout, QInputDialog, QLabel,
                             QLineEdit, QMessageBox, QPushButton, QScrollArea,
                             QSizePolicy, QTabWidget, QTextEdit, QVBoxLayout,
                             QWidget)


class SignalManager(QObject):
    message_signal = pyqtSignal(str)
    dropdown_signal = pyqtSignal(list)
    clear_signal = pyqtSignal()


class LambdaTab(QWidget):
    def __init__(self, session):
        super().__init__()
        self.current_session = session
        self.lambda_client = session.client('lambda')
        self.iam_client = session.client('iam')
        self.s3_client = session.client('s3')
        self.signal_manager = SignalManager()
        self.initUI()
        self.connect_signals()
        self.load_iam_roles()
        self.load_lambda_functions()

    def initUI(self):
        main_layout = QHBoxLayout()

        # Left Column: Lambda Management Section with Subtabs
        left_column = QVBoxLayout()

        # Refresh Button for Lambda Functions and IAM Roles
        self.refresh_button = QPushButton("Refresh Resources", self)
        self.refresh_button.clicked.connect(self.refresh_resources)
        left_column.addWidget(self.refresh_button)

        # Existing Lambda Functions Dropdown (available globally within LambdaTab)
        self.existing_functions_dropdown = QComboBox(self)
        self.existing_functions_dropdown.setPlaceholderText("Select a Lambda Function")
        left_column.addWidget(QLabel("Existing Lambda Functions:"))
        left_column.addWidget(self.existing_functions_dropdown)

        # Create Subtabs for Different Functionalities
        self.lambda_subtabs = QTabWidget()
        left_column.addWidget(self.lambda_subtabs)

        # Function Management Subtab
        self.function_management_tab = QWidget()
        self.lambda_subtabs.addTab(self.function_management_tab, "Function Management")
        self.setup_function_management_tab()

        # Invocation Subtab
        self.invocation_tab = QWidget()
        self.lambda_subtabs.addTab(self.invocation_tab, "Invocation")
        self.setup_invocation_tab()

        # Trigger Management Subtab
        self.trigger_management_tab = QWidget()
        self.lambda_subtabs.addTab(self.trigger_management_tab, "Trigger Management")
        self.setup_trigger_management_tab()

        # Alias Management Subtab
        self.alias_management_tab = QWidget()
        self.lambda_subtabs.addTab(self.alias_management_tab, "Alias Management")
        self.setup_alias_management_tab()

        # Version Management Subtab
        self.version_management_tab = QWidget()
        self.lambda_subtabs.addTab(self.version_management_tab, "Version Management")
        self.setup_version_management_tab()

        # Add stretch to push elements to the top
        left_column.addStretch()

        # Right Column: Output Area
        right_column = QVBoxLayout()

        self.output_area = QTextEdit(self)
        self.output_area.setReadOnly(True)

        right_column.addWidget(QLabel("Lambda Action Output:"))
        right_column.addWidget(self.output_area)

        # Add columns to the main layout with specific stretch factors
        main_layout.addLayout(left_column, 2)
        main_layout.addLayout(right_column, 3)

        self.setLayout(main_layout)

    def connect_signals(self):
        self.signal_manager.message_signal.connect(self.show_message)
        self.signal_manager.dropdown_signal.connect(self.populate_dropdown)
        self.signal_manager.clear_signal.connect(self.clear_output_area)

    def run_in_thread(self, target, *args, **kwargs):
        thread = threading.Thread(target=target, args=args, kwargs=kwargs)
        thread.start()

    def refresh_resources(self):
        self.run_in_thread(self.load_iam_roles)
        self.run_in_thread(self.load_lambda_functions)
        self.signal_manager.message_signal.emit("Refreshing resources...")

    def load_iam_roles(self):
        try:
            roles = []
            paginator = self.iam_client.get_paginator('list_roles')
            for page in paginator.paginate(MaxItems=1000):
                for role in page['Roles']:
                    roles.append(role['RoleName'])
            self.signal_manager.dropdown_signal.emit(roles)
            self.signal_manager.message_signal.emit("IAM Roles loaded successfully.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error loading IAM roles: {str(e)}")

    def load_lambda_functions(self):
        try:
            functions = []
            paginator = self.lambda_client.get_paginator('list_functions')
            for page in paginator.paginate():
                for function in page['Functions']:
                    functions.append(function['FunctionName'])
            self.signal_manager.dropdown_signal.emit(functions)
            self.signal_manager.message_signal.emit("Lambda functions loaded successfully.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error loading Lambda functions: {str(e)}")

    def populate_dropdown(self, items):
        sender = self.sender()
        if sender == self.signal_manager.dropdown_signal:
            # Populate IAM Roles Dropdown in Function Management Tab
            self.function_role_dropdown.clear()
            self.function_role_dropdown.addItems(items)

            # Populate existing functions dropdown
            self.existing_functions_dropdown.clear()
            self.existing_functions_dropdown.addItems(items)

            # Populate Function Dropdowns in other subtabs
            self.invocation_function_dropdown.clear()
            self.invocation_function_dropdown.addItems(items)

            self.trigger_function_dropdown.clear()
            self.trigger_function_dropdown.addItems(items)

            self.alias_function_dropdown.clear()
            self.alias_function_dropdown.addItems(items)

            self.version_function_dropdown.clear()
            self.version_function_dropdown.addItems(items)

    def show_message(self, message):
        QMetaObject.invokeMethod(
            self.output_area, "append", Qt.QueuedConnection, Q_ARG(str, message)
        )

    def clear_output_area(self):
        QMetaObject.invokeMethod(
            self.output_area, "clear", Qt.QueuedConnection
        )

    def setup_function_management_tab(self):
        layout = QFormLayout()

        # Function Name
        self.create_function_name = QLineEdit(self)
        self.create_function_name.setPlaceholderText("Enter function name")
        layout.addRow(QLabel("Function Name:"), self.create_function_name)

        # Runtime
        self.runtime_input = QComboBox(self)
        self.runtime_input.addItems([
            "python3.9", "python3.8", "nodejs14.x", "nodejs16.x",
            "java11", "dotnet6", "go1.x", "ruby2.7", "provided.al2"
        ])
        layout.addRow(QLabel("Runtime:"), self.runtime_input)

        # IAM Role Dropdown (Uses the main dropdown)
        self.function_role_dropdown = QComboBox(self)
        self.function_role_dropdown.setPlaceholderText("Select IAM Role")
        layout.addRow(QLabel("IAM Role:"), self.function_role_dropdown)

        # Handler
        self.handler_input = QLineEdit(self)
        self.handler_input.setPlaceholderText("e.g., lambda_function.lambda_handler")
        layout.addRow(QLabel("Handler:"), self.handler_input)

        # ZIP File Selection
        zip_layout = QHBoxLayout()
        self.create_zip_file_button = QPushButton("Select ZIP File", self)
        self.create_zip_file_button.clicked.connect(self.select_zip_file_create)
        self.create_zip_file_path = QLineEdit(self)
        self.create_zip_file_path.setReadOnly(True)
        zip_layout.addWidget(self.create_zip_file_button)
        zip_layout.addWidget(self.create_zip_file_path)
        layout.addRow(QLabel("ZIP File:"), zip_layout)

        # Execute Button
        self.execute_create_function_button = QPushButton("Execute Create Function", self)
        self.execute_create_function_button.clicked.connect(self.execute_create_function)
        layout.addRow(self.execute_create_function_button)

        # Describe Function Button
        self.describe_function_button = QPushButton("Describe Function", self)
        self.describe_function_button.clicked.connect(self.execute_describe_function)
        layout.addRow(self.describe_function_button)

        self.function_management_tab.setLayout(layout)

    def setup_invocation_tab(self):
        layout = QFormLayout()

        # Select Function (Removed redundant dropdown)
        # Use the main existing_functions_dropdown
        # No additional dropdown needed in subtab

        # Payload Input
        self.payload_input = QTextEdit(self)
        self.payload_input.setPlaceholderText("Enter JSON payload")
        layout.addRow(QLabel("Payload:"), self.payload_input)

        # Execute Button
        self.execute_invoke_function_button = QPushButton("Execute Invoke Function", self)
        self.execute_invoke_function_button.clicked.connect(self.execute_invoke_function)
        layout.addRow(self.execute_invoke_function_button)

        self.invocation_tab.setLayout(layout)

    def setup_trigger_management_tab(self):
        layout = QFormLayout()

        # Select Trigger Type
        self.trigger_type_dropdown = QComboBox(self)
        self.trigger_type_dropdown.addItems([
            "s3", "sns", "sqs", "cloudwatch-event", "cloudwatch-log", "api-gateway"
        ])
        layout.addRow(QLabel("Trigger Type:"), self.trigger_type_dropdown)

        # Trigger Configuration
        self.trigger_configuration_input = QTextEdit(self)
        self.trigger_configuration_input.setPlaceholderText("Enter trigger configuration in JSON")
        layout.addRow(QLabel("Trigger Configuration:"), self.trigger_configuration_input)

        # Execute Buttons
        buttons_layout = QHBoxLayout()
        self.execute_add_trigger_button = QPushButton("Add Trigger", self)
        self.execute_add_trigger_button.clicked.connect(self.execute_add_trigger)
        self.execute_remove_trigger_button = QPushButton("Remove Trigger", self)
        self.execute_remove_trigger_button.clicked.connect(self.execute_remove_trigger)
        buttons_layout.addWidget(self.execute_add_trigger_button)
        buttons_layout.addWidget(self.execute_remove_trigger_button)
        layout.addRow(buttons_layout)

        self.trigger_management_tab.setLayout(layout)

    def setup_alias_management_tab(self):
        layout = QFormLayout()

        # Alias Name
        self.alias_name_input = QLineEdit(self)
        self.alias_name_input.setPlaceholderText("Enter alias name")
        layout.addRow(QLabel("Alias Name:"), self.alias_name_input)

        # Function Version
        self.alias_function_version_input = QLineEdit(self)
        self.alias_function_version_input.setPlaceholderText("Enter function version")
        layout.addRow(QLabel("Function Version:"), self.alias_function_version_input)

        # Execute Button
        self.execute_manage_alias_button = QPushButton("Execute Manage Alias", self)
        self.execute_manage_alias_button.clicked.connect(self.execute_manage_alias)
        layout.addRow(self.execute_manage_alias_button)

        self.alias_management_tab.setLayout(layout)

    def setup_version_management_tab(self):
        layout = QFormLayout()

        # Version Action
        self.version_action_dropdown = QComboBox(self)
        self.version_action_dropdown.addItems([
            "Publish New Version", "List Versions", "Delete Version"
        ])
        layout.addRow(QLabel("Version Action:"), self.version_action_dropdown)

        # Version Specific Input
        self.version_specific_input = QLineEdit(self)
        self.version_specific_input.setPlaceholderText("Enter version number (for Delete)")
        layout.addRow(QLabel("Version:"), self.version_specific_input)

        # Execute Button
        self.execute_version_management_button = QPushButton("Execute Version Action", self)
        self.execute_version_management_button.clicked.connect(self.execute_version_management)
        layout.addRow(self.execute_version_management_button)

        self.version_management_tab.setLayout(layout)

    def execute_create_function(self):
        function_name = self.create_function_name.text()
        runtime = self.runtime_input.currentText()
        role_name = self.function_role_dropdown.currentText()
        handler = self.handler_input.text()
        zip_path = self.create_zip_file_path.text()

        if not all([function_name, runtime, role_name, handler, zip_path]):
            self.signal_manager.message_signal.emit("Please fill all fields for creating a function.")
            return

        # Get Role ARN from role name
        try:
            role_response = self.iam_client.get_role(RoleName=role_name)
            role_arn = role_response['Role']['Arn']
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error fetching IAM role ARN: {str(e)}")
            return

        self.run_in_thread(self._create_function, function_name, runtime, role_arn, handler, zip_path)

    def _create_function(self, function_name, runtime, role_arn, handler, zip_path):
        try:
            with open(zip_path, 'rb') as f:
                zipped_code = f.read()

            response = self.lambda_client.create_function(
                FunctionName=function_name,
                Runtime=runtime,
                Role=role_arn,
                Handler=handler,
                Code={'ZipFile': zipped_code},
                Publish=True
            )
            self.signal_manager.message_signal.emit(f"Function '{function_name}' created successfully.")
            self.run_in_thread(self.load_lambda_functions)  # Refresh functions list
        except FileNotFoundError:
            self.signal_manager.message_signal.emit(f"ZIP file not found: {zip_path}")
        except ParamValidationError as e:
            self.signal_manager.message_signal.emit(f"Parameter validation error: {str(e)}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error creating function: {str(e)}")

    def execute_describe_function(self):
        function_name = self.existing_functions_dropdown.currentText()
        if not function_name:
            self.signal_manager.message_signal.emit("Please select a function to describe.")
            return
        self.run_in_thread(self._describe_function, function_name)

    def _describe_function(self, function_name):
        try:
            response = self.lambda_client.get_function(FunctionName=function_name)
            config = json.dumps(response, indent=4, default=str)
            self.signal_manager.message_signal.emit(f"Configuration for function '{function_name}':\n{config}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error describing function: {str(e)}")

    def execute_invoke_function(self):
        function_name = self.existing_functions_dropdown.currentText()
        payload = self.payload_input.toPlainText()

        if not function_name:
            self.signal_manager.message_signal.emit("Please select a function to invoke.")
            return

        try:
            payload_json = json.loads(payload) if payload else {}
        except json.JSONDecodeError as e:
            self.signal_manager.message_signal.emit(f"Invalid JSON payload: {str(e)}")
            return

        self.run_in_thread(self._invoke_function, function_name, payload_json)

    def _invoke_function(self, function_name, payload):
        try:
            response = self.lambda_client.invoke(
                FunctionName=function_name,
                InvocationType='RequestResponse',
                Payload=json.dumps(payload).encode()
            )
            response_payload = response['Payload'].read().decode()
            self.signal_manager.message_signal.emit(
                f"Function '{function_name}' invoked successfully.\nResponse:\n{response_payload}"
            )
        except ParamValidationError as e:
            self.signal_manager.message_signal.emit(f"Parameter validation error: {str(e)}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error invoking function: {str(e)}")

    def execute_add_trigger(self):
        function_name = self.existing_functions_dropdown.currentText()
        trigger_type = self.trigger_type_dropdown.currentText()
        trigger_config = self.trigger_configuration_input.toPlainText()

        if not all([function_name, trigger_type, trigger_config]):
            self.signal_manager.message_signal.emit("Please fill all fields to add a trigger.")
            return

        try:
            trigger_config_json = json.loads(trigger_config)
        except json.JSONDecodeError as e:
            self.signal_manager.message_signal.emit(f"Invalid JSON for trigger configuration: {str(e)}")
            return

        self.run_in_thread(self._add_trigger, function_name, trigger_type, trigger_config_json)

    def _add_trigger(self, function_name, trigger_type, trigger_config):
        try:
            if trigger_type.lower() == "s3":
                bucket = trigger_config.get("Bucket")
                events = trigger_config.get("Events", ["s3:ObjectCreated:*"])
                prefix = trigger_config.get("Prefix", "")
                suffix = trigger_config.get("Suffix", "")

                if not bucket:
                    self.signal_manager.message_signal.emit("Bucket name is required for S3 triggers.")
                    return

                # Add S3 permission to Lambda
                account_id = self._get_account_id()
                if not account_id:
                    return

                lambda_arn = f"arn:aws:lambda:{self.current_session.region_name}:{account_id}:function:{function_name}"

                self.lambda_client.add_permission(
                    FunctionName=function_name,
                    StatementId=f"{function_name}-s3-trigger-permission",
                    Action='lambda:InvokeFunction',
                    Principal='s3.amazonaws.com',
                    SourceArn=f"arn:aws:s3:::{bucket}"
                )

                # Configure S3 to send notifications to Lambda
                notification_configuration = self.s3_client.get_bucket_notification_configuration(Bucket=bucket)
                if 'LambdaFunctionConfigurations' not in notification_configuration:
                    notification_configuration['LambdaFunctionConfigurations'] = []

                # Avoid adding duplicate triggers
                for config_item in notification_configuration['LambdaFunctionConfigurations']:
                    if config_item['LambdaFunctionArn'] == lambda_arn:
                        self.signal_manager.message_signal.emit(f"Trigger already exists for bucket '{bucket}'.")
                        return

                config = {
                    'LambdaFunctionArn': lambda_arn,
                    'Events': events,
                }
                if prefix or suffix:
                    config['Filter'] = {
                        'Key': {
                            'FilterRules': []
                        }
                    }
                    if prefix:
                        config['Filter']['Key']['FilterRules'].append({
                            'Name': 'prefix',
                            'Value': prefix
                        })
                    if suffix:
                        config['Filter']['Key']['FilterRules'].append({
                            'Name': 'suffix',
                            'Value': suffix
                        })

                notification_configuration['LambdaFunctionConfigurations'].append(config)

                self.s3_client.put_bucket_notification_configuration(
                    Bucket=bucket,
                    NotificationConfiguration=notification_configuration
                )

                self.signal_manager.message_signal.emit(f"S3 trigger added to function '{function_name}' for bucket '{bucket}'.")

            else:
                self.signal_manager.message_signal.emit(f"Trigger type '{trigger_type}' not supported yet.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error adding trigger: {str(e)}")
        except Exception as e:
            self.signal_manager.message_signal.emit(f"Unexpected error adding trigger: {str(e)}")

    def execute_remove_trigger(self):
        function_name = self.existing_functions_dropdown.currentText()
        trigger_type = self.trigger_type_dropdown.currentText()

        if not all([function_name, trigger_type]):
            self.signal_manager.message_signal.emit("Please fill all fields to remove a trigger.")
            return

        self.run_in_thread(self._remove_trigger, function_name, trigger_type)

    def _remove_trigger(self, function_name, trigger_type):
        try:
            if trigger_type.lower() == "s3":
                # Prompt for bucket name
                bucket, ok = QInputDialog.getText(
                    self, "Remove S3 Trigger", "Enter the S3 bucket name to remove the trigger:"
                )
                if not ok or not bucket:
                    self.signal_manager.message_signal.emit("Trigger removal canceled.")
                    return

                account_id = self._get_account_id()
                if not account_id:
                    return

                lambda_arn = f"arn:aws:lambda:{self.current_session.region_name}:{account_id}:function:{function_name}"

                # Remove S3 notification
                notification_configuration = self.s3_client.get_bucket_notification_configuration(Bucket=bucket)

                if 'LambdaFunctionConfigurations' in notification_configuration:
                    original_count = len(notification_configuration['LambdaFunctionConfigurations'])
                    notification_configuration['LambdaFunctionConfigurations'] = [
                        config for config in notification_configuration['LambdaFunctionConfigurations']
                        if config['LambdaFunctionArn'] != lambda_arn
                    ]
                    removed_count = original_count - len(notification_configuration['LambdaFunctionConfigurations'])
                    if removed_count > 0:
                        self.s3_client.put_bucket_notification_configuration(
                            Bucket=bucket,
                            NotificationConfiguration=notification_configuration
                        )
                        self.signal_manager.message_signal.emit(f"Removed {removed_count} trigger(s) from bucket '{bucket}'.")
                    else:
                        self.signal_manager.message_signal.emit(f"No triggers found for bucket '{bucket}'.")
                else:
                    self.signal_manager.message_signal.emit(f"No triggers found for bucket '{bucket}'.")
            else:
                self.signal_manager.message_signal.emit(f"Trigger type '{trigger_type}' not supported yet.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error removing trigger: {str(e)}")
        except Exception as e:
            self.signal_manager.message_signal.emit(f"Unexpected error removing trigger: {str(e)}")

    def execute_manage_alias(self):
        function_name = self.existing_functions_dropdown.currentText()
        alias_name = self.alias_name_input.text()
        function_version = self.alias_function_version_input.text()

        if not all([function_name, alias_name, function_version]):
            self.signal_manager.message_signal.emit("Please fill all fields to manage aliases.")
            return

        self.run_in_thread(self._manage_aliases, function_name, alias_name, function_version)

    def _manage_aliases(self, function_name, alias_name, function_version):
        try:
            # Create or update an alias
            response = self.lambda_client.create_alias(
                FunctionName=function_name,
                Name=alias_name,
                FunctionVersion=function_version,
                Description=f"Alias '{alias_name}' for version {function_version}"
            )
            self.signal_manager.message_signal.emit(f"Alias '{alias_name}' created for function '{function_name}'.")
        except self.lambda_client.exceptions.ResourceConflictException:
            # Alias already exists, update it
            try:
                response = self.lambda_client.update_alias(
                    FunctionName=function_name,
                    Name=alias_name,
                    FunctionVersion=function_version,
                    Description=f"Alias '{alias_name}' updated to version {function_version}"
                )
                self.signal_manager.message_signal.emit(f"Alias '{alias_name}' updated to version {function_version} for function '{function_name}'.")
            except botocore.exceptions.ClientError as e:
                self.signal_manager.message_signal.emit(f"Error updating alias: {str(e)}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error managing aliases: {str(e)}")

    def execute_version_management(self):
        function_name = self.existing_functions_dropdown.currentText()
        version_action = self.version_action_dropdown.currentText()
        version = self.version_specific_input.text()

        if not function_name:
            self.signal_manager.message_signal.emit("Please select a function.")
            return

        if version_action == "Delete Version" and not version:
            self.signal_manager.message_signal.emit("Please enter the version number to delete.")
            return

        if version_action == "Publish New Version":
            self.run_in_thread(self._publish_new_version, function_name)
        elif version_action == "List Versions":
            self.run_in_thread(self._list_versions, function_name)
        elif version_action == "Delete Version":
            self.run_in_thread(self._delete_version, function_name, version)

    def _publish_new_version(self, function_name):
        try:
            response = self.lambda_client.publish_version(FunctionName=function_name)
            version = response['Version']
            self.signal_manager.message_signal.emit(f"New version '{version}' published for function '{function_name}'.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error publishing new version: {str(e)}")

    def _list_versions(self, function_name):
        try:
            paginator = self.lambda_client.get_paginator('list_versions_by_function')
            versions = []
            for page in paginator.paginate(FunctionName=function_name):
                for version in page['Versions']:
                    versions.append(f"Version: {version['Version']}, LastModified: {version['LastModified']}, Description: {version.get('Description', 'N/A')}")

            if versions:
                versions_list = "\n".join(versions)
                self.signal_manager.message_signal.emit(f"Versions for function '{function_name}':\n{versions_list}")
            else:
                self.signal_manager.message_signal.emit(f"No versions found for function '{function_name}'.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error listing versions: {str(e)}")

    def _delete_version(self, function_name, version):
        try:
            response = self.lambda_client.delete_function(
                FunctionName=function_name,
                Qualifier=version
            )
            self.signal_manager.message_signal.emit(f"Version '{version}' of function '{function_name}' deleted successfully.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error deleting version: {str(e)}")

    def _manage_aliases(self, function_name, alias_name, function_version):
        try:
            # Create or update an alias
            response = self.lambda_client.create_alias(
                FunctionName=function_name,
                Name=alias_name,
                FunctionVersion=function_version,
                Description=f"Alias '{alias_name}' for version {function_version}"
            )
            self.signal_manager.message_signal.emit(f"Alias '{alias_name}' created for function '{function_name}'.")
        except self.lambda_client.exceptions.ResourceConflictException:
            # Alias already exists, update it
            try:
                response = self.lambda_client.update_alias(
                    FunctionName=function_name,
                    Name=alias_name,
                    FunctionVersion=function_version,
                    Description=f"Alias '{alias_name}' updated to version {function_version}"
                )
                self.signal_manager.message_signal.emit(f"Alias '{alias_name}' updated to version {function_version} for function '{function_name}'.")
            except botocore.exceptions.ClientError as e:
                self.signal_manager.message_signal.emit(f"Error updating alias: {str(e)}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error managing aliases: {str(e)}")

    def _get_account_id(self):
        try:
            sts_client = self.current_session.client('sts')
            identity = sts_client.get_caller_identity()
            return identity['Account']
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error retrieving account ID: {str(e)}")
            return None

    def execute_add_trigger(self):
        function_name = self.existing_functions_dropdown.currentText()
        trigger_type = self.trigger_type_dropdown.currentText()
        trigger_config = self.trigger_configuration_input.toPlainText()

        if not all([function_name, trigger_type, trigger_config]):
            self.signal_manager.message_signal.emit("Please fill all fields to add a trigger.")
            return

        try:
            trigger_config_json = json.loads(trigger_config)
        except json.JSONDecodeError as e:
            self.signal_manager.message_signal.emit(f"Invalid JSON for trigger configuration: {str(e)}")
            return

        self.run_in_thread(self._add_trigger, function_name, trigger_type, trigger_config_json)

    def execute_remove_trigger(self):
        function_name = self.existing_functions_dropdown.currentText()
        trigger_type = self.trigger_type_dropdown.currentText()

        if not all([function_name, trigger_type]):
            self.signal_manager.message_signal.emit("Please fill all fields to remove a trigger.")
            return

        self.run_in_thread(self._remove_trigger, function_name, trigger_type)

    def execute_manage_alias(self):
        function_name = self.existing_functions_dropdown.currentText()
        alias_name = self.alias_name_input.text()
        function_version = self.alias_function_version_input.text()

        if not all([function_name, alias_name, function_version]):
            self.signal_manager.message_signal.emit("Please fill all fields to manage aliases.")
            return

        self.run_in_thread(self._manage_aliases, function_name, alias_name, function_version)

    def select_zip_file_create(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select ZIP File", "", "ZIP Files (*.zip)")
        if file_path:
            self.create_zip_file_path.setText(file_path)


# Example S3Tab class (Placeholder)
class S3Tab(QWidget):
    def __init__(self, session):
        super().__init__()
        # Initialize your S3Tab UI and functionalities here
        layout = QVBoxLayout()
        label = QLabel("S3 Management Tab - Implementation Pending")
        layout.addWidget(label)
        self.setLayout(layout)



