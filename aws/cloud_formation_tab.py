import json
import sys
import threading

import boto3
import botocore
from botocore.exceptions import ClientError
from PyQt5.QtCore import Q_ARG, QMetaObject, QObject, Qt, pyqtSignal
from PyQt5.QtWidgets import (QComboBox, QFileDialog, QFormLayout, QHBoxLayout,
                             QInputDialog, QLabel, QLineEdit, QMessageBox,
                             QPushButton, QTabWidget, QTextEdit, QVBoxLayout,
                             QWidget)


class SignalManager(QObject):
    message_signal = pyqtSignal(str)
    dropdown_signal = pyqtSignal(list)
    clear_signal = pyqtSignal()


class CloudFormationTab(QWidget):
    def __init__(self, session):
        super().__init__()
        self.current_session = session
        self.cf_client = session.client('cloudformation')
        self.signal_manager = SignalManager()
        self.initUI()
        self.connect_signals()
        self.load_stacks()

    def initUI(self):
        main_layout = QHBoxLayout()

        # Left Column: CloudFormation Management Section with Subtabs
        left_column = QVBoxLayout()

        # Refresh Button for Stacks
        self.refresh_button = QPushButton("Refresh Stacks", self)
        self.refresh_button.clicked.connect(self.refresh_stacks)
        left_column.addWidget(self.refresh_button)

        # Existing Stacks Dropdown (available globally within CloudFormationTab)
        self.existing_stacks_dropdown = QComboBox(self)
        self.existing_stacks_dropdown.setPlaceholderText("Select a Stack")
        left_column.addWidget(QLabel("Existing Stacks:"))
        left_column.addWidget(self.existing_stacks_dropdown)

        # Create Subtabs for Different Functionalities
        self.cf_subtabs = QTabWidget()
        left_column.addWidget(self.cf_subtabs)

        # Stack Management Subtab
        self.stack_management_tab = QWidget()
        self.cf_subtabs.addTab(self.stack_management_tab, "Stack Management")
        self.setup_stack_management_tab()

        # Change Sets Subtab
        self.change_sets_tab = QWidget()
        self.cf_subtabs.addTab(self.change_sets_tab, "Change Sets")
        self.setup_change_sets_tab()

        # Template Management Subtab
        self.template_management_tab = QWidget()
        self.cf_subtabs.addTab(self.template_management_tab, "Template Management")
        self.setup_template_management_tab()

        # Stack Events Subtab
        self.stack_events_tab = QWidget()
        self.cf_subtabs.addTab(self.stack_events_tab, "Stack Events")
        self.setup_stack_events_tab()

        # Stack Outputs Subtab
        self.stack_outputs_tab = QWidget()
        self.cf_subtabs.addTab(self.stack_outputs_tab, "Stack Outputs")
        self.setup_stack_outputs_tab()

        # Add stretch to push elements to the top
        left_column.addStretch()

        # Right Column: Output Area
        right_column = QVBoxLayout()

        self.output_area = QTextEdit(self)
        self.output_area.setReadOnly(True)

        right_column.addWidget(QLabel("CloudFormation Action Output:"))
        right_column.addWidget(self.output_area)

        # Add columns to the main layout with specific stretch factors
        main_layout.addLayout(left_column, 2)
        main_layout.addLayout(right_column, 3)

        self.setLayout(main_layout)

    def connect_signals(self):
        self.signal_manager.message_signal.connect(self.show_message)
        self.signal_manager.dropdown_signal.connect(self.populate_stacks)
        self.signal_manager.clear_signal.connect(self.clear_output_area)

    def run_in_thread(self, target, *args, **kwargs):
        thread = threading.Thread(target=target, args=args, kwargs=kwargs)
        thread.start()

    def refresh_stacks(self):
        self.run_in_thread(self.load_stacks)
        self.signal_manager.message_signal.emit("Refreshing stacks...")

    def load_stacks(self):
        try:
            paginator = self.cf_client.get_paginator('list_stacks')
            stack_status_filter = [
                'CREATE_COMPLETE', 'UPDATE_COMPLETE', 'DELETE_COMPLETE',
                'ROLLBACK_COMPLETE', 'UPDATE_ROLLBACK_COMPLETE'
            ]
            stacks = []
            for page in paginator.paginate(StackStatusFilter=stack_status_filter):
                for stack in page['StackSummaries']:
                    stacks.append(stack['StackName'])
            self.signal_manager.dropdown_signal.emit(stacks)
            self.signal_manager.message_signal.emit("Stacks loaded successfully.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error loading stacks: {str(e)}")

    def populate_stacks(self, stacks):
        self.existing_stacks_dropdown.clear()
        self.existing_stacks_dropdown.addItems(stacks)

    def show_message(self, message):
        QMetaObject.invokeMethod(
            self.output_area, "append", Qt.QueuedConnection, Q_ARG(str, message)
        )

    def clear_output_area(self):
        QMetaObject.invokeMethod(
            self.output_area, "clear", Qt.QueuedConnection
        )

    # -------------------- Stack Management Subtab --------------------
    def setup_stack_management_tab(self):
        layout = QFormLayout()

        # Stack Name
        self.create_stack_name_input = QLineEdit(self)
        self.create_stack_name_input.setPlaceholderText("Enter stack name")
        layout.addRow(QLabel("Stack Name:"), self.create_stack_name_input)

        # Template File Selection
        template_layout = QHBoxLayout()
        self.select_template_button = QPushButton("Select Template File", self)
        self.select_template_button.clicked.connect(self.select_template_file)
        self.template_file_path = QLineEdit(self)
        self.template_file_path.setReadOnly(True)
        template_layout.addWidget(self.select_template_button)
        template_layout.addWidget(self.template_file_path)
        layout.addRow(QLabel("Template File:"), template_layout)

        # Parameters (Optional)
        self.parameters_input = QLineEdit(self)
        self.parameters_input.setPlaceholderText("Enter parameters in JSON format")
        layout.addRow(QLabel("Parameters:"), self.parameters_input)

        # Execute Buttons
        buttons_layout = QHBoxLayout()
        self.execute_create_stack_button = QPushButton("Create Stack", self)
        self.execute_create_stack_button.clicked.connect(self.execute_create_stack)
        self.execute_delete_stack_button = QPushButton("Delete Stack", self)
        self.execute_delete_stack_button.clicked.connect(self.execute_delete_stack)
        layout.addRow(buttons_layout)
        buttons_layout.addWidget(self.execute_create_stack_button)
        buttons_layout.addWidget(self.execute_delete_stack_button)

        # Describe Stack Button
        self.execute_describe_stack_button = QPushButton("Describe Stack", self)
        self.execute_describe_stack_button.clicked.connect(self.execute_describe_stack)
        layout.addRow(self.execute_describe_stack_button)

        self.stack_management_tab.setLayout(layout)

    def select_template_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select CloudFormation Template", "", "YAML Files (*.yaml *.yml);;JSON Files (*.json)")
        if file_path:
            self.template_file_path.setText(file_path)

    def execute_create_stack(self):
        stack_name = self.create_stack_name_input.text()
        template_path = self.template_file_path.text()
        parameters_text = self.parameters_input.text()

        if not stack_name or not template_path:
            self.signal_manager.message_signal.emit("Please provide both stack name and template file.")
            return

        parameters = {}
        if parameters_text:
            try:
                parameters = json.loads(parameters_text)
            except json.JSONDecodeError as e:
                self.signal_manager.message_signal.emit(f"Invalid JSON for parameters: {str(e)}")
                return

        self.run_in_thread(self._create_stack, stack_name, template_path, parameters)

    def _create_stack(self, stack_name, template_path, parameters):
        try:
            with open(template_path, 'r') as f:
                template_body = f.read()

            # Transform parameters to the format required by CloudFormation
            cf_parameters = []
            for key, value in parameters.items():
                cf_parameters.append({
                    'ParameterKey': key,
                    'ParameterValue': str(value)
                })

            response = self.cf_client.create_stack(
                StackName=stack_name,
                TemplateBody=template_body,
                Parameters=cf_parameters,
                Capabilities=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM'],
                OnFailure='ROLLBACK'
            )
            stack_id = response['StackId']
            self.signal_manager.message_signal.emit(f"Stack '{stack_name}' creation initiated. Stack ID: {stack_id}")
            self.run_in_thread(self.load_stacks)  # Refresh stacks list
        except FileNotFoundError:
            self.signal_manager.message_signal.emit(f"Template file not found: {template_path}")
        except ClientError as e:
            self.signal_manager.message_signal.emit(f"Error creating stack: {str(e)}")

    def execute_delete_stack(self):
        stack_name = self.existing_stacks_dropdown.currentText()
        if not stack_name:
            self.signal_manager.message_signal.emit("Please select a stack to delete.")
            return

        confirm = QMessageBox.question(
            self, "Delete Stack",
            f"Are you sure you want to delete the stack '{stack_name}'?",
            QMessageBox.Yes | QMessageBox.No
        )

        if confirm == QMessageBox.Yes:
            self.run_in_thread(self._delete_stack, stack_name)

    def _delete_stack(self, stack_name):
        try:
            response = self.cf_client.delete_stack(StackName=stack_name)
            self.signal_manager.message_signal.emit(f"Stack '{stack_name}' deletion initiated.")
            self.run_in_thread(self.load_stacks)  # Refresh stacks list
        except ClientError as e:
            self.signal_manager.message_signal.emit(f"Error deleting stack: {str(e)}")

    def execute_describe_stack(self):
        stack_name = self.existing_stacks_dropdown.currentText()
        if not stack_name:
            self.signal_manager.message_signal.emit("Please select a stack to describe.")
            return

        self.run_in_thread(self._describe_stack, stack_name)

    def _describe_stack(self, stack_name):
        try:
            response = self.cf_client.describe_stacks(StackName=stack_name)
            stacks = response.get('Stacks', [])
            if stacks:
                stack = stacks[0]
                stack_info = json.dumps(stack, indent=4, default=str)
                self.signal_manager.message_signal.emit(f"Description of stack '{stack_name}':\n{stack_info}")
            else:
                self.signal_manager.message_signal.emit(f"No information found for stack '{stack_name}'.")
        except ClientError as e:
            self.signal_manager.message_signal.emit(f"Error describing stack: {str(e)}")

    # -------------------- Change Sets Subtab --------------------
    def setup_change_sets_tab(self):
        layout = QFormLayout()

        # Select Stack
        self.change_set_stack_dropdown = QComboBox(self)
        self.change_set_stack_dropdown.setPlaceholderText("Select a Stack")
        layout.addRow(QLabel("Select Stack:"), self.change_set_stack_dropdown)

        # Change Set Name
        self.change_set_name_input = QLineEdit(self)
        self.change_set_name_input.setPlaceholderText("Enter change set name")
        layout.addRow(QLabel("Change Set Name:"), self.change_set_name_input)

        # Template File Selection
        template_layout = QHBoxLayout()
        self.change_set_select_template_button = QPushButton("Select Template File", self)
        self.change_set_select_template_button.clicked.connect(self.select_change_set_template_file)
        self.change_set_template_file_path = QLineEdit(self)
        self.change_set_template_file_path.setReadOnly(True)
        template_layout.addWidget(self.change_set_select_template_button)
        template_layout.addWidget(self.change_set_template_file_path)
        layout.addRow(QLabel("Template File:"), template_layout)

        # Parameters (Optional)
        self.change_set_parameters_input = QLineEdit(self)
        self.change_set_parameters_input.setPlaceholderText("Enter parameters in JSON format")
        layout.addRow(QLabel("Parameters:"), self.change_set_parameters_input)

        # Execute Buttons
        buttons_layout = QHBoxLayout()
        self.execute_create_change_set_button = QPushButton("Create Change Set", self)
        self.execute_create_change_set_button.clicked.connect(self.execute_create_change_set)
        self.execute_execute_change_set_button = QPushButton("Execute Change Set", self)
        self.execute_execute_change_set_button.clicked.connect(self.execute_execute_change_set)
        layout.addRow(buttons_layout)
        buttons_layout.addWidget(self.execute_create_change_set_button)
        buttons_layout.addWidget(self.execute_execute_change_set_button)

        # List Change Sets Button
        self.execute_list_change_sets_button = QPushButton("List Change Sets", self)
        self.execute_list_change_sets_button.clicked.connect(self.execute_list_change_sets)
        layout.addRow(self.execute_list_change_sets_button)

        self.change_sets_tab.setLayout(layout)

    def select_change_set_template_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select CloudFormation Template", "", "YAML Files (*.yaml *.yml);;JSON Files (*.json)")
        if file_path:
            self.change_set_template_file_path.setText(file_path)

    def execute_create_change_set(self):
        stack_name = self.change_set_stack_dropdown.currentText()
        change_set_name = self.change_set_name_input.text()
        template_path = self.change_set_template_file_path.text()
        parameters_text = self.change_set_parameters_input.text()

        if not all([stack_name, change_set_name, template_path]):
            self.signal_manager.message_signal.emit("Please provide stack name, change set name, and template file.")
            return

        parameters = {}
        if parameters_text:
            try:
                parameters = json.loads(parameters_text)
            except json.JSONDecodeError as e:
                self.signal_manager.message_signal.emit(f"Invalid JSON for parameters: {str(e)}")
                return

        self.run_in_thread(self._create_change_set, stack_name, change_set_name, template_path, parameters)

    def _create_change_set(self, stack_name, change_set_name, template_path, parameters):
        try:
            with open(template_path, 'r') as f:
                template_body = f.read()

            # Transform parameters to the format required by CloudFormation
            cf_parameters = []
            for key, value in parameters.items():
                cf_parameters.append({
                    'ParameterKey': key,
                    'ParameterValue': str(value)
                })

            response = self.cf_client.create_change_set(
                StackName=stack_name,
                ChangeSetName=change_set_name,
                TemplateBody=template_body,
                Parameters=cf_parameters,
                Capabilities=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM'],
                ChangeSetType='UPDATE'  # or 'CREATE' based on stack existence
            )
            change_set_id = response['Id']
            self.signal_manager.message_signal.emit(f"Change set '{change_set_name}' creation initiated. Change Set ID: {change_set_id}")
        except FileNotFoundError:
            self.signal_manager.message_signal.emit(f"Template file not found: {template_path}")
        except ClientError as e:
            self.signal_manager.message_signal.emit(f"Error creating change set: {str(e)}")

    def execute_execute_change_set(self):
        stack_name = self.change_set_stack_dropdown.currentText()
        change_set_name = self.change_set_name_input.text()

        if not all([stack_name, change_set_name]):
            self.signal_manager.message_signal.emit("Please provide both stack name and change set name to execute.")
            return

        self.run_in_thread(self._execute_change_set, stack_name, change_set_name)

    def _execute_change_set(self, stack_name, change_set_name):
        try:
            response = self.cf_client.execute_change_set(
                ChangeSetName=change_set_name,
                StackName=stack_name
            )
            self.signal_manager.message_signal.emit(f"Change set '{change_set_name}' executed successfully.")
        except ClientError as e:
            self.signal_manager.message_signal.emit(f"Error executing change set: {str(e)}")

    def execute_list_change_sets(self):
        stack_name = self.change_set_stack_dropdown.currentText()
        if not stack_name:
            self.signal_manager.message_signal.emit("Please select a stack to list change sets.")
            return

        self.run_in_thread(self._list_change_sets, stack_name)

    def _list_change_sets(self, stack_name):
        try:
            paginator = self.cf_client.get_paginator('list_change_sets')
            change_sets = []
            for page in paginator.paginate(StackName=stack_name):
                change_sets.extend(page.get('Summaries', []))
            if change_sets:
                cs_list = "\n".join([f"Name: {cs['ChangeSetName']}, Status: {cs['Status']}, Execution Status: {cs['ExecutionStatus']}" for cs in change_sets])
                self.signal_manager.message_signal.emit(f"Change Sets for stack '{stack_name}':\n{cs_list}")
            else:
                self.signal_manager.message_signal.emit(f"No change sets found for stack '{stack_name}'.")
        except ClientError as e:
            self.signal_manager.message_signal.emit(f"Error listing change sets: {str(e)}")

    # -------------------- Template Management Subtab --------------------
    def setup_template_management_tab(self):
        layout = QFormLayout()

        # Template File Selection
        template_layout = QHBoxLayout()
        self.template_select_file_button = QPushButton("Select Template File", self)
        self.template_select_file_button.clicked.connect(self.select_template_file_management)
        self.template_management_file_path = QLineEdit(self)
        self.template_management_file_path.setReadOnly(True)
        template_layout.addWidget(self.template_select_file_button)
        template_layout.addWidget(self.template_management_file_path)
        layout.addRow(QLabel("Template File:"), template_layout)

        # Execute Buttons
        self.execute_upload_template_button = QPushButton("Upload Template", self)
        self.execute_upload_template_button.clicked.connect(self.execute_upload_template)
        self.execute_delete_template_button = QPushButton("Delete Template", self)
        self.execute_delete_template_button.clicked.connect(self.execute_delete_template_management)
        self.execute_list_templates_button = QPushButton("List Templates", self)
        self.execute_list_templates_button.clicked.connect(self.execute_list_templates_management)
        layout.addRow(self.execute_upload_template_button)
        layout.addRow(self.execute_delete_template_button)
        layout.addRow(self.execute_list_templates_button)

        self.template_management_tab.setLayout(layout)

    def select_template_file_management(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select CloudFormation Template", "", "YAML Files (*.yaml *.yml);;JSON Files (*.json)")
        if file_path:
            self.template_management_file_path.setText(file_path)

    def execute_upload_template(self):
        template_path = self.template_management_file_path.text()

        if not template_path:
            self.signal_manager.message_signal.emit("Please select a template file to upload.")
            return

        self.run_in_thread(self._upload_template, template_path)

    def _upload_template(self, template_path):
        try:
            with open(template_path, 'r') as f:
                template_body = f.read()

            # Extract template name from file name
            import os
            template_name = os.path.splitext(os.path.basename(template_path))[0]

            # Validate template
            self.cf_client.validate_template(TemplateBody=template_body)

            # Note: CloudFormation does not have an 'upload template' API.
            # Templates are used during stack operations.
            # To store templates, you might consider uploading them to S3 and referencing the S3 URL.
            # This section can be adjusted based on specific requirements.

            self.signal_manager.message_signal.emit(f"Template '{template_name}' validated successfully.")
        except FileNotFoundError:
            self.signal_manager.message_signal.emit(f"Template file not found: {template_path}")
        except ClientError as e:
            self.signal_manager.message_signal.emit(f"Error uploading template: {str(e)}")
        except Exception as e:
            self.signal_manager.message_signal.emit(f"Unexpected error: {str(e)}")

    def execute_delete_template_management(self):
        # Placeholder: CloudFormation does not store templates separately.
        # Implement template deletion if using S3 or another storage service.
        template_name, ok = QInputDialog.getText(
            self, "Delete Template", "Enter the template name to delete:"
        )
        if not ok or not template_name:
            return

        confirm = QMessageBox.question(
            self, "Delete Template",
            f"Are you sure you want to delete the template '{template_name}'?",
            QMessageBox.Yes | QMessageBox.No
        )

        if confirm == QMessageBox.Yes:
            self.run_in_thread(self._delete_template_management, template_name)

    def _delete_template_management(self, template_name):
        try:
            # Since CloudFormation does not store templates separately,
            # this functionality depends on how you store templates (e.g., in S3).
            # This is a placeholder implementation.
            self.signal_manager.message_signal.emit(f"Template '{template_name}' deletion not implemented. CloudFormation does not store templates separately.")
        except ClientError as e:
            self.signal_manager.message_signal.emit(f"Error deleting template: {str(e)}")

    def execute_list_templates_management(self):
        try:
            # Since CloudFormation does not have a 'list templates' API,
            # list templates from your storage service (e.g., S3).
            # This is a placeholder implementation.
            self.signal_manager.message_signal.emit("List Templates functionality is not implemented. CloudFormation does not store templates separately.")
        except ClientError as e:
            self.signal_manager.message_signal.emit(f"Error listing templates: {str(e)}")

    # -------------------- Stack Events Subtab --------------------
    def setup_stack_events_tab(self):
        layout = QFormLayout()

        # Select Stack
        self.events_stack_dropdown = QComboBox(self)
        self.events_stack_dropdown.setPlaceholderText("Select a Stack")
        layout.addRow(QLabel("Select Stack:"), self.events_stack_dropdown)

        # Time Range Inputs
        self.events_start_time_input = QLineEdit(self)
        self.events_start_time_input.setPlaceholderText("Enter start time (e.g., 2023-01-01T00:00:00Z)")
        layout.addRow(QLabel("Start Time:"), self.events_start_time_input)

        self.events_end_time_input = QLineEdit(self)
        self.events_end_time_input.setPlaceholderText("Enter end time (e.g., 2023-12-31T23:59:59Z)")
        layout.addRow(QLabel("End Time:"), self.events_end_time_input)

        # Execute Button
        self.execute_view_events_button = QPushButton("View Stack Events", self)
        self.execute_view_events_button.clicked.connect(self.execute_view_stack_events)
        layout.addRow(self.execute_view_events_button)

        self.stack_events_tab.setLayout(layout)

    def execute_view_stack_events(self):
        stack_name = self.events_stack_dropdown.currentText()
        start_time = self.events_start_time_input.text()
        end_time = self.events_end_time_input.text()

        if not stack_name:
            self.signal_manager.message_signal.emit("Please select a stack to view events.")
            return

        if not all([start_time, end_time]):
            self.signal_manager.message_signal.emit("Please enter both start time and end time.")
            return

        self.run_in_thread(self._view_stack_events, stack_name, start_time, end_time)

    def _view_stack_events(self, stack_name, start_time, end_time):
        try:
            paginator = self.cf_client.get_paginator('describe_stack_events')
            events = []
            for page in paginator.paginate(StackName=stack_name):
                for event in page['StackEvents']:
                    event_time = event.get('Timestamp')
                    # Convert start_time and end_time to datetime objects for comparison
                    from datetime import datetime
                    try:
                        start_dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
                        end_dt = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
                        if start_dt <= event_time <= end_dt:
                            event_desc = f"ID: {event['EventId']}, Time: {event['Timestamp']}, Resource: {event['LogicalResourceId']}, Status: {event['ResourceStatus']}, Status Reason: {event.get('ResourceStatusReason', 'N/A')}"
                            events.append(event_desc)
                    except ValueError:
                        self.signal_manager.message_signal.emit("Invalid date format. Please use ISO 8601 format (e.g., 2023-01-01T00:00:00Z).")
                        return
            if events:
                events_list = "\n".join(events)
                self.signal_manager.message_signal.emit(f"Stack Events for '{stack_name}' between {start_time} and {end_time}:\n{events_list}")
            else:
                self.signal_manager.message_signal.emit(f"No stack events found for '{stack_name}' in the specified time range.")
        except ClientError as e:
            self.signal_manager.message_signal.emit(f"Error fetching stack events: {str(e)}")

    # -------------------- Stack Outputs Subtab --------------------
    def setup_stack_outputs_tab(self):
        layout = QFormLayout()

        # Select Stack
        self.outputs_stack_dropdown = QComboBox(self)
        self.outputs_stack_dropdown.setPlaceholderText("Select a Stack")
        layout.addRow(QLabel("Select Stack:"), self.outputs_stack_dropdown)

        # Execute Button
        self.execute_view_outputs_button = QPushButton("View Stack Outputs", self)
        self.execute_view_outputs_button.clicked.connect(self.execute_view_stack_outputs)
        layout.addRow(self.execute_view_outputs_button)

        self.stack_outputs_tab.setLayout(layout)

    def execute_view_stack_outputs(self):
        stack_name = self.outputs_stack_dropdown.currentText()
        if not stack_name:
            self.signal_manager.message_signal.emit("Please select a stack to view outputs.")
            return

        self.run_in_thread(self._view_stack_outputs, stack_name)

    def _view_stack_outputs(self, stack_name):
        try:
            response = self.cf_client.describe_stacks(StackName=stack_name)
            stacks = response.get('Stacks', [])
            if stacks:
                outputs = stacks[0].get('Outputs', [])
                if outputs:
                    outputs_str = "\n".join([f"Output Key: {output['OutputKey']}, Value: {output['OutputValue']}, Description: {output.get('Description', 'N/A')}" for output in outputs])
                    self.signal_manager.message_signal.emit(f"Stack Outputs for '{stack_name}':\n{outputs_str}")
                else:
                    self.signal_manager.message_signal.emit(f"No outputs found for stack '{stack_name}'.")
            else:
                self.signal_manager.message_signal.emit(f"No information found for stack '{stack_name}'.")
        except ClientError as e:
            self.signal_manager.message_signal.emit(f"Error fetching stack outputs: {str(e)}")
