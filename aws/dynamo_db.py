import json
import re
import sys
import threading
from datetime import datetime, timedelta

import boto3
import botocore
from botocore.exceptions import ClientError, ParamValidationError
from PyQt5.QtCore import Q_ARG, QMetaObject, QObject, Qt, pyqtSignal
from PyQt5.QtGui import QMovie
from PyQt5.QtWidgets import (QApplication, QComboBox, QFileDialog, QFormLayout,
                             QHBoxLayout, QHeaderView, QInputDialog, QLabel,
                             QLineEdit, QMessageBox, QPushButton, QTableWidget,
                             QTableWidgetItem, QTabWidget, QTextEdit,
                             QVBoxLayout, QWidget)


class SignalManager(QObject):
    message_signal = pyqtSignal(str)
    dropdown_signal = pyqtSignal(list, str)  # list, dropdown_name
    clear_signal = pyqtSignal()


class DynamoDBTab(QWidget):
    def __init__(self, session):
        super().__init__()
        self.current_session = session
        self.dynamodb_client = session.client('dynamodb')
        self.signal_manager = SignalManager()
        self.initUI()
        self.connect_signals()
        self.load_tables()

    def initUI(self):
        main_layout = QHBoxLayout()

        # Left Column: DynamoDB Management Section with Subtabs
        left_column = QVBoxLayout()

        # Refresh Button for Tables
        self.refresh_button = QPushButton("Refresh Tables", self)
        self.refresh_button.clicked.connect(self.refresh_tables)
        left_column.addWidget(self.refresh_button)

        # Existing Tables Dropdown
        self.existing_tables_dropdown = QComboBox(self)
        self.existing_tables_dropdown.setPlaceholderText("Select a Table")
        left_column.addWidget(QLabel("Existing Tables:"))
        left_column.addWidget(self.existing_tables_dropdown)

        # Status Label for User Feedback
        self.status_label = QLabel("", self)
        left_column.addWidget(self.status_label)

        # Loading Indicator (GIF)
        self.loading_movie = QMovie("loading.gif")
        self.loading_label = QLabel(self)
        self.loading_label.setMovie(self.loading_movie)
        self.loading_label.setVisible(False)
        left_column.addWidget(self.loading_label)

        # Create Subtabs for Different Functionalities
        self.dynamodb_subtabs = QTabWidget()
        left_column.addWidget(self.dynamodb_subtabs)

        # Table Management Subtab
        self.table_management_tab = QWidget()
        self.dynamodb_subtabs.addTab(self.table_management_tab, "Table Management")
        self.setup_table_management_tab()

        # Item Management Subtab
        self.item_management_tab = QWidget()
        self.dynamodb_subtabs.addTab(self.item_management_tab, "Item Management")
        self.setup_item_management_tab()

        # Index Management Subtab
        self.index_management_tab = QWidget()
        self.dynamodb_subtabs.addTab(self.index_management_tab, "Index Management")
        self.setup_index_management_tab()

        # Monitoring Subtab
        self.monitoring_tab = QWidget()
        self.dynamodb_subtabs.addTab(self.monitoring_tab, "Monitoring")
        self.setup_monitoring_tab()

        # Add stretch to push elements to the top
        left_column.addStretch()

        # Right Column: Output Area
        right_column = QVBoxLayout()

        self.output_area = QTextEdit(self)
        self.output_area.setReadOnly(True)

        right_column.addWidget(QLabel("DynamoDB Action Output:"))
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

    # -------------------- User Feedback Methods --------------------
    def show_loading(self):
        self.loading_label.setVisible(True)
        self.loading_movie.start()
        self.status_label.setText("Operation in progress...")

    def hide_loading(self):
        self.loading_movie.stop()
        self.loading_label.setVisible(False)
        self.status_label.setText("")

    def show_message(self, message):
        # Sanitize the message if necessary
        safe_message = self.sanitize_message(message)
        QMetaObject.invokeMethod(
            self.output_area, "append", Qt.QueuedConnection, Q_ARG(str, safe_message)
        )

    def sanitize_message(self, message):
        # Implement any necessary sanitization here
        # For example, remove or mask sensitive information
        return message

    def clear_output_area(self):
        QMetaObject.invokeMethod(
            self.output_area, "clear", Qt.QueuedConnection
        )

    def populate_dropdown(self, items, dropdown_name):
        if dropdown_name == 'tables':
            self.existing_tables_dropdown.clear()
            self.existing_tables_dropdown.addItems(items)

    # -------------------- Input Validation Methods --------------------
    def is_valid_table_name(self, table_name):
        """
        Validate the table name format: 255 characters or less, consisting of letters, numbers, underscores, hyphens.
        """
        return bool(re.match(r'^[a-zA-Z0-9_-]{1,255}$', table_name))

    def is_valid_key_schema(self, key_schema):
        """
        Validate the key schema: list of key definitions with AttributeName and KeyType.
        """
        if not isinstance(key_schema, list) or not key_schema:
            return False
        for key in key_schema:
            if 'AttributeName' not in key or 'KeyType' not in key:
                return False
            if key['KeyType'] not in ['HASH', 'RANGE']:
                return False
        return True

    def is_valid_attribute_definitions(self, attr_definitions):
        """
        Validate attribute definitions: list with AttributeName and AttributeType.
        """
        if not isinstance(attr_definitions, list) or not attr_definitions:
            return False
        for attr in attr_definitions:
            if 'AttributeName' not in attr or 'AttributeType' not in attr:
                return False
            if attr['AttributeType'] not in ['S', 'N', 'B']:
                return False
        return True

    def validate_read_write_capacity(self, read_capacity, write_capacity):
        """
        Validate that read and write capacities are positive integers.
        """
        return read_capacity.isdigit() and write_capacity.isdigit() and int(read_capacity) > 0 and int(write_capacity) > 0

    # -------------------- Table Management Subtab --------------------
    def setup_table_management_tab(self):
        layout = QFormLayout()

        # Table Name
        self.table_name_input = QLineEdit(self)
        self.table_name_input.setPlaceholderText("Enter table name")
        layout.addRow(QLabel("Table Name:"), self.table_name_input)

        # Attribute Definitions (JSON)
        self.attribute_definitions_input = QLineEdit(self)
        self.attribute_definitions_input.setPlaceholderText('Enter attribute definitions as JSON, e.g., [{"AttributeName": "Id", "AttributeType": "S"}]')
        layout.addRow(QLabel("Attribute Definitions:"), self.attribute_definitions_input)

        # Key Schema (JSON)
        self.key_schema_input = QLineEdit(self)
        self.key_schema_input.setPlaceholderText='Enter key schema as JSON, e.g., [{"AttributeName": "Id", "KeyType": "HASH"}]'
        layout.addRow(QLabel("Key Schema:"), self.key_schema_input)

        # Provisioned Throughput
        self.read_capacity_input = QLineEdit(self)
        self.read_capacity_input.setPlaceholderText("Enter read capacity units")
        layout.addRow(QLabel("Read Capacity Units:"), self.read_capacity_input)

        self.write_capacity_input = QLineEdit(self)
        self.write_capacity_input.setPlaceholderText("Enter write capacity units")
        layout.addRow(QLabel("Write Capacity Units:"), self.write_capacity_input)

        # Execute Buttons
        self.create_table_button = QPushButton("Create Table", self)
        self.create_table_button.clicked.connect(self.create_table)
        layout.addRow(self.create_table_button)

        self.describe_table_button = QPushButton("Describe Table", self)
        self.describe_table_button.clicked.connect(self.describe_table)
        layout.addRow(self.describe_table_button)

        self.delete_table_button = QPushButton("Delete Table", self)
        self.delete_table_button.clicked.connect(self.delete_table)
        layout.addRow(self.delete_table_button)

        self.update_table_button = QPushButton("Update Table", self)
        self.update_table_button.clicked.connect(self.update_table)
        layout.addRow(self.update_table_button)

        self.table_management_tab.setLayout(layout)

    def create_table(self):
        table_name = self.table_name_input.text().strip()
        attribute_definitions = self.attribute_definitions_input.text().strip()
        key_schema = self.key_schema_input.text().strip()
        read_capacity = self.read_capacity_input.text().strip()
        write_capacity = self.write_capacity_input.text().strip()

        # Validation: All fields must be filled
        if not all([table_name, attribute_definitions, key_schema, read_capacity, write_capacity]):
            self.signal_manager.message_signal.emit("Please fill all fields to create a table.")
            return

        # Validate table name
        if not self.is_valid_table_name(table_name):
            self.signal_manager.message_signal.emit("Invalid table name format. Must be 255 characters or less, consisting of letters, numbers, underscores, hyphens.")
            return

        # Parse JSON inputs
        try:
            attribute_definitions = json.loads(attribute_definitions)
            key_schema = json.loads(key_schema)
        except json.JSONDecodeError:
            self.signal_manager.message_signal.emit("Attribute Definitions and Key Schema must be valid JSON.")
            return

        # Validate attribute definitions and key schema
        if not self.is_valid_attribute_definitions(attribute_definitions):
            self.signal_manager.message_signal.emit("Invalid Attribute Definitions format.")
            return

        if not self.is_valid_key_schema(key_schema):
            self.signal_manager.message_signal.emit("Invalid Key Schema format.")
            return

        # Validate provisioned throughput
        if not self.validate_read_write_capacity(read_capacity, write_capacity):
            self.signal_manager.message_signal.emit("Read and Write Capacity Units must be positive integers.")
            return

        # Check if table already exists
        if self.is_table_exists(table_name):
            self.signal_manager.message_signal.emit(f"Table '{table_name}' already exists. Please choose a different name.")
            return

        self.show_loading()
        self.run_in_thread(
            self._create_table,
            table_name,
            attribute_definitions,
            key_schema,
            int(read_capacity),
            int(write_capacity)
        )

    def _create_table(self, table_name, attribute_definitions, key_schema, read_capacity, write_capacity):
        try:
            response = self.dynamodb_client.create_table(
                TableName=table_name,
                AttributeDefinitions=attribute_definitions,
                KeySchema=key_schema,
                ProvisionedThroughput={
                    'ReadCapacityUnits': read_capacity,
                    'WriteCapacityUnits': write_capacity
                }
            )
            self.signal_manager.message_signal.emit(f"Table '{table_name}' creation initiated successfully.")
            self.run_in_thread(self.load_tables)  # Refresh tables list
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['ResourceInUseException', 'AccessDeniedException', 'ValidationException']:
                self.signal_manager.message_signal.emit(f"Error creating table: {e.response['Error']['Message']}")
            else:
                self.signal_manager.message_signal.emit(f"Error creating table: {str(e)}")
        finally:
            self.hide_loading()

    def describe_table(self):
        table_name = self.existing_tables_dropdown.currentText()
        if not table_name:
            self.signal_manager.message_signal.emit("Please select a table to describe.")
            return

        # Extract Table Name from the selected item
        table_name = table_name.split('(')[0].strip()

        self.show_loading()
        self.run_in_thread(self._describe_table, table_name)

    def _describe_table(self, table_name):
        try:
            response = self.dynamodb_client.describe_table(TableName=table_name)
            table = response['Table']
            table_info = json.dumps(table, indent=4, default=str)
            self.signal_manager.message_signal.emit(f"Description of Table '{table_name}':\n{table_info}")
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ResourceNotFoundException':
                self.signal_manager.message_signal.emit(f"Table '{table_name}' does not exist.")
            else:
                self.signal_manager.message_signal.emit(f"Error describing table: {str(e)}")
        finally:
            self.hide_loading()

    def delete_table(self):
        table_name = self.existing_tables_dropdown.currentText()
        if not table_name:
            self.signal_manager.message_signal.emit("Please select a table to delete.")
            return

        # Extract Table Name from the selected item
        table_name = table_name.split('(')[0].strip()

        confirm = QMessageBox.question(
            self, "Delete Table",
            f"Are you sure you want to delete the table '{table_name}'?",
            QMessageBox.Yes | QMessageBox.No
        )

        if confirm == QMessageBox.Yes:
            self.show_loading()
            self.run_in_thread(self._delete_table, table_name)

    def _delete_table(self, table_name):
        try:
            self.dynamodb_client.delete_table(TableName=table_name)
            self.signal_manager.message_signal.emit(f"Table '{table_name}' deletion initiated successfully.")
            self.run_in_thread(self.load_tables)  # Refresh tables list
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ResourceNotFoundException':
                self.signal_manager.message_signal.emit(f"Table '{table_name}' does not exist.")
            else:
                self.signal_manager.message_signal.emit(f"Error deleting table: {str(e)}")
        finally:
            self.hide_loading()

    def update_table(self):
        table_name = self.existing_tables_dropdown.currentText()
        if not table_name:
            self.signal_manager.message_signal.emit("Please select a table to update.")
            return

        # Extract Table Name from the selected item
        table_name = table_name.split('(')[0].strip()

        # Prompt user for new provisioned throughput
        read_capacity, ok = QInputDialog.getText(
            self, "Update Table", "Enter new Read Capacity Units:"
        )
        if not ok or not read_capacity.isdigit() or int(read_capacity) <= 0:
            self.signal_manager.message_signal.emit("Invalid Read Capacity Units.")
            return

        write_capacity, ok = QInputDialog.getText(
            self, "Update Table", "Enter new Write Capacity Units:"
        )
        if not ok or not write_capacity.isdigit() or int(write_capacity) <= 0:
            self.signal_manager.message_signal.emit("Invalid Write Capacity Units.")
            return

        self.show_loading()
        self.run_in_thread(
            self._update_table,
            table_name,
            int(read_capacity),
            int(write_capacity)
        )

    def _update_table(self, table_name, read_capacity, write_capacity):
        try:
            response = self.dynamodb_client.update_table(
                TableName=table_name,
                ProvisionedThroughput={
                    'ReadCapacityUnits': read_capacity,
                    'WriteCapacityUnits': write_capacity
                }
            )
            self.signal_manager.message_signal.emit(f"Table '{table_name}' update initiated successfully.")
            self.run_in_thread(self.load_tables)  # Refresh tables list
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['ResourceNotFoundException', 'ValidationException', 'AccessDeniedException']:
                self.signal_manager.message_signal.emit(f"Error updating table: {e.response['Error']['Message']}")
            else:
                self.signal_manager.message_signal.emit(f"Error updating table: {str(e)}")
        finally:
            self.hide_loading()

    def load_tables(self):
        try:
            tables = []
            paginator = self.dynamodb_client.get_paginator('list_tables')
            for page in paginator.paginate():
                tables.extend(page['TableNames'])
            self.signal_manager.dropdown_signal.emit(tables, 'tables')
            self.signal_manager.message_signal.emit("Tables loaded successfully.")
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['AccessDeniedException', 'UnauthorizedOperation']:
                self.signal_manager.message_signal.emit("Permission denied. Please ensure your AWS credentials have the necessary permissions.")
            else:
                self.signal_manager.message_signal.emit(f"Error loading tables: {str(e)}")

    def refresh_tables(self):
        self.show_loading()
        self.run_in_thread(self.load_tables)
        self.signal_manager.message_signal.emit("Refreshing tables...")

    def is_table_exists(self, table_name):
        try:
            self.dynamodb_client.describe_table(TableName=table_name)
            return True
        except self.dynamodb_client.exceptions.ResourceNotFoundException:
            return False
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error checking table existence: {str(e)}")
            return False

    # -------------------- Item Management Subtab --------------------
    def setup_item_management_tab(self):
        layout = QFormLayout()

        # Select Table
        self.item_table_dropdown = QComboBox(self)
        self.item_table_dropdown.setPlaceholderText("Select a Table")
        layout.addRow(QLabel("Select Table:"), self.item_table_dropdown)
        self.populate_item_table_dropdown()

        # Primary Key Attributes
        self.primary_keys_label = QLabel("Primary Key Attributes:")
        layout.addRow(self.primary_keys_label)
        self.primary_keys_display = QLabel("", self)
        layout.addRow(self.primary_keys_display)

        # Item Attributes (JSON)
        self.item_attributes_input = QLineEdit(self)
        self.item_attributes_input.setPlaceholderText('Enter item attributes as JSON, e.g., {"Id": {"S": "123"}, "Name": {"S": "John Doe"}}')
        layout.addRow(QLabel("Item Attributes:"), self.item_attributes_input)

        # Execute Buttons
        self.add_item_button = QPushButton("Add Item", self)
        self.add_item_button.clicked.connect(self.add_item)
        layout.addRow(self.add_item_button)

        self.get_item_button = QPushButton("Get Item", self)
        self.get_item_button.clicked.connect(self.get_item)
        layout.addRow(self.get_item_button)

        self.update_item_button = QPushButton("Update Item", self)
        self.update_item_button.clicked.connect(self.update_item)
        layout.addRow(self.update_item_button)

        self.delete_item_button = QPushButton("Delete Item", self)
        self.delete_item_button.clicked.connect(self.delete_item)
        layout.addRow(self.delete_item_button)

        self.query_scan_button = QPushButton("Query/Scan Items", self)
        self.query_scan_button.clicked.connect(self.query_scan_items)
        layout.addRow(self.query_scan_button)

        self.item_management_tab.setLayout(layout)
        self.item_table_dropdown.currentTextChanged.connect(self.display_primary_keys)

    def populate_item_table_dropdown(self):
        tables = self.existing_tables_dropdown.currentText().split('\n') if self.existing_tables_dropdown.currentText() else []
        self.item_table_dropdown.clear()
        self.item_table_dropdown.addItems(tables)

    def display_primary_keys(self, table_entry):
        if not table_entry:
            self.primary_keys_display.setText("")
            return
        table_name = table_entry.split('(')[0].strip()
        try:
            response = self.dynamodb_client.describe_table(TableName=table_name)
            key_schema = response['Table']['KeySchema']
            keys = ', '.join([f"{key['AttributeName']} ({key['KeyType']})" for key in key_schema])
            self.primary_keys_display.setText(keys)
        except botocore.exceptions.ClientError as e:
            self.primary_keys_display.setText("Error fetching key schema.")
            self.signal_manager.message_signal.emit(f"Error fetching key schema: {str(e)}")

    def add_item(self):
        table_entry = self.item_table_dropdown.currentText()
        if not table_entry:
            self.signal_manager.message_signal.emit("Please select a table to add an item.")
            return

        # Extract Table Name
        table_name = table_entry.split('(')[0].strip()

        item_attributes = self.item_attributes_input.text().strip()
        if not item_attributes:
            self.signal_manager.message_signal.emit("Please enter item attributes.")
            return

        # Parse JSON
        try:
            item_attributes = json.loads(item_attributes)
        except json.JSONDecodeError:
            self.signal_manager.message_signal.emit("Item Attributes must be valid JSON.")
            return

        # Validate item attributes format
        if not isinstance(item_attributes, dict):
            self.signal_manager.message_signal.emit("Item Attributes must be a JSON object.")
            return

        self.show_loading()
        self.run_in_thread(
            self._add_item,
            table_name,
            item_attributes
        )

    def _add_item(self, table_name, item_attributes):
        try:
            response = self.dynamodb_client.put_item(
                TableName=table_name,
                Item=item_attributes
            )
            self.signal_manager.message_signal.emit(f"Item added to table '{table_name}' successfully.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error adding item: {str(e)}")
        finally:
            self.hide_loading()

    def get_item(self):
        table_entry = self.item_table_dropdown.currentText()
        if not table_entry:
            self.signal_manager.message_signal.emit("Please select a table to get an item.")
            return

        # Extract Table Name
        table_name = table_entry.split('(')[0].strip()

        # Prompt user for primary key(s)
        try:
            response = self.dynamodb_client.describe_table(TableName=table_name)
            key_schema = response['Table']['KeySchema']
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error describing table: {str(e)}")
            return

        key = {}
        for key_element in key_schema:
            attr_name = key_element['AttributeName']
            key_type = key_element['KeyType']
            value, ok = QInputDialog.getText(
                self, "Get Item", f"Enter value for {attr_name} ({key_type}):"
            )
            if not ok or not value:
                self.signal_manager.message_signal.emit("Primary key value is required.")
                return
            # For simplicity, assume all keys are of type String ('S')
            key[attr_name] = {'S': value}

        self.show_loading()
        self.run_in_thread(
            self._get_item,
            table_name,
            key
        )

    def _get_item(self, table_name, key):
        try:
            response = self.dynamodb_client.get_item(
                TableName=table_name,
                Key=key
            )
            item = response.get('Item', {})
            if not item:
                self.signal_manager.message_signal.emit("Item not found.")
                return
            item_info = json.dumps(item, indent=4)
            self.signal_manager.message_signal.emit(f"Item in table '{table_name}':\n{item_info}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error getting item: {str(e)}")
        finally:
            self.hide_loading()

    def update_item(self):
        table_entry = self.item_table_dropdown.currentText()
        if not table_entry:
            self.signal_manager.message_signal.emit("Please select a table to update an item.")
            return

        # Extract Table Name
        table_name = table_entry.split('(')[0].strip()

        # Prompt user for primary key(s)
        try:
            response = self.dynamodb_client.describe_table(TableName=table_name)
            key_schema = response['Table']['KeySchema']
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error describing table: {str(e)}")
            return

        key = {}
        for key_element in key_schema:
            attr_name = key_element['AttributeName']
            key_type = key_element['KeyType']
            value, ok = QInputDialog.getText(
                self, "Update Item", f"Enter value for {attr_name} ({key_type}):"
            )
            if not ok or not value:
                self.signal_manager.message_signal.emit("Primary key value is required.")
                return
            # For simplicity, assume all keys are of type String ('S')
            key[attr_name] = {'S': value}

        # Prompt for update expressions
        update_expression, ok = QInputDialog.getText(
            self, "Update Item", "Enter Update Expression (e.g., SET Age = :a):"
        )
        if not ok or not update_expression:
            self.signal_manager.message_signal.emit("Update Expression is required.")
            return

        # Prompt for Expression Attribute Values (JSON)
        expr_attr_values = QInputDialog.getText(
            self, "Update Item", "Enter Expression Attribute Values as JSON (e.g., {\":a\": {\"N\": \"30\"}}):"
        )
        if not expr_attr_values[1]:
            self.signal_manager.message_signal.emit("Expression Attribute Values are required.")
            return

        try:
            expr_attr_values = json.loads(expr_attr_values[0])
        except json.JSONDecodeError:
            self.signal_manager.message_signal.emit("Expression Attribute Values must be valid JSON.")
            return

        # Validate format
        if not isinstance(expr_attr_values, dict):
            self.signal_manager.message_signal.emit("Expression Attribute Values must be a JSON object.")
            return

        self.show_loading()
        self.run_in_thread(
            self._update_item,
            table_name,
            key,
            update_expression,
            expr_attr_values
        )

    def _update_item(self, table_name, key, update_expression, expr_attr_values):
        try:
            response = self.dynamodb_client.update_item(
                TableName=table_name,
                Key=key,
                UpdateExpression=update_expression,
                ExpressionAttributeValues=expr_attr_values,
                ReturnValues="UPDATED_NEW"
            )
            attributes = response.get('Attributes', {})
            attributes_info = json.dumps(attributes, indent=4)
            self.signal_manager.message_signal.emit(f"Item updated successfully. Updated attributes:\n{attributes_info}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error updating item: {str(e)}")
        finally:
            self.hide_loading()

    def delete_item(self):
        table_entry = self.item_table_dropdown.currentText()
        if not table_entry:
            self.signal_manager.message_signal.emit("Please select a table to delete an item.")
            return

        # Extract Table Name
        table_name = table_entry.split('(')[0].strip()

        # Prompt user for primary key(s)
        try:
            response = self.dynamodb_client.describe_table(TableName=table_name)
            key_schema = response['Table']['KeySchema']
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error describing table: {str(e)}")
            return

        key = {}
        for key_element in key_schema:
            attr_name = key_element['AttributeName']
            key_type = key_element['KeyType']
            value, ok = QInputDialog.getText(
                self, "Delete Item", f"Enter value for {attr_name} ({key_type}):"
            )
            if not ok or not value:
                self.signal_manager.message_signal.emit("Primary key value is required.")
                return
            # For simplicity, assume all keys are of type String ('S')
            key[attr_name] = {'S': value}

        self.show_loading()
        self.run_in_thread(
            self._delete_item,
            table_name,
            key
        )

    def _delete_item(self, table_name, key):
        try:
            response = self.dynamodb_client.delete_item(
                TableName=table_name,
                Key=key,
                ReturnValues="ALL_OLD"
            )
            old_item = response.get('Attributes', {})
            if not old_item:
                self.signal_manager.message_signal.emit("Item not found or already deleted.")
                return
            old_item_info = json.dumps(old_item, indent=4)
            self.signal_manager.message_signal.emit(f"Item deleted successfully. Previous attributes:\n{old_item_info}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error deleting item: {str(e)}")
        finally:
            self.hide_loading()

    def query_scan_items(self):
        table_entry = self.item_table_dropdown.currentText()
        if not table_entry:
            self.signal_manager.message_signal.emit("Please select a table to query/scan items.")
            return

        # Extract Table Name
        table_name = table_entry.split('(')[0].strip()

        # Prompt user for operation type
        operation, ok = QInputDialog.getItem(
            self, "Query/Scan Items", "Select operation:",
            ["Query", "Scan"], 0, False
        )
        if not ok or not operation:
            return

        filter_expression, ok = QInputDialog.getText(
            self, "Query/Scan Items", "Enter Filter Expression (optional):"
        )
        if not ok:
            return

        expr_attr_values = {}
        if filter_expression:
            expr_attr_values_input, ok = QInputDialog.getText(
                self, "Query/Scan Items", "Enter Expression Attribute Values as JSON (e.g., {\":val\": {\"S\": \"John\"}}):"
            )
            if not ok or not expr_attr_values_input:
                self.signal_manager.message_signal.emit("Expression Attribute Values are required for Filter Expression.")
                return
            try:
                expr_attr_values = json.loads(expr_attr_values_input)
            except json.JSONDecodeError:
                self.signal_manager.message_signal.emit("Expression Attribute Values must be valid JSON.")
                return

        # For Query, prompt for key condition expression
        key_condition_expression = ""
        if operation == "Query":
            key_condition_expression, ok = QInputDialog.getText(
                self, "Query Items", "Enter Key Condition Expression (e.g., \"Id = :id\"):"
            )
            if not ok or not key_condition_expression:
                self.signal_manager.message_signal.emit("Key Condition Expression is required for Query.")
                return

        self.show_loading()
        self.run_in_thread(
            self._query_scan_items,
            table_name,
            operation,
            key_condition_expression,
            filter_expression,
            expr_attr_values
        )

    def _query_scan_items(self, table_name, operation, key_condition_expression, filter_expression, expr_attr_values):
        try:
            if operation == "Query":
                response = self.dynamodb_client.query(
                    TableName=table_name,
                    KeyConditionExpression=key_condition_expression,
                    FilterExpression=filter_expression if filter_expression else None,
                    ExpressionAttributeValues=expr_attr_values if expr_attr_values else None
                )
                items = response.get('Items', [])
                if not items:
                    self.signal_manager.message_signal.emit("No items found matching the query.")
                    return
                items_info = json.dumps(items, indent=4)
                self.signal_manager.message_signal.emit(f"Query Results from '{table_name}':\n{items_info}")
            elif operation == "Scan":
                response = self.dynamodb_client.scan(
                    TableName=table_name,
                    FilterExpression=filter_expression if filter_expression else None,
                    ExpressionAttributeValues=expr_attr_values if expr_attr_values else None
                )
                items = response.get('Items', [])
                if not items:
                    self.signal_manager.message_signal.emit("No items found matching the scan criteria.")
                    return
                items_info = json.dumps(items, indent=4)
                self.signal_manager.message_signal.emit(f"Scan Results from '{table_name}':\n{items_info}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error performing {operation.lower()}: {str(e)}")
        finally:
            self.hide_loading()

    def load_tables(self):
        try:
            tables = []
            paginator = self.dynamodb_client.get_paginator('list_tables')
            for page in paginator.paginate():
                tables.extend(page['TableNames'])
            self.signal_manager.dropdown_signal.emit(tables, 'tables')
            self.signal_manager.message_signal.emit("Tables loaded successfully.")
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['AccessDeniedException', 'UnauthorizedOperation']:
                self.signal_manager.message_signal.emit("Permission denied. Please ensure your AWS credentials have the necessary permissions.")
            else:
                self.signal_manager.message_signal.emit(f"Error loading tables: {str(e)}")

    def refresh_tables(self):
        self.show_loading()
        self.run_in_thread(self.load_tables)
        self.signal_manager.message_signal.emit("Refreshing tables...")

    # -------------------- Helper Validation Methods --------------------
    def is_table_exists(self, table_name):
        try:
            self.dynamodb_client.describe_table(TableName=table_name)
            return True
        except self.dynamodb_client.exceptions.ResourceNotFoundException:
            return False
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error checking table existence: {str(e)}")
            return False

    # -------------------- Index Management Subtab --------------------
    def setup_index_management_tab(self):
        layout = QFormLayout()

        # Select Table
        self.index_table_dropdown = QComboBox(self)
        self.index_table_dropdown.setPlaceholderText("Select a Table")
        layout.addRow(QLabel("Select Table:"), self.index_table_dropdown)
        self.populate_index_table_dropdown()
        self.index_table_dropdown.currentTextChanged.connect(self.load_existing_indexes)

        # Existing Indexes Dropdown
        self.existing_indexes_dropdown = QComboBox(self)
        self.existing_indexes_dropdown.setPlaceholderText("Select an Index")
        layout.addRow(QLabel("Existing Indexes:"), self.existing_indexes_dropdown)

        # Index Name
        self.index_name_input = QLineEdit(self)
        self.index_name_input.setPlaceholderText("Enter index name")
        layout.addRow(QLabel("Index Name:"), self.index_name_input)

        # Attribute Definitions (JSON)
        self.index_attribute_definitions_input = QLineEdit(self)
        self.index_attribute_definitions_input.setPlaceholderText='Enter attribute definitions as JSON, e.g., [{"AttributeName": "Age", "AttributeType": "N"}]'
        layout.addRow(QLabel("Attribute Definitions:"), self.index_attribute_definitions_input)

        # Key Schema (JSON)
        self.index_key_schema_input = QLineEdit(self)
        self.index_key_schema_input.setPlaceholderText='Enter key schema as JSON, e.g., [{"AttributeName": "Age", "KeyType": "HASH"}]'
        layout.addRow(QLabel("Key Schema:"), self.index_key_schema_input)

        # Projection Type
        self.index_projection_type_dropdown = QComboBox(self)
        self.index_projection_type_dropdown.addItems(["ALL", "KEYS_ONLY", "INCLUDE"])
        layout.addRow(QLabel("Projection Type:"), self.index_projection_type_dropdown)

        # Non-Key Attributes (for INCLUDE projection type)
        self.index_non_key_attrs_input = QLineEdit(self)
        self.index_non_key_attrs_input.setPlaceholderText("Enter non-key attributes separated by commas")
        layout.addRow(QLabel("Non-Key Attributes:"), self.index_non_key_attrs_input)

        # Execute Buttons
        self.create_index_button = QPushButton("Create Index", self)
        self.create_index_button.clicked.connect(self.create_index)
        layout.addRow(self.create_index_button)

        self.delete_index_button = QPushButton("Delete Index", self)
        self.delete_index_button.clicked.connect(self.delete_index)
        layout.addRow(self.delete_index_button)

        self.index_management_tab.setLayout(layout)

    def populate_index_table_dropdown(self):
        tables = self.existing_tables_dropdown.currentText().split('\n') if self.existing_tables_dropdown.currentText() else []
        self.index_table_dropdown.clear()
        self.index_table_dropdown.addItems(tables)

    def load_existing_indexes(self, table_entry):
        if not table_entry:
            self.existing_indexes_dropdown.clear()
            return
        table_name = table_entry.split('(')[0].strip()
        try:
            response = self.dynamodb_client.describe_table(TableName=table_name)
            gsis = response['Table'].get('GlobalSecondaryIndexes', [])
            indexes = [gsi['IndexName'] for gsi in gsis]
            self.existing_indexes_dropdown.clear()
            self.existing_indexes_dropdown.addItems(indexes)
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error loading indexes: {str(e)}")

    def create_index(self):
        table_entry = self.index_table_dropdown.currentText()
        if not table_entry:
            self.signal_manager.message_signal.emit("Please select a table to create an index.")
            return

        table_name = table_entry.split('(')[0].strip()
        index_name = self.index_name_input.text().strip()
        attribute_definitions = self.index_attribute_definitions_input.text().strip()
        key_schema = self.index_key_schema_input.text().strip()
        projection_type = self.index_projection_type_dropdown.currentText()
        non_key_attrs = self.index_non_key_attrs_input.text().strip()

        # Validation: All required fields must be filled
        if not all([index_name, attribute_definitions, key_schema, projection_type]):
            self.signal_manager.message_signal.emit("Please fill all required fields to create an index.")
            return

        # Validate index name
        if not self.is_valid_table_name(index_name):
            self.signal_manager.message_signal.emit("Invalid Index Name format. Must be 255 characters or less, consisting of letters, numbers, underscores, hyphens.")
            return

        # Parse JSON inputs
        try:
            attribute_definitions = json.loads(attribute_definitions)
            key_schema = json.loads(key_schema)
        except json.JSONDecodeError:
            self.signal_manager.message_signal.emit("Attribute Definitions and Key Schema must be valid JSON.")
            return

        # Validate attribute definitions and key schema
        if not self.is_valid_attribute_definitions(attribute_definitions):
            self.signal_manager.message_signal.emit("Invalid Attribute Definitions format.")
            return

        if not self.is_valid_key_schema(key_schema):
            self.signal_manager.message_signal.emit("Invalid Key Schema format.")
            return

        # Handle projection type
        projection = {
            'ProjectionType': projection_type
        }
        if projection_type == "INCLUDE":
            if not non_key_attrs:
                self.signal_manager.message_signal.emit("Non-Key Attributes are required for INCLUDE projection type.")
                return
            projection['NonKeyAttributes'] = [attr.strip() for attr in non_key_attrs.split(",") if attr.strip()]
            if not projection['NonKeyAttributes']:
                self.signal_manager.message_signal.emit("Please enter at least one non-key attribute.")
                return

        self.show_loading()
        self.run_in_thread(
            self._create_index,
            table_name,
            index_name,
            attribute_definitions,
            key_schema,
            projection
        )

    def _create_index(self, table_name, index_name, attribute_definitions, key_schema, projection):
        try:
            response = self.dynamodb_client.update_table(
                TableName=table_name,
                AttributeDefinitions=attribute_definitions,
                GlobalSecondaryIndexUpdates=[
                    {
                        'Create': {
                            'IndexName': index_name,
                            'KeySchema': key_schema,
                            'Projection': projection,
                            'ProvisionedThroughput': {
                                'ReadCapacityUnits': 5,
                                'WriteCapacityUnits': 5
                            }
                        }
                    }
                ]
            )
            self.signal_manager.message_signal.emit(f"Index '{index_name}' creation initiated on table '{table_name}'.")
            self.run_in_thread(self.load_tables)  # Refresh tables list to show new index
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error creating index: {str(e)}")
        finally:
            self.hide_loading()

    def delete_index(self):
        table_entry = self.index_table_dropdown.currentText()
        index_entry = self.existing_indexes_dropdown.currentText()
        if not table_entry or not index_entry:
            self.signal_manager.message_signal.emit("Please select both a table and an index to delete.")
            return

        table_name = table_entry.split('(')[0].strip()
        index_name = index_entry.strip()

        confirm = QMessageBox.question(
            self, "Delete Index",
            f"Are you sure you want to delete the index '{index_name}' from table '{table_name}'?",
            QMessageBox.Yes | QMessageBox.No
        )

        if confirm == QMessageBox.Yes:
            self.show_loading()
            self.run_in_thread(self._delete_index, table_name, index_name)

    def _delete_index(self, table_name, index_name):
        try:
            response = self.dynamodb_client.update_table(
                TableName=table_name,
                GlobalSecondaryIndexUpdates=[
                    {
                        'Delete': {
                            'IndexName': index_name
                        }
                    }
                ]
            )
            self.signal_manager.message_signal.emit(f"Index '{index_name}' deletion initiated from table '{table_name}'.")
            self.run_in_thread(self.load_tables)  # Refresh tables list to remove deleted index
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error deleting index: {str(e)}")
        finally:
            self.hide_loading()

    # -------------------- Item Management Subtab Methods --------------------
    def setup_item_management_tab(self):
        layout = QFormLayout()

        # Select Table
        self.item_table_dropdown = QComboBox(self)
        self.item_table_dropdown.setPlaceholderText("Select a Table")
        layout.addRow(QLabel("Select Table:"), self.item_table_dropdown)
        self.populate_item_table_dropdown()
        self.item_table_dropdown.currentTextChanged.connect(self.display_primary_keys)

        # Primary Key Attributes
        self.primary_keys_label = QLabel("Primary Key Attributes:")
        layout.addRow(self.primary_keys_label)
        self.primary_keys_display = QLabel("", self)
        layout.addRow(self.primary_keys_display)

        # Item Attributes (JSON)
        self.item_attributes_input = QLineEdit(self)
        self.item_attributes_input.setPlaceholderText('Enter item attributes as JSON, e.g., {"Id": {"S": "123"}, "Name": {"S": "John Doe"}}')
        layout.addRow(QLabel("Item Attributes:"), self.item_attributes_input)

        # Execute Buttons
        self.add_item_button = QPushButton("Add Item", self)
        self.add_item_button.clicked.connect(self.add_item)
        layout.addRow(self.add_item_button)

        self.get_item_button = QPushButton("Get Item", self)
        self.get_item_button.clicked.connect(self.get_item)
        layout.addRow(self.get_item_button)

        self.update_item_button = QPushButton("Update Item", self)
        self.update_item_button.clicked.connect(self.update_item)
        layout.addRow(self.update_item_button)

        self.delete_item_button = QPushButton("Delete Item", self)
        self.delete_item_button.clicked.connect(self.delete_item)
        layout.addRow(self.delete_item_button)

        self.query_scan_button = QPushButton("Query/Scan Items", self)
        self.query_scan_button.clicked.connect(self.query_scan_items)
        layout.addRow(self.query_scan_button)

        self.item_management_tab.setLayout(layout)
        self.item_table_dropdown.currentTextChanged.connect(self.display_primary_keys)

    def populate_item_table_dropdown(self):
        tables = self.existing_tables_dropdown.currentText().split('\n') if self.existing_tables_dropdown.currentText() else []
        self.item_table_dropdown.clear()
        self.item_table_dropdown.addItems(tables)

    def display_primary_keys(self, table_entry):
        if not table_entry:
            self.primary_keys_display.setText("")
            return
        table_name = table_entry.split('(')[0].strip()
        try:
            response = self.dynamodb_client.describe_table(TableName=table_name)
            key_schema = response['Table']['KeySchema']
            keys = ', '.join([f"{key['AttributeName']} ({key['KeyType']})" for key in key_schema])
            self.primary_keys_display.setText(keys)
        except botocore.exceptions.ClientError as e:
            self.primary_keys_display.setText("Error fetching key schema.")
            self.signal_manager.message_signal.emit(f"Error fetching key schema: {str(e)}")

    def add_item(self):
        table_entry = self.item_table_dropdown.currentText()
        if not table_entry:
            self.signal_manager.message_signal.emit("Please select a table to add an item.")
            return

        # Extract Table Name
        table_name = table_entry.split('(')[0].strip()

        item_attributes = self.item_attributes_input.text().strip()
        if not item_attributes:
            self.signal_manager.message_signal.emit("Please enter item attributes.")
            return

        # Parse JSON
        try:
            item_attributes = json.loads(item_attributes)
        except json.JSONDecodeError:
            self.signal_manager.message_signal.emit("Item Attributes must be valid JSON.")
            return

        # Validate item attributes format
        if not isinstance(item_attributes, dict):
            self.signal_manager.message_signal.emit("Item Attributes must be a JSON object.")
            return

        self.show_loading()
        self.run_in_thread(
            self._add_item,
            table_name,
            item_attributes
        )

    def _add_item(self, table_name, item_attributes):
        try:
            response = self.dynamodb_client.put_item(
                TableName=table_name,
                Item=item_attributes
            )
            self.signal_manager.message_signal.emit(f"Item added to table '{table_name}' successfully.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error adding item: {str(e)}")
        finally:
            self.hide_loading()

    def get_item(self):
        table_entry = self.item_table_dropdown.currentText()
        if not table_entry:
            self.signal_manager.message_signal.emit("Please select a table to get an item.")
            return

        # Extract Table Name
        table_name = table_entry.split('(')[0].strip()

        # Prompt user for primary key(s)
        try:
            response = self.dynamodb_client.describe_table(TableName=table_name)
            key_schema = response['Table']['KeySchema']
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error describing table: {str(e)}")
            return

        key = {}
        for key_element in key_schema:
            attr_name = key_element['AttributeName']
            key_type = key_element['KeyType']
            value, ok = QInputDialog.getText(
                self, "Get Item", f"Enter value for {attr_name} ({key_type}):"
            )
            if not ok or not value:
                self.signal_manager.message_signal.emit("Primary key value is required.")
                return
            # For simplicity, assume all keys are of type String ('S')
            key[attr_name] = {'S': value}

        self.show_loading()
        self.run_in_thread(
            self._get_item,
            table_name,
            key
        )

    def _get_item(self, table_name, key):
        try:
            response = self.dynamodb_client.get_item(
                TableName=table_name,
                Key=key
            )
            item = response.get('Item', {})
            if not item:
                self.signal_manager.message_signal.emit("Item not found.")
                return
            item_info = json.dumps(item, indent=4)
            self.signal_manager.message_signal.emit(f"Item in table '{table_name}':\n{item_info}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error getting item: {str(e)}")
        finally:
            self.hide_loading()

    def update_item(self):
        table_entry = self.item_table_dropdown.currentText()
        if not table_entry:
            self.signal_manager.message_signal.emit("Please select a table to update an item.")
            return

        # Extract Table Name
        table_name = table_entry.split('(')[0].strip()

        # Prompt user for primary key(s)
        try:
            response = self.dynamodb_client.describe_table(TableName=table_name)
            key_schema = response['Table']['KeySchema']
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error describing table: {str(e)}")
            return

        key = {}
        for key_element in key_schema:
            attr_name = key_element['AttributeName']
            key_type = key_element['KeyType']
            value, ok = QInputDialog.getText(
                self, "Update Item", f"Enter value for {attr_name} ({key_type}):"
            )
            if not ok or not value:
                self.signal_manager.message_signal.emit("Primary key value is required.")
                return
            # For simplicity, assume all keys are of type String ('S')
            key[attr_name] = {'S': value}

        # Prompt for update expressions
        update_expression, ok = QInputDialog.getText(
            self, "Update Item", "Enter Update Expression (e.g., SET Age = :a):"
        )
        if not ok or not update_expression:
            self.signal_manager.message_signal.emit("Update Expression is required.")
            return

        # Prompt for Expression Attribute Values (JSON)
        expr_attr_values_input, ok = QInputDialog.getText(
            self, "Update Item", "Enter Expression Attribute Values as JSON (e.g., {\":a\": {\"N\": \"30\"}}):"
        )
        if not ok or not expr_attr_values_input:
            self.signal_manager.message_signal.emit("Expression Attribute Values are required.")
            return

        try:
            expr_attr_values = json.loads(expr_attr_values_input)
        except json.JSONDecodeError:
            self.signal_manager.message_signal.emit("Expression Attribute Values must be valid JSON.")
            return

        # Validate format
        if not isinstance(expr_attr_values, dict):
            self.signal_manager.message_signal.emit("Expression Attribute Values must be a JSON object.")
            return

        self.show_loading()
        self.run_in_thread(
            self._update_item,
            table_name,
            key,
            update_expression,
            expr_attr_values
        )

    def _update_item(self, table_name, key, update_expression, expr_attr_values):
        try:
            response = self.dynamodb_client.update_item(
                TableName=table_name,
                Key=key,
                UpdateExpression=update_expression,
                ExpressionAttributeValues=expr_attr_values,
                ReturnValues="UPDATED_NEW"
            )
            attributes = response.get('Attributes', {})
            attributes_info = json.dumps(attributes, indent=4)
            self.signal_manager.message_signal.emit(f"Item updated successfully. Updated attributes:\n{attributes_info}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error updating item: {str(e)}")
        finally:
            self.hide_loading()

    def delete_item(self):
        table_entry = self.item_table_dropdown.currentText()
        if not table_entry:
            self.signal_manager.message_signal.emit("Please select a table to delete an item.")
            return

        # Extract Table Name
        table_name = table_entry.split('(')[0].strip()

        # Prompt user for primary key(s)
        try:
            response = self.dynamodb_client.describe_table(TableName=table_name)
            key_schema = response['Table']['KeySchema']
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error describing table: {str(e)}")
            return

        key = {}
        for key_element in key_schema:
            attr_name = key_element['AttributeName']
            key_type = key_element['KeyType']
            value, ok = QInputDialog.getText(
                self, "Delete Item", f"Enter value for {attr_name} ({key_type}):"
            )
            if not ok or not value:
                self.signal_manager.message_signal.emit("Primary key value is required.")
                return
            # For simplicity, assume all keys are of type String ('S')
            key[attr_name] = {'S': value}

        self.show_loading()
        self.run_in_thread(
            self._delete_item,
            table_name,
            key
        )

    def _delete_item(self, table_name, key):
        try:
            response = self.dynamodb_client.delete_item(
                TableName=table_name,
                Key=key,
                ReturnValues="ALL_OLD"
            )
            old_item = response.get('Attributes', {})
            if not old_item:
                self.signal_manager.message_signal.emit("Item not found or already deleted.")
                return
            old_item_info = json.dumps(old_item, indent=4)
            self.signal_manager.message_signal.emit(f"Item deleted successfully. Previous attributes:\n{old_item_info}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error deleting item: {str(e)}")
        finally:
            self.hide_loading()

    def query_scan_items(self):
        table_entry = self.item_table_dropdown.currentText()
        if not table_entry:
            self.signal_manager.message_signal.emit("Please select a table to query/scan items.")
            return

        # Extract Table Name
        table_name = table_entry.split('(')[0].strip()

        # Prompt user for operation type
        operation, ok = QInputDialog.getItem(
            self, "Query/Scan Items", "Select operation:",
            ["Query", "Scan"], 0, False
        )
        if not ok or not operation:
            return

        filter_expression, ok = QInputDialog.getText(
            self, "Query/Scan Items", "Enter Filter Expression (optional):"
        )
        if not ok:
            return

        expr_attr_values = {}
        if filter_expression:
            expr_attr_values_input, ok = QInputDialog.getText(
                self, "Query/Scan Items", "Enter Expression Attribute Values as JSON (e.g., {\":val\": {\"S\": \"John\"}}):"
            )
            if not ok or not expr_attr_values_input:
                self.signal_manager.message_signal.emit("Expression Attribute Values are required for Filter Expression.")
                return
            try:
                expr_attr_values = json.loads(expr_attr_values_input)
            except json.JSONDecodeError:
                self.signal_manager.message_signal.emit("Expression Attribute Values must be valid JSON.")
                return

        # For Query, prompt for key condition expression
        key_condition_expression = ""
        if operation == "Query":
            key_condition_expression, ok = QInputDialog.getText(
                self, "Query Items", "Enter Key Condition Expression (e.g., \"Id = :id\"):"
            )
            if not ok or not key_condition_expression:
                self.signal_manager.message_signal.emit("Key Condition Expression is required for Query.")
                return

        self.show_loading()
        self.run_in_thread(
            self._query_scan_items,
            table_name,
            operation,
            key_condition_expression,
            filter_expression,
            expr_attr_values
        )

    def _query_scan_items(self, table_name, operation, key_condition_expression, filter_expression, expr_attr_values):
        try:
            if operation == "Query":
                response = self.dynamodb_client.query(
                    TableName=table_name,
                    KeyConditionExpression=key_condition_expression,
                    FilterExpression=filter_expression if filter_expression else None,
                    ExpressionAttributeValues=expr_attr_values if expr_attr_values else None
                )
                items = response.get('Items', [])
                if not items:
                    self.signal_manager.message_signal.emit("No items found matching the query.")
                    return
                items_info = json.dumps(items, indent=4)
                self.signal_manager.message_signal.emit(f"Query Results from '{table_name}':\n{items_info}")
            elif operation == "Scan":
                response = self.dynamodb_client.scan(
                    TableName=table_name,
                    FilterExpression=filter_expression if filter_expression else None,
                    ExpressionAttributeValues=expr_attr_values if expr_attr_values else None
                )
                items = response.get('Items', [])
                if not items:
                    self.signal_manager.message_signal.emit("No items found matching the scan criteria.")
                    return
                items_info = json.dumps(items, indent=4)
                self.signal_manager.message_signal.emit(f"Scan Results from '{table_name}':\n{items_info}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error performing {operation.lower()}: {str(e)}")
        finally:
            self.hide_loading()

    # -------------------- Index Management Subtab Methods --------------------
    # Implemented above in setup_index_management_tab and related methods

    # -------------------- Monitoring Subtab Methods --------------------
    def setup_monitoring_tab(self):
        layout = QFormLayout()

        # Select Table
        self.monitor_table_dropdown = QComboBox(self)
        self.monitor_table_dropdown.setPlaceholderText("Select a Table")
        layout.addRow(QLabel("Select Table:"), self.monitor_table_dropdown)
        self.populate_monitor_table_dropdown()
        self.monitor_table_dropdown.currentTextChanged.connect(self.load_monitoring_metrics)

        # Metrics Display Area
        self.metrics_display = QTextEdit(self)
        self.metrics_display.setReadOnly(True)
        layout.addRow(QLabel("Metrics:"), self.metrics_display)

        self.monitoring_tab.setLayout(layout)

    def populate_monitor_table_dropdown(self):
        tables = self.existing_tables_dropdown.currentText().split('\n') if self.existing_tables_dropdown.currentText() else []
        self.monitor_table_dropdown.clear()
        self.monitor_table_dropdown.addItems(tables)

    def load_monitoring_metrics(self, table_entry):
        if not table_entry:
            self.metrics_display.setText("")
            return
        table_name = table_entry.split('(')[0].strip()
        self.show_loading()
        self.run_in_thread(self._fetch_metrics, table_name)

    def _fetch_metrics(self, table_name):
        try:
            cloudwatch = self.current_session.client('cloudwatch')
            metrics = {}
            # Example: Retrieve ConsumedReadCapacityUnits and ConsumedWriteCapacityUnits
            for metric in ['ConsumedReadCapacityUnits', 'ConsumedWriteCapacityUnits']:
                response = cloudwatch.get_metric_statistics(
                    Namespace='AWS/DynamoDB',
                    MetricName=metric,
                    Dimensions=[
                        {
                            'Name': 'TableName',
                            'Value': table_name
                        },
                    ],
                    StartTime=datetime.utcnow() - timedelta(minutes=10),
                    EndTime=datetime.utcnow(),
                    Period=300,
                    Statistics=['Average']
                )
                datapoints = response.get('Datapoints', [])
                if datapoints:
                    average = sorted(datapoints, key=lambda x: x['Timestamp'])[-1]['Average']
                    metrics[metric] = average
                else:
                    metrics[metric] = 'No data'
            metrics_info = json.dumps(metrics, indent=4)
            self.signal_manager.message_signal.emit(f"Metrics for Table '{table_name}':\n{metrics_info}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error fetching metrics: {str(e)}")
        finally:
            self.hide_loading()

    # -------------------- Helper Validation Methods --------------------
    def validate_subnet_group(self, subnet_group):
        try:
            response = self.dynamodb_client.describe_subnet_group(SubnetGroupName=subnet_group)
            return True
        except self.dynamodb_client.exceptions.SubnetGroupNotFoundFault:
            return False
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error validating subnet group: {str(e)}")
            return False

    def validate_parameter_group(self, parameter_group, engine):
        try:
            response = self.dynamodb_client.describe_parameter_groups(ParameterGroupNames=[parameter_group])
            param_group = response['ParameterGroups'][0]
            return param_group['ParameterGroupFamily'].startswith(engine)
        except self.dynamodb_client.exceptions.ParameterGroupNotFoundFault:
            return False
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error validating parameter group: {str(e)}")
            return False

    def validate_security_groups(self, sg_ids):
        try:
            ec2_client = self.current_session.client('ec2')
            response = ec2_client.describe_security_groups(GroupIds=sg_ids)
            valid_sgs = [sg['GroupId'] for sg in response['SecurityGroups']]
            if len(valid_sgs) != len(sg_ids):
                invalid = set(sg_ids) - set(valid_sgs)
                self.signal_manager.message_signal.emit(f"Invalid security group IDs: {', '.join(invalid)}")
                return None
            return valid_sgs
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['InvalidGroup.NotFound', 'AccessDenied']:
                self.signal_manager.message_signal.emit(f"Error validating security groups: {str(e)}")
            else:
                self.signal_manager.message_signal.emit(f"Error validating security groups: {str(e)}")
            return None

    # -------------------- Extensibility Example: SSL Certificate Management --------------------
    # Future implementation can be added here to manage SSL certificates

