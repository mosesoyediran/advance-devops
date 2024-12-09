from concurrent.futures import ThreadPoolExecutor

import boto3
import botocore
from PyQt5.QtCore import Q_ARG, QMetaObject, QObject, Qt, pyqtSignal
from PyQt5.QtWidgets import (QComboBox, QFormLayout, QLabel, QLineEdit,
                             QMessageBox, QPushButton, QTabWidget, QTextEdit,
                             QVBoxLayout, QWidget)


class SignalManager(QObject):
    message_signal = pyqtSignal(str)
    dropdown_signal = pyqtSignal(list)
    clear_signal = pyqtSignal()


class RDSTab(QWidget):
    def __init__(self, session):
        super().__init__()
        self.session = session
        self.rds_client = session.client('rds')
        self.ec2_client = session.client('ec2')
        self.signal_manager = SignalManager()
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.initUI()
        self.connect_signals()

    def initUI(self):
        main_layout = QVBoxLayout()

        # Tab Widget to hold different RDS management tabs
        self.tab_widget = QTabWidget()

        # Create tabs for different sections
        self.tab_widget.addTab(self.create_instance_tab(), "Create Instance")
        self.tab_widget.addTab(self.modify_instance_tab(), "Modify Instance")
        self.tab_widget.addTab(self.start_stop_instance_tab(), "Start/Stop Instance")
        self.tab_widget.addTab(self.snapshot_management_tab(), "Manage Snapshots")
        self.tab_widget.addTab(self.delete_instance_tab(), "Delete Instance")
        self.tab_widget.addTab(self.list_instances_tab(), "List Instances")

        # Output Area
        self.output_area = QTextEdit(self)
        self.output_area.setReadOnly(True)

        # Add tabs and output area to the main layout
        main_layout.addWidget(self.tab_widget)
        main_layout.addWidget(QLabel("RDS Action Output:"))
        main_layout.addWidget(self.output_area)

        self.setLayout(main_layout)

        # Load options from AWS
        self.load_db_options()

    def connect_signals(self):
        self.signal_manager.message_signal.connect(self.show_message)
        self.signal_manager.clear_signal.connect(self.clear_output_area)

    def show_message(self, message):
        QMetaObject.invokeMethod(self.output_area, "append", Qt.QueuedConnection, Q_ARG(str, message))

    def clear_output_area(self):
        QMetaObject.invokeMethod(self.output_area, "clear", Qt.QueuedConnection)

    def list_instances_tab(self):
        list_section = QWidget()
        layout = QVBoxLayout()

        self.list_db_action_button = QPushButton("List All DB Instances", self)
        self.list_db_action_button.clicked.connect(self._list_all_instances)

        layout.addWidget(self.list_db_action_button)
        list_section.setLayout(layout)
        return list_section

    def create_instance_tab(self):
        create_tab = QWidget()
        layout = QFormLayout()

        self.db_identifier_input = QLineEdit(self)
        self.db_identifier_input.setPlaceholderText("Enter DB instance identifier")

        self.db_instance_class_dropdown = QComboBox(self)
        self.db_engine_dropdown = QComboBox(self)
        self.db_engine_version_dropdown = QComboBox(self)
        self.db_storage_type_dropdown = QComboBox(self)

        # Change allocated storage from dropdown to input box
        self.db_allocated_storage_input = QLineEdit(self)
        self.db_allocated_storage_input.setPlaceholderText("Enter Allocated Storage (GB)")

        self.db_port_input = QLineEdit(self)
        self.db_port_input.setPlaceholderText("DB Port (e.g., 3306)")

        self.db_publicly_accessible_dropdown = QComboBox(self)
        self.db_publicly_accessible_dropdown.addItems(["True", "False"])

        self.db_multi_az_dropdown = QComboBox(self)
        self.db_multi_az_dropdown.addItems(["True", "False"])

        self.db_backup_retention_input = QLineEdit(self)
        self.db_backup_retention_input.setPlaceholderText("Backup Retention Period (Days)")

        self.db_preferred_backup_window_input = QLineEdit(self)
        self.db_preferred_backup_window_input.setPlaceholderText("Preferred Backup Window")

        self.db_preferred_maintenance_window_input = QLineEdit(self)
        self.db_preferred_maintenance_window_input.setPlaceholderText("Preferred Maintenance Window")

        self.db_auto_minor_version_upgrade_dropdown = QComboBox(self)
        self.db_auto_minor_version_upgrade_dropdown.addItems(["True", "False"])

        self.db_username_input = QLineEdit(self)
        self.db_username_input.setPlaceholderText("Master Username")

        self.db_password_input = QLineEdit(self)
        self.db_password_input.setPlaceholderText("Master Password")
        self.db_password_input.setEchoMode(QLineEdit.Password)

        self.create_db_action_button = QPushButton("Create DB Instance", self)
        self.create_db_action_button.clicked.connect(self._create_db_instance)

        layout.addRow("DB Identifier", self.db_identifier_input)
        layout.addRow("Instance Class", self.db_instance_class_dropdown)
        layout.addRow("Engine", self.db_engine_dropdown)
        layout.addRow("Engine Version", self.db_engine_version_dropdown)
        layout.addRow("Storage Type", self.db_storage_type_dropdown)
        layout.addRow("Allocated Storage (GB)", self.db_allocated_storage_input)  # Input box instead of dropdown
        layout.addRow("Port", self.db_port_input)
        layout.addRow("Publicly Accessible", self.db_publicly_accessible_dropdown)
        layout.addRow("Multi-AZ", self.db_multi_az_dropdown)
        layout.addRow("Backup Retention (Days)", self.db_backup_retention_input)
        layout.addRow("Preferred Backup Window", self.db_preferred_backup_window_input)
        layout.addRow("Preferred Maintenance Window", self.db_preferred_maintenance_window_input)
        layout.addRow("Auto Minor Version Upgrade", self.db_auto_minor_version_upgrade_dropdown)
        layout.addRow("Master Username", self.db_username_input)
        layout.addRow("Master Password", self.db_password_input)
        layout.addWidget(self.create_db_action_button)

        create_tab.setLayout(layout)
        return create_tab

    def modify_instance_tab(self):
        modify_tab = QWidget()
        layout = QFormLayout()

        self.modify_db_identifier_input = QLineEdit(self)
        self.modify_db_identifier_input.setPlaceholderText("Enter DB instance identifier to modify")

        self.modify_db_instance_class_dropdown = QComboBox(self)

        self.modify_db_action_button = QPushButton("Modify DB Instance", self)
        self.modify_db_action_button.clicked.connect(self._modify_db_instance)

        layout.addRow("DB Identifier", self.modify_db_identifier_input)
        layout.addRow("New Instance Class", self.modify_db_instance_class_dropdown)
        layout.addWidget(self.modify_db_action_button)

        modify_tab.setLayout(layout)
        return modify_tab

    def start_stop_instance_tab(self):
        start_stop_tab = QWidget()
        layout = QFormLayout()

        self.start_stop_db_identifier_input = QLineEdit(self)
        self.start_stop_db_identifier_input.setPlaceholderText("Enter DB instance identifier")

        self.start_db_action_button = QPushButton("Start DB Instance", self)
        self.start_db_action_button.clicked.connect(self._start_db_instance)

        self.stop_db_action_button = QPushButton("Stop DB Instance", self)
        self.stop_db_action_button.clicked.connect(self._stop_db_instance)

        layout.addRow("DB Identifier", self.start_stop_db_identifier_input)
        layout.addWidget(self.start_db_action_button)
        layout.addWidget(self.stop_db_action_button)

        start_stop_tab.setLayout(layout)
        return start_stop_tab

    def snapshot_management_tab(self):
        snapshot_tab = QWidget()
        layout = QFormLayout()

        self.snapshot_db_identifier_input = QLineEdit(self)
        self.snapshot_db_identifier_input.setPlaceholderText("Enter DB instance identifier")

        self.create_snapshot_input = QLineEdit(self)
        self.create_snapshot_input.setPlaceholderText("Enter snapshot identifier")

        self.create_snapshot_action_button = QPushButton("Create Snapshot", self)
        self.create_snapshot_action_button.clicked.connect(self._create_snapshot)

        self.restore_db_identifier_input = QLineEdit(self)
        self.restore_db_identifier_input.setPlaceholderText("Enter DB identifier to restore")

        self.restore_snapshot_action_button = QPushButton("Restore Snapshot", self)
        self.restore_snapshot_action_button.clicked.connect(self._restore_snapshot)

        layout.addRow("DB Identifier", self.snapshot_db_identifier_input)
        layout.addRow("Snapshot Identifier", self.create_snapshot_input)
        layout.addWidget(self.create_snapshot_action_button)
        layout.addRow("Restore DB Identifier", self.restore_db_identifier_input)
        layout.addWidget(self.restore_snapshot_action_button)

        snapshot_tab.setLayout(layout)
        return snapshot_tab

    def delete_instance_tab(self):
        delete_tab = QWidget()
        layout = QFormLayout()

        self.delete_db_identifier_input = QLineEdit(self)
        self.delete_db_identifier_input.setPlaceholderText("Enter DB instance identifier")

        self.delete_db_action_button = QPushButton("Delete DB Instance", self)
        self.delete_db_action_button.clicked.connect(self._delete_db_instance)

        layout.addRow("DB Identifier", self.delete_db_identifier_input)
        layout.addWidget(self.delete_db_action_button)

        delete_tab.setLayout(layout)
        return delete_tab

    def _list_all_instances(self):
        self.executor.submit(self._run_list_all_instances)

    def _run_list_all_instances(self):
        try:
            self.signal_manager.message_signal.emit("Attempting to list all instances...")
            response = self.rds_client.describe_db_instances()
            instances = response.get('DBInstances', [])

            if instances:
                instance_details = []
                for instance in instances:
                    details = (
                        f"Identifier: {instance['DBInstanceIdentifier']}\n"
                        f"  Status: {instance['DBInstanceStatus']}\n"
                        f"  Engine: {instance['Engine']}\n"
                        f"  Engine Version: {instance['EngineVersion']}\n"
                        f"  Instance Class: {instance['DBInstanceClass']}\n"
                        f"  Allocated Storage: {instance['AllocatedStorage']} GB\n"
                        f"  Storage Type: {instance['StorageType']}\n"
                        f"  Endpoint: {instance.get('Endpoint', {}).get('Address', 'N/A')}:{instance.get('Endpoint', {}).get('Port', 'N/A')}\n"
                        f"  Publicly Accessible: {instance['PubliclyAccessible']}\n"
                        f"  Multi-AZ: {instance['MultiAZ']}\n"
                        f"  Backup Retention: {instance['BackupRetentionPeriod']} days\n"
                        f"  Preferred Backup Window: {instance['PreferredBackupWindow']}\n"
                        f"  Preferred Maintenance Window: {instance['PreferredMaintenanceWindow']}\n"
                    )
                    instance_details.append(details)
                self.signal_manager.message_signal.emit("\n\n".join(instance_details))
            else:
                self.signal_manager.message_signal.emit("No RDS instances found.")
        except botocore.exceptions.ClientError as e:
            error_message = f"Error listing RDS instances: {str(e)}"
            self.signal_manager.message_signal.emit(error_message)

    def _create_db_instance(self):
        self.executor.submit(self._run_create_db_instance)

    def _run_create_db_instance(self):
        try:
            db_identifier = self.db_identifier_input.text()
            db_instance_class = self.db_instance_class_dropdown.currentText()
            db_engine = self.db_engine_dropdown.currentText()
            db_engine_version = self.db_engine_version_dropdown.currentText()
            db_storage_type = self.db_storage_type_dropdown.currentText()

            # Validate and get the manually entered storage size
            if not self.db_allocated_storage_input.text().isdigit():
                raise ValueError("Allocated Storage must be a valid integer")
            db_allocated_storage = int(self.db_allocated_storage_input.text())

            # Validate DB Port
            if not self.db_port_input.text().isdigit():
                raise ValueError("DB Port must be a valid integer")
            db_port = int(self.db_port_input.text())

            publicly_accessible = self.db_publicly_accessible_dropdown.currentText() == "True"
            multi_az = self.db_multi_az_dropdown.currentText() == "True"

            # Validate Backup Retention Period
            if not self.db_backup_retention_input.text().isdigit():
                raise ValueError("Backup Retention Period must be a valid integer")
            backup_retention_period = int(self.db_backup_retention_input.text())

            preferred_backup_window = self.db_preferred_backup_window_input.text()
            preferred_maintenance_window = self.db_preferred_maintenance_window_input.text()
            auto_minor_version_upgrade = self.db_auto_minor_version_upgrade_dropdown.currentText() == "True"
            db_username = self.db_username_input.text()
            db_password = self.db_password_input.text()

            # Ensure required fields are filled out
            if not db_identifier or not db_username or not db_password:
                self.signal_manager.message_signal.emit("Error: DB Identifier, Master Username, and Master Password are required.")
                return

            self.rds_client.create_db_instance(
                DBInstanceIdentifier=db_identifier,
                DBInstanceClass=db_instance_class,
                Engine=db_engine,
                EngineVersion=db_engine_version,
                StorageType=db_storage_type,
                AllocatedStorage=db_allocated_storage,
                Port=db_port,
                PubliclyAccessible=publicly_accessible,
                MultiAZ=multi_az,
                BackupRetentionPeriod=backup_retention_period,
                PreferredBackupWindow=preferred_backup_window,
                PreferredMaintenanceWindow=preferred_maintenance_window,
                AutoMinorVersionUpgrade=auto_minor_version_upgrade,
                MasterUsername=db_username,
                MasterUserPassword=db_password
            )
            self.signal_manager.message_signal.emit(f"Creating RDS instance '{db_identifier}'. This may take a few minutes.")
        except ValueError as e:
            self.signal_manager.message_signal.emit(f"Error: Invalid input - {str(e)}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error creating RDS instance: {str(e)}")

    def _modify_db_instance(self):
        self.executor.submit(self._run_modify_db_instance)

    def _run_modify_db_instance(self):
        db_identifier = self.modify_db_identifier_input.text()
        db_instance_class = self.modify_db_instance_class_dropdown.currentText()

        if not db_identifier or not db_instance_class:
            self.signal_manager.message_signal.emit("Error: DB Identifier and New Instance Class are required.")
            return

        try:
            self.rds_client.modify_db_instance(
                DBInstanceIdentifier=db_identifier,
                DBInstanceClass=db_instance_class,
                ApplyImmediately=True
            )
            self.signal_manager.message_signal.emit(f"Modifying RDS instance '{db_identifier}'. This may take a few minutes.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error modifying RDS instance: {str(e)}")

    def _start_db_instance(self):
        self.executor.submit(self._run_start_db_instance)

    def _run_start_db_instance(self):
        db_identifier = self.start_stop_db_identifier_input.text()

        if not db_identifier:
            self.signal_manager.message_signal.emit("Error: DB Identifier is required to start an instance.")
            return

        try:
            self.rds_client.start_db_instance(DBInstanceIdentifier=db_identifier)
            self.signal_manager.message_signal.emit(f"Starting RDS instance '{db_identifier}'. This may take a few minutes.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error starting RDS instance: {str(e)}")

    def _stop_db_instance(self):
        self.executor.submit(self._run_stop_db_instance)

    def _run_stop_db_instance(self):
        db_identifier = self.start_stop_db_identifier_input.text()

        if not db_identifier:
            self.signal_manager.message_signal.emit("Error: DB Identifier is required to stop an instance.")
            return

        try:
            self.rds_client.stop_db_instance(DBInstanceIdentifier=db_identifier)
            self.signal_manager.message_signal.emit(f"Stopping RDS instance '{db_identifier}'. This may take a few minutes.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error stopping RDS instance: {str(e)}")

    def _create_snapshot(self):
        self.executor.submit(self._run_create_snapshot)

    def _run_create_snapshot(self):
        db_identifier = self.snapshot_db_identifier_input.text()
        snapshot_identifier = self.create_snapshot_input.text()

        if not db_identifier or not snapshot_identifier:
            self.signal_manager.message_signal.emit("Error: DB Identifier and Snapshot Identifier are required to create a snapshot.")
            return

        try:
            self.rds_client.create_db_snapshot(
                DBInstanceIdentifier=db_identifier,
                DBSnapshotIdentifier=snapshot_identifier
            )
            self.signal_manager.message_signal.emit(f"Creating snapshot '{snapshot_identifier}' for RDS instance '{db_identifier}'. This may take a few minutes.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error creating snapshot: {str(e)}")

    def _restore_snapshot(self):
        self.executor.submit(self._run_restore_snapshot)

    def _run_restore_snapshot(self):
        snapshot_identifier = self.create_snapshot_input.text()
        db_identifier = self.restore_db_identifier_input.text()

        if not db_identifier or not snapshot_identifier:
            self.signal_manager.message_signal.emit("Error: Snapshot Identifier and DB Identifier are required to restore a snapshot.")
            return

        try:
            self.rds_client.restore_db_instance_from_db_snapshot(
                DBInstanceIdentifier=db_identifier,
                DBSnapshotIdentifier=snapshot_identifier
            )
            self.signal_manager.message_signal.emit(f"Restoring RDS instance '{db_identifier}' from snapshot '{snapshot_identifier}'. This may take a few minutes.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error restoring snapshot: {str(e)}")

    def _delete_db_instance(self):
        self.executor.submit(self._run_delete_db_instance)

    def _run_delete_db_instance(self):
        db_identifier = self.delete_db_identifier_input.text()

        if not db_identifier:
            self.signal_manager.message_signal.emit("Error: DB Identifier is required for deletion.")
            return

        try:
            self.rds_client.delete_db_instance(
                DBInstanceIdentifier=db_identifier,
                SkipFinalSnapshot=True
            )
            self.signal_manager.message_signal.emit(f"Deleting RDS instance '{db_identifier}'. This may take a few minutes.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error deleting RDS instance: {str(e)}")

    def load_db_options(self):
        self.executor.submit(self.load_instance_classes_and_storage_types)
        self.executor.submit(self.load_db_engines)

    def load_instance_classes_and_storage_types(self):
        try:
            selected_engine = self.db_engine_dropdown.currentText()
            selected_engine_version = self.db_engine_version_dropdown.currentText()

            if not selected_engine or not selected_engine_version:
                return

            response = self.rds_client.describe_orderable_db_instance_options(
                Engine=selected_engine,
                EngineVersion=selected_engine_version
            )

            # Extract unique instance classes
            classes = sorted(set(option['DBInstanceClass'] for option in response['OrderableDBInstanceOptions']))
            self.db_instance_class_dropdown.clear()
            self.modify_db_instance_class_dropdown.clear()
            self.db_instance_class_dropdown.addItems(classes)
            self.modify_db_instance_class_dropdown.addItems(classes)

            # Extract unique storage types
            storage_types = sorted(set(option['StorageType'] for option in response['OrderableDBInstanceOptions']))
            self.db_storage_type_dropdown.clear()
            self.db_storage_type_dropdown.addItems(storage_types)

        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error loading instance classes or storage types: {str(e)}")

    def load_db_engines(self):
        try:
            paginator = self.rds_client.get_paginator('describe_db_engine_versions')
            page_iterator = paginator.paginate()
            engines = set()
            for page in page_iterator:
                for engine in page['DBEngineVersions']:
                    engines.add(engine['Engine'])
            self.db_engine_dropdown.clear()  # Clear any existing items
            self.db_engine_dropdown.addItems(sorted(engines))

            self.db_engine_dropdown.currentIndexChanged.connect(self.load_engine_versions)

            # Also trigger load of instance classes and storage types
            self.db_engine_dropdown.currentIndexChanged.connect(self.load_instance_classes_and_storage_types)
            self.db_engine_version_dropdown.currentIndexChanged.connect(self.load_instance_classes_and_storage_types)

        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error loading DB engines: {str(e)}")

    def load_engine_versions(self):
        self.executor.submit(self._run_load_engine_versions)

    def _run_load_engine_versions(self):
        selected_engine = self.db_engine_dropdown.currentText()
        self.db_engine_version_dropdown.clear()
        try:
            paginator = self.rds_client.get_paginator('describe_db_engine_versions')
            page_iterator = paginator.paginate(Engine=selected_engine)
            versions = set()
            for page in page_iterator:
                for engine in page['DBEngineVersions']:
                    versions.add(engine['EngineVersion'])
            self.db_engine_version_dropdown.addItems(sorted(versions))
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error loading engine versions: {str(e)}")

