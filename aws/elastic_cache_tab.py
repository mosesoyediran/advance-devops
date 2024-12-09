import json
import re
import sys
import threading

import boto3
import botocore
from botocore.exceptions import ClientError, ParamValidationError
from PyQt5.QtCore import Q_ARG, QMetaObject, QObject, Qt, pyqtSignal
from PyQt5.QtGui import QMovie
from PyQt5.QtWidgets import (QApplication, QComboBox, QFileDialog, QFormLayout,
                             QHBoxLayout, QInputDialog, QLabel, QLineEdit,
                             QMessageBox, QPushButton, QTabWidget, QTextEdit,
                             QVBoxLayout, QWidget)


class SignalManager(QObject):
    message_signal = pyqtSignal(str)
    dropdown_signal = pyqtSignal(list, str)  # Added 'dropdown_name' parameter
    clear_signal = pyqtSignal()


class ElastiCacheTab(QWidget):
    def __init__(self, session):
        super().__init__()
        self.current_session = session
        self.elasticache_client = session.client('elasticache')
        self.ec2_client = session.client('ec2')  # For validating VPCs, subnets, security groups
        self.signal_manager = SignalManager()
        self.initUI()
        self.connect_signals()
        self.load_clusters()

    def initUI(self):
        main_layout = QHBoxLayout()

        # Left Column: ElastiCache Management Section with Subtabs
        left_column = QVBoxLayout()

        # Refresh Button for Clusters
        self.refresh_button = QPushButton("Refresh Clusters", self)
        self.refresh_button.clicked.connect(self.refresh_clusters)
        left_column.addWidget(self.refresh_button)

        # Existing Clusters Dropdown (globally within ElastiCacheTab)
        self.existing_clusters_dropdown = QComboBox(self)
        self.existing_clusters_dropdown.setPlaceholderText("Select a Cluster")
        left_column.addWidget(QLabel("Existing Clusters:"))
        left_column.addWidget(self.existing_clusters_dropdown)

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
        self.elasticache_subtabs = QTabWidget()
        left_column.addWidget(self.elasticache_subtabs)

        # Cluster Management Subtab
        self.cluster_management_tab = QWidget()
        self.elasticache_subtabs.addTab(self.cluster_management_tab, "Cluster Management")
        self.setup_cluster_management_tab()

        # Replication Group Management Subtab (Redis Only)
        self.replication_group_management_tab = QWidget()
        self.elasticache_subtabs.addTab(self.replication_group_management_tab, "Replication Group Management")
        self.setup_replication_group_management_tab()

        # Parameter Group Management Subtab
        self.parameter_group_management_tab = QWidget()
        self.elasticache_subtabs.addTab(self.parameter_group_management_tab, "Parameter Group Management")
        self.setup_parameter_group_management_tab()

        # Snapshot Management Subtab
        self.snapshot_management_tab = QWidget()
        self.elasticache_subtabs.addTab(self.snapshot_management_tab, "Snapshot Management")
        self.setup_snapshot_management_tab()

        # Monitoring and Events Subtab
        self.monitoring_events_tab = QWidget()
        self.elasticache_subtabs.addTab(self.monitoring_events_tab, "Monitoring and Events")
        self.setup_monitoring_events_tab()

        # Add stretch to push elements to the top
        left_column.addStretch()

        # Right Column: Output Area
        right_column = QVBoxLayout()

        self.output_area = QTextEdit(self)
        self.output_area.setReadOnly(True)

        right_column.addWidget(QLabel("ElastiCache Action Output:"))
        right_column.addWidget(self.output_area)

        # Add columns to the main layout with specific stretch factors
        main_layout.addLayout(left_column, 2)
        main_layout.addLayout(right_column, 3)

        self.setLayout(main_layout)

    def connect_signals(self):
        self.signal_manager.message_signal.connect(self.show_message)
        self.signal_manager.dropdown_signal.connect(self.populate_clusters_dropdown)
        self.signal_manager.clear_signal.connect(self.clear_output_area)

    def run_in_thread(self, target, *args, **kwargs):
        thread = threading.Thread(target=target, args=args, kwargs=kwargs)
        thread.start()

    def refresh_clusters(self):
        self.show_loading()
        self.run_in_thread(self.load_clusters)
        self.signal_manager.message_signal.emit("Refreshing clusters...")

    def load_clusters(self):
        try:
            clusters = []
            paginator = self.elasticache_client.get_paginator('describe_cache_clusters')
            for page in paginator.paginate(MaxRecords=100):
                for cluster in page['CacheClusters']:
                    cluster_id = cluster['CacheClusterId']
                    cluster_status = cluster['CacheClusterStatus']
                    clusters.append(f"{cluster_id} (Status: {cluster_status})")
            self.signal_manager.dropdown_signal.emit(clusters, 'clusters')  # Pass 'clusters' as dropdown_name
            self.signal_manager.message_signal.emit("Clusters loaded successfully.")
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['AccessDenied', 'UnauthorizedOperation']:
                self.signal_manager.message_signal.emit("Permission denied. Please ensure your AWS credentials have the necessary permissions.")
            else:
                self.signal_manager.message_signal.emit(f"Error loading clusters: {str(e)}")
        finally:
            self.hide_loading()

    def populate_clusters_dropdown(self, items, dropdown_name):
        if dropdown_name == 'clusters':
            self.existing_clusters_dropdown.clear()
            self.existing_clusters_dropdown.addItems(items)
            self.populate_listener_dropdown()
        elif dropdown_name == 'replication_groups':
            self.existing_replication_groups_dropdown.clear()
            self.existing_replication_groups_dropdown.addItems(items)
        elif dropdown_name == 'parameter_groups':
            self.existing_parameter_groups_dropdown.clear()
            self.existing_parameter_groups_dropdown.addItems(items)
            
    def populate_listener_dropdown(self):
        pass

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

    def show_loading(self):
        self.loading_label.setVisible(True)
        self.loading_movie.start()
        self.status_label.setText("Operation in progress...")

    def hide_loading(self):
        self.loading_movie.stop()
        self.loading_label.setVisible(False)
        self.status_label.setText("")

    # -------------------- Cluster Management Subtab --------------------
    def setup_cluster_management_tab(self):
        layout = QFormLayout()

        # Cluster ID
        self.cluster_id_input = QLineEdit(self)
        self.cluster_id_input.setPlaceholderText("Enter cluster ID")
        layout.addRow(QLabel("Cluster ID:"), self.cluster_id_input)

        # Node Type
        self.node_type_dropdown = QComboBox(self)
        self.node_type_dropdown.addItems([
            "cache.t2.micro", "cache.t2.small", "cache.t2.medium",
            "cache.m4.large", "cache.m4.xlarge", "cache.m4.2xlarge",
            "cache.m5.large", "cache.m5.xlarge", "cache.m5.2xlarge",
            # Add more as needed
        ])
        layout.addRow(QLabel("Node Type:"), self.node_type_dropdown)

        # Engine
        self.engine_dropdown = QComboBox(self)
        self.engine_dropdown.addItems(["redis", "memcached"])
        self.engine_dropdown.currentTextChanged.connect(self.update_engine_specific_fields)
        layout.addRow(QLabel("Engine:"), self.engine_dropdown)

        # Engine Version
        self.engine_version_input = QLineEdit(self)
        self.engine_version_input.setPlaceholderText("Enter engine version (e.g., 5.0.6)")
        layout.addRow(QLabel("Engine Version:"), self.engine_version_input)

        # Number of Nodes
        self.num_nodes_input = QLineEdit(self)
        self.num_nodes_input.setPlaceholderText("Enter number of nodes")
        layout.addRow(QLabel("Number of Nodes:"), self.num_nodes_input)

        # VPC Security Groups
        self.cluster_security_groups_input = QLineEdit(self)
        self.cluster_security_groups_input.setPlaceholderText("Enter security group IDs separated by commas")
        layout.addRow(QLabel("Security Groups:"), self.cluster_security_groups_input)

        # Subnet Group
        self.cluster_subnet_group_input = QLineEdit(self)
        self.cluster_subnet_group_input.setPlaceholderText("Enter subnet group name")
        layout.addRow(QLabel("Subnet Group:"), self.cluster_subnet_group_input)

        # Parameter Group
        self.cluster_parameter_group_input = QLineEdit(self)
        self.cluster_parameter_group_input.setPlaceholderText("Enter parameter group name")
        layout.addRow(QLabel("Parameter Group:"), self.cluster_parameter_group_input)

        # Execute Buttons
        self.create_cluster_button = QPushButton("Create Cluster", self)
        self.create_cluster_button.clicked.connect(self.create_cluster)
        layout.addRow(self.create_cluster_button)

        self.delete_cluster_button = QPushButton("Delete Cluster", self)
        self.delete_cluster_button.clicked.connect(self.delete_cluster)
        layout.addRow(self.delete_cluster_button)

        self.cluster_management_tab.setLayout(layout)

    def update_engine_specific_fields(self, engine):
        if engine.lower() == "redis":
            self.cluster_parameter_group_input.setPlaceholderText("Enter Redis parameter group name")
        elif engine.lower() == "memcached":
            self.cluster_parameter_group_input.setPlaceholderText("Enter Memcached parameter group name")
        else:
            self.cluster_parameter_group_input.setPlaceholderText("Enter parameter group name")

    def create_cluster(self):
        cluster_id = self.cluster_id_input.text().strip()
        node_type = self.node_type_dropdown.currentText()
        engine = self.engine_dropdown.currentText().strip().lower()
        engine_version = self.engine_version_input.text().strip()
        num_nodes = self.num_nodes_input.text().strip()
        security_groups = [sg.strip() for sg in self.cluster_security_groups_input.text().split(",") if sg.strip()]
        subnet_group = self.cluster_subnet_group_input.text().strip()
        parameter_group = self.cluster_parameter_group_input.text().strip()

        # Validation: All fields must be filled
        if not all([cluster_id, node_type, engine, engine_version, num_nodes, security_groups, subnet_group, parameter_group]):
            self.signal_manager.message_signal.emit("Please fill all fields to create a cluster.")
            return

        # Validate cluster ID format
        if not self.is_valid_cluster_id(cluster_id):
            self.signal_manager.message_signal.emit("Invalid Cluster ID format. Must be 20 characters or less, consisting of letters, numbers, and hyphens.")
            return

        # Validate number of nodes
        if not num_nodes.isdigit() or int(num_nodes) < 1:
            self.signal_manager.message_signal.emit("Number of nodes must be a positive integer.")
            return

        # Validate Engine
        if engine not in ['redis', 'memcached']:
            self.signal_manager.message_signal.emit("Engine must be either 'redis' or 'memcached'.")
            return

        # Validate Cluster ID uniqueness
        if self.is_cluster_id_exists(cluster_id):
            self.signal_manager.message_signal.emit(f"Cluster ID '{cluster_id}' already exists. Please choose a different ID.")
            return

        # Validate Subnet Group exists
        if not self.validate_subnet_group(subnet_group):
            self.signal_manager.message_signal.emit(f"Subnet Group '{subnet_group}' does not exist.")
            return

        # Validate Parameter Group exists
        if not self.validate_parameter_group(parameter_group, engine):
            self.signal_manager.message_signal.emit(f"Parameter Group '{parameter_group}' does not exist or does not match the engine '{engine}'.")
            return

        # Validate Security Groups
        valid_security_groups = self.validate_security_groups(security_groups)
        if not valid_security_groups:
            # Error message already sent in validate_security_groups
            return

        self.show_loading()
        self.run_in_thread(
            self._create_cluster,
            cluster_id,
            node_type,
            engine,
            engine_version,
            int(num_nodes),
            valid_security_groups,
            subnet_group,
            parameter_group
        )

    def _create_cluster(self, cluster_id, node_type, engine, engine_version, num_nodes, security_groups, subnet_group, parameter_group):
        try:
            if engine == "redis":
                # For Redis, create a replication group
                response = self.elasticache_client.create_replication_group(
                    ReplicationGroupId=cluster_id,
                    ReplicationGroupDescription=f"Replication group for {cluster_id}",
                    Engine=engine,
                    EngineVersion=engine_version,
                    CacheNodeType=node_type,
                    NumCacheClusters=1,
                    SecurityGroupIds=security_groups,
                    CacheSubnetGroupName=subnet_group,
                    CacheParameterGroupName=parameter_group,
                    AutomaticFailoverEnabled=True if num_nodes > 1 else False,
                    MultiAZEnabled=True if num_nodes > 1 else False,
                )
            else:
                # For Memcached, create a cache cluster
                response = self.elasticache_client.create_cache_cluster(
                    CacheClusterId=cluster_id,
                    ReplicationGroupId=None,
                    CacheNodeType=node_type,
                    Engine=engine,
                    EngineVersion=engine_version,
                    NumCacheNodes=int(num_nodes),
                    SecurityGroupIds=security_groups,
                    CacheSubnetGroupName=subnet_group,
                    CacheParameterGroupName=parameter_group,
                    AZMode='single-az',
                )
            self.signal_manager.message_signal.emit(f"Cluster '{cluster_id}' creation initiated successfully.")
            self.run_in_thread(self.load_clusters)  # Refresh clusters list
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['ReplicationGroupAlreadyExistsFault', 'CacheClusterAlreadyExists', 'AccessDenied', 'UnauthorizedOperation']:
                if error_code in ['ReplicationGroupAlreadyExistsFault', 'CacheClusterAlreadyExists']:
                    self.signal_manager.message_signal.emit(f"Cluster ID '{cluster_id}' already exists. Please choose a different ID.")
                else:
                    self.signal_manager.message_signal.emit("Permission denied. Please ensure your AWS credentials have the necessary permissions.")
            else:
                self.signal_manager.message_signal.emit(f"Error creating cluster: {str(e)}")
        finally:
            self.hide_loading()

    def delete_cluster(self):
        selected_cluster = self.existing_clusters_dropdown.currentText()
        if not selected_cluster:
            self.signal_manager.message_signal.emit("Please select a cluster to delete.")
            return

        # Extract Cluster ID from the selected item
        cluster_id = selected_cluster.split('(')[0].strip()

        confirm = QMessageBox.question(
            self, "Delete Cluster",
            f"Are you sure you want to delete the cluster '{cluster_id}'?",
            QMessageBox.Yes | QMessageBox.No
        )

        if confirm == QMessageBox.Yes:
            self.show_loading()
            self.run_in_thread(self._delete_cluster, cluster_id)

    def _delete_cluster(self, cluster_id):
        try:
            # Determine if the cluster is part of a replication group
            response = self.elasticache_client.describe_replication_groups(ReplicationGroupId=cluster_id)
            if response['ReplicationGroups']:
                # It's a replication group
                self.elasticache_client.delete_replication_group(
                    ReplicationGroupId=cluster_id,
                    RetainPrimaryCluster=False
                )
                self.signal_manager.message_signal.emit(f"Replication Group '{cluster_id}' deletion initiated.")
            else:
                # It's a standalone cache cluster
                self.elasticache_client.delete_cache_cluster(CacheClusterId=cluster_id)
                self.signal_manager.message_signal.emit(f"Cache Cluster '{cluster_id}' deletion initiated.")
            self.run_in_thread(self.load_clusters)  # Refresh clusters list
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['ReplicationGroupNotFoundFault', 'CacheClusterNotFound', 'AccessDenied', 'UnauthorizedOperation']:
                if error_code in ['ReplicationGroupNotFoundFault', 'CacheClusterNotFound']:
                    self.signal_manager.message_signal.emit(f"Cluster ID '{cluster_id}' not found.")
                else:
                    self.signal_manager.message_signal.emit("Permission denied. Please ensure your AWS credentials have the necessary permissions.")
            else:
                self.signal_manager.message_signal.emit(f"Error deleting cluster: {str(e)}")
        finally:
            self.hide_loading()

    def is_cluster_id_exists(self, cluster_id):
        try:
            self.elasticache_client.describe_cache_clusters(CacheClusterId=cluster_id, ShowCacheClusters=True)
            return True
        except self.elasticache_client.exceptions.CacheClusterNotFoundFault:
            return False
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error checking cluster existence: {str(e)}")
            return False

    def is_valid_cluster_id(self, cluster_id):
        """
        Validate the cluster ID format: 20 characters or less, consisting of letters, numbers, and hyphens.
        """
        return bool(re.match(r'^[a-zA-Z0-9\-]{1,20}$', cluster_id))

    def validate_subnet_group(self, subnet_group):
        try:
            response = self.elasticache_client.describe_cache_subnet_groups(CacheSubnetGroupName=subnet_group)
            return True
        except self.elasticache_client.exceptions.CacheSubnetGroupNotFoundFault:
            return False
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error validating subnet group: {str(e)}")
            return False

    def validate_parameter_group(self, parameter_group, engine):
        try:
            response = self.elasticache_client.describe_cache_parameter_groups(CacheParameterGroupNames=[parameter_group])
            if not response['CacheParameterGroups']:
                return False
            # Optionally, verify that the parameter group engine matches the cluster engine
            # This requires fetching the parameter group details
            param_group = response['CacheParameterGroups'][0]
            return param_group['CacheParameterGroupFamily'].startswith(engine)
        except self.elasticache_client.exceptions.CacheParameterGroupNotFoundFault:
            return False
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error validating parameter group: {str(e)}")
            return False

    def validate_security_groups(self, sg_ids):
        try:
            response = self.ec2_client.describe_security_groups(GroupIds=sg_ids)
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

    # -------------------- Replication Group Management Subtab --------------------
    def setup_replication_group_management_tab(self):
        layout = QFormLayout()

        # Replication Group ID
        self.replication_group_id_input = QLineEdit(self)
        self.replication_group_id_input.setPlaceholderText("Enter replication group ID")
        layout.addRow(QLabel("Replication Group ID:"), self.replication_group_id_input)

        # Description
        self.replication_group_description_input = QLineEdit(self)
        self.replication_group_description_input.setPlaceholderText("Enter description")
        layout.addRow(QLabel("Description:"), self.replication_group_description_input)

        # Primary Cluster ID
        self.primary_cluster_id_input = QLineEdit(self)
        self.primary_cluster_id_input.setPlaceholderText("Enter primary cluster ID")
        layout.addRow(QLabel("Primary Cluster ID:"), self.primary_cluster_id_input)

        # Node Type
        self.replication_node_type_dropdown = QComboBox(self)
        self.replication_node_type_dropdown.addItems([
            "cache.t2.micro", "cache.t2.small", "cache.t2.medium",
            "cache.m4.large", "cache.m4.xlarge", "cache.m4.2xlarge",
            "cache.m5.large", "cache.m5.xlarge", "cache.m5.2xlarge",
            # Add more as needed
        ])
        layout.addRow(QLabel("Node Type:"), self.replication_node_type_dropdown)

        # Number of Replicas
        self.num_replicas_input = QLineEdit(self)
        self.num_replicas_input.setPlaceholderText("Enter number of replicas")
        layout.addRow(QLabel("Number of Replicas:"), self.num_replicas_input)

        # Engine Version
        self.replication_engine_version_input = QLineEdit(self)
        self.replication_engine_version_input.setPlaceholderText("Enter engine version (e.g., 5.0.6)")
        layout.addRow(QLabel("Engine Version:"), self.replication_engine_version_input)

        # VPC Security Groups
        self.replication_security_groups_input = QLineEdit(self)
        self.replication_security_groups_input.setPlaceholderText("Enter security group IDs separated by commas")
        layout.addRow(QLabel("Security Groups:"), self.replication_security_groups_input)

        # Subnet Group
        self.replication_subnet_group_input = QLineEdit(self)
        self.replication_subnet_group_input.setPlaceholderText("Enter subnet group name")
        layout.addRow(QLabel("Subnet Group:"), self.replication_subnet_group_input)

        # Parameter Group
        self.replication_parameter_group_input = QLineEdit(self)
        self.replication_parameter_group_input.setPlaceholderText("Enter parameter group name")
        layout.addRow(QLabel("Parameter Group:"), self.replication_parameter_group_input)

        # Execute Buttons
        self.create_replication_group_button = QPushButton("Create Replication Group", self)
        self.create_replication_group_button.clicked.connect(self.create_replication_group)
        layout.addRow(self.create_replication_group_button)

        self.delete_replication_group_button = QPushButton("Delete Replication Group", self)
        self.delete_replication_group_button.clicked.connect(self.delete_replication_group)
        layout.addRow(self.delete_replication_group_button)

        self.replication_group_management_tab.setLayout(layout)

    def create_replication_group(self):
        rg_id = self.replication_group_id_input.text().strip()
        description = self.replication_group_description_input.text().strip()
        primary_cluster_id = self.primary_cluster_id_input.text().strip()
        node_type = self.replication_node_type_dropdown.currentText()
        num_replicas = self.num_replicas_input.text().strip()
        engine_version = self.replication_engine_version_input.text().strip()
        security_groups = [sg.strip() for sg in self.replication_security_groups_input.text().split(",") if sg.strip()]
        subnet_group = self.replication_subnet_group_input.text().strip()
        parameter_group = self.replication_parameter_group_input.text().strip()

        # Validation: All fields must be filled
        if not all([rg_id, description, primary_cluster_id, node_type, num_replicas, engine_version, security_groups, subnet_group, parameter_group]):
            self.signal_manager.message_signal.emit("Please fill all fields to create a replication group.")
            return

        # Validate Replication Group ID format
        if not self.is_valid_replication_group_id(rg_id):
            self.signal_manager.message_signal.emit("Invalid Replication Group ID format. Must be 20 characters or less, consisting of letters, numbers, and hyphens.")
            return

        # Validate number of replicas
        if not num_replicas.isdigit() or int(num_replicas) < 0:
            self.signal_manager.message_signal.emit("Number of replicas must be a non-negative integer.")
            return

        # Validate Replication Group ID uniqueness
        if self.is_replication_group_id_exists(rg_id):
            self.signal_manager.message_signal.emit(f"Replication Group ID '{rg_id}' already exists. Please choose a different ID.")
            return

        # Validate Primary Cluster ID exists
        if not self.is_cluster_id_exists(primary_cluster_id):
            self.signal_manager.message_signal.emit(f"Primary Cluster ID '{primary_cluster_id}' does not exist.")
            return

        # Validate Subnet Group exists
        if not self.validate_subnet_group(subnet_group):
            self.signal_manager.message_signal.emit(f"Subnet Group '{subnet_group}' does not exist.")
            return

        # Validate Parameter Group exists
        if not self.validate_parameter_group(parameter_group, engine="redis"):
            self.signal_manager.message_signal.emit(f"Parameter Group '{parameter_group}' does not exist or does not match the engine 'redis'.")
            return

        # Validate Security Groups
        valid_security_groups = self.validate_security_groups(security_groups)
        if not valid_security_groups:
            # Error message already sent in validate_security_groups
            return

        self.show_loading()
        self.run_in_thread(
            self._create_replication_group,
            rg_id,
            description,
            primary_cluster_id,
            node_type,
            int(num_replicas),
            engine_version,
            valid_security_groups,
            subnet_group,
            parameter_group
        )

    def _create_replication_group(self, rg_id, description, primary_cluster_id, node_type, num_replicas, engine_version, security_groups, subnet_group, parameter_group):
        try:
            response = self.elasticache_client.create_replication_group(
                ReplicationGroupId=rg_id,
                ReplicationGroupDescription=description,
                PrimaryClusterId=primary_cluster_id,
                CacheNodeType=node_type,
                AutomaticFailoverEnabled=True if num_replicas > 0 else False,
                NumCacheClusters=1,
                NumNodeGroups=1,
                ReplicasPerNodeGroup=num_replicas,
                EngineVersion=engine_version,
                CacheParameterGroupName=parameter_group,
                CacheSubnetGroupName=subnet_group,
                SecurityGroupIds=security_groups,
            )
            self.signal_manager.message_signal.emit(f"Replication Group '{rg_id}' creation initiated successfully.")
            self.run_in_thread(self.load_clusters)  # Refresh clusters list
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['ReplicationGroupAlreadyExistsFault', 'AccessDenied', 'UnauthorizedOperation']:
                if error_code == 'ReplicationGroupAlreadyExistsFault':
                    self.signal_manager.message_signal.emit(f"Replication Group ID '{rg_id}' already exists. Please choose a different ID.")
                else:
                    self.signal_manager.message_signal.emit("Permission denied. Please ensure your AWS credentials have the necessary permissions.")
            else:
                self.signal_manager.message_signal.emit(f"Error creating replication group: {str(e)}")
        finally:
            self.hide_loading()

    def delete_replication_group(self):
        rg_id, ok = QInputDialog.getText(
            self, "Delete Replication Group", "Enter the Replication Group ID to delete:"
        )
        if ok and rg_id:
            # Validate Replication Group ID format
            if not self.is_valid_replication_group_id(rg_id):
                self.signal_manager.message_signal.emit("Invalid Replication Group ID format.")
                return

            # Validate Replication Group ID exists
            if not self.is_replication_group_id_exists(rg_id):
                self.signal_manager.message_signal.emit(f"Replication Group ID '{rg_id}' does not exist.")
                return

            confirm = QMessageBox.question(
                self, "Delete Replication Group",
                f"Are you sure you want to delete the replication group '{rg_id}'?",
                QMessageBox.Yes | QMessageBox.No
            )

            if confirm == QMessageBox.Yes:
                self.show_loading()
                self.run_in_thread(self._delete_replication_group, rg_id)

    def _delete_replication_group(self, rg_id):
        try:
            self.elasticache_client.delete_replication_group(
                ReplicationGroupId=rg_id,
                RetainPrimaryCluster=False
            )
            self.signal_manager.message_signal.emit(f"Replication Group '{rg_id}' deletion initiated.")
            self.run_in_thread(self.load_clusters)  # Refresh clusters list
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['ReplicationGroupNotFoundFault', 'AccessDenied', 'UnauthorizedOperation']:
                if error_code == 'ReplicationGroupNotFoundFault':
                    self.signal_manager.message_signal.emit(f"Replication Group ID '{rg_id}' not found.")
                else:
                    self.signal_manager.message_signal.emit("Permission denied. Please ensure your AWS credentials have the necessary permissions.")
            else:
                self.signal_manager.message_signal.emit(f"Error deleting replication group: {str(e)}")
        finally:
            self.hide_loading()

    def is_replication_group_id_exists(self, rg_id):
        try:
            self.elasticache_client.describe_replication_groups(ReplicationGroupId=rg_id)
            return True
        except self.elasticache_client.exceptions.ReplicationGroupNotFoundFault:
            return False
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error checking replication group existence: {str(e)}")
            return False

    def is_valid_replication_group_id(self, rg_id):
        """
        Validate the replication group ID format: 20 characters or less, consisting of letters, numbers, and hyphens.
        """
        return bool(re.match(r'^[a-zA-Z0-9\-]{1,20}$', rg_id))

    # -------------------- Parameter Group Management Subtab --------------------
    def setup_parameter_group_management_tab(self):
        layout = QFormLayout()

        # Parameter Group Name
        self.param_group_name_input = QLineEdit(self)
        self.param_group_name_input.setPlaceholderText("Enter parameter group name")
        layout.addRow(QLabel("Parameter Group Name:"), self.param_group_name_input)

        # Description
        self.param_group_description_input = QLineEdit(self)
        self.param_group_description_input.setPlaceholderText("Enter description")
        layout.addRow(QLabel("Description:"), self.param_group_description_input)

        # Engine
        self.param_group_engine_dropdown = QComboBox(self)
        self.param_group_engine_dropdown.addItems(["redis", "memcached"])
        layout.addRow(QLabel("Engine:"), self.param_group_engine_dropdown)

        # Execute Buttons
        self.create_param_group_button = QPushButton("Create Parameter Group", self)
        self.create_param_group_button.clicked.connect(self.create_parameter_group)
        layout.addRow(self.create_param_group_button)

        self.delete_param_group_button = QPushButton("Delete Parameter Group", self)
        self.delete_param_group_button.clicked.connect(self.delete_parameter_group)
        layout.addRow(self.delete_param_group_button)

        self.parameter_group_management_tab.setLayout(layout)

    def create_parameter_group(self):
        param_group_name = self.param_group_name_input.text().strip()
        description = self.param_group_description_input.text().strip()
        engine = self.param_group_engine_dropdown.currentText().strip().lower()

        # Validation: All fields must be filled
        if not all([param_group_name, description, engine]):
            self.signal_manager.message_signal.emit("Please fill all fields to create a parameter group.")
            return

        # Validate Parameter Group Name format
        if not self.is_valid_parameter_group_name(param_group_name):
            self.signal_manager.message_signal.emit("Invalid Parameter Group Name format. Must be 20 characters or less, consisting of letters, numbers, and hyphens.")
            return

        # Validate Engine
        if engine not in ['redis', 'memcached']:
            self.signal_manager.message_signal.emit("Engine must be either 'redis' or 'memcached'.")
            return

        # Validate Parameter Group Name uniqueness
        if self.is_parameter_group_name_exists(param_group_name):
            self.signal_manager.message_signal.emit(f"Parameter Group Name '{param_group_name}' already exists. Please choose a different name.")
            return

        self.show_loading()
        self.run_in_thread(
            self._create_parameter_group,
            param_group_name,
            description,
            engine
        )

    def _create_parameter_group(self, param_group_name, description, engine):
        try:
            response = self.elasticache_client.create_cache_parameter_group(
                CacheParameterGroupName=param_group_name,
                CacheParameterGroupFamily=f"{engine}5.0",  # Adjust based on engine version
                Description=description
            )
            self.signal_manager.message_signal.emit(f"Parameter Group '{param_group_name}' created successfully.")
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['CacheParameterGroupAlreadyExists', 'AccessDenied', 'UnauthorizedOperation']:
                if error_code == 'CacheParameterGroupAlreadyExists':
                    self.signal_manager.message_signal.emit(f"Parameter Group '{param_group_name}' already exists. Please choose a different name.")
                else:
                    self.signal_manager.message_signal.emit("Permission denied. Please ensure your AWS credentials have the necessary permissions.")
            else:
                self.signal_manager.message_signal.emit(f"Error creating parameter group: {str(e)}")
        finally:
            self.hide_loading()

    def delete_parameter_group(self):
        param_group_name, ok = QInputDialog.getText(
            self, "Delete Parameter Group", "Enter the Parameter Group Name to delete:"
        )
        if ok and param_group_name:
            # Validate Parameter Group Name format
            if not self.is_valid_parameter_group_name(param_group_name):
                self.signal_manager.message_signal.emit("Invalid Parameter Group Name format.")
                return

            # Validate Parameter Group exists
            if not self.is_parameter_group_name_exists(param_group_name):
                self.signal_manager.message_signal.emit(f"Parameter Group '{param_group_name}' does not exist.")
                return

            confirm = QMessageBox.question(
                self, "Delete Parameter Group",
                f"Are you sure you want to delete the parameter group '{param_group_name}'?",
                QMessageBox.Yes | QMessageBox.No
            )

            if confirm == QMessageBox.Yes:
                self.show_loading()
                self.run_in_thread(self._delete_parameter_group, param_group_name)

    def _delete_parameter_group(self, param_group_name):
        try:
            self.elasticache_client.delete_cache_parameter_group(CacheParameterGroupName=param_group_name)
            self.signal_manager.message_signal.emit(f"Parameter Group '{param_group_name}' deletion initiated.")
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['CacheParameterGroupNotFound', 'CacheParameterGroupInUse', 'AccessDenied', 'UnauthorizedOperation']:
                if error_code == 'CacheParameterGroupNotFound':
                    self.signal_manager.message_signal.emit(f"Parameter Group '{param_group_name}' not found.")
                elif error_code == 'CacheParameterGroupInUse':
                    self.signal_manager.message_signal.emit(f"Parameter Group '{param_group_name}' is in use and cannot be deleted.")
                else:
                    self.signal_manager.message_signal.emit("Permission denied. Please ensure your AWS credentials have the necessary permissions.")
            else:
                self.signal_manager.message_signal.emit(f"Error deleting parameter group: {str(e)}")
        finally:
            self.hide_loading()

    def is_parameter_group_name_exists(self, param_group_name):
        try:
            self.elasticache_client.describe_cache_parameter_groups(CacheParameterGroupNames=[param_group_name])
            return True
        except self.elasticache_client.exceptions.CacheParameterGroupNotFoundFault:
            return False
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error checking parameter group existence: {str(e)}")
            return False

    def is_valid_parameter_group_name(self, param_group_name):
        """
        Validate the parameter group name format: 20 characters or less, consisting of letters, numbers, and hyphens.
        """
        return bool(re.match(r'^[a-zA-Z0-9\-]{1,20}$', param_group_name))

    # -------------------- Snapshot Management Subtab --------------------
    def setup_snapshot_management_tab(self):
        layout = QFormLayout()

        # Snapshot ID
        self.snapshot_id_input = QLineEdit(self)
        self.snapshot_id_input.setPlaceholderText("Enter snapshot ID")
        layout.addRow(QLabel("Snapshot ID:"), self.snapshot_id_input)

        # Cluster ID
        self.snapshot_cluster_id_input = QLineEdit(self)
        self.snapshot_cluster_id_input.setPlaceholderText("Enter cluster ID")
        layout.addRow(QLabel("Cluster ID:"), self.snapshot_cluster_id_input)

        # Execute Buttons
        self.create_snapshot_button = QPushButton("Create Snapshot", self)
        self.create_snapshot_button.clicked.connect(self.create_snapshot)
        layout.addRow(self.create_snapshot_button)

        self.restore_snapshot_button = QPushButton("Restore from Snapshot", self)
        self.restore_snapshot_button.clicked.connect(self.restore_snapshot)
        layout.addRow(self.restore_snapshot_button)

        self.delete_snapshot_button = QPushButton("Delete Snapshot", self)
        self.delete_snapshot_button.clicked.connect(self.delete_snapshot)
        layout.addRow(self.delete_snapshot_button)

        self.snapshot_management_tab.setLayout(layout)

    def create_snapshot(self):
        snapshot_id = self.snapshot_id_input.text().strip()
        cluster_id = self.snapshot_cluster_id_input.text().strip()

        # Validation: All fields must be filled
        if not all([snapshot_id, cluster_id]):
            self.signal_manager.message_signal.emit("Please fill all fields to create a snapshot.")
            return

        # Validate Snapshot ID format
        if not self.is_valid_snapshot_id(snapshot_id):
            self.signal_manager.message_signal.emit("Invalid Snapshot ID format. Must be 20 characters or less, consisting of letters, numbers, and hyphens.")
            return

        # Validate Cluster ID exists
        if not self.is_cluster_id_exists(cluster_id):
            self.signal_manager.message_signal.emit(f"Cluster ID '{cluster_id}' does not exist.")
            return

        # Validate Snapshot ID uniqueness
        if self.is_snapshot_id_exists(snapshot_id):
            self.signal_manager.message_signal.emit(f"Snapshot ID '{snapshot_id}' already exists. Please choose a different ID.")
            return

        self.show_loading()
        self.run_in_thread(
            self._create_snapshot,
            snapshot_id,
            cluster_id
        )

    def _create_snapshot(self, snapshot_id, cluster_id):
        try:
            response = self.elasticache_client.create_snapshot(
                SnapshotName=snapshot_id,
                CacheClusterId=cluster_id
            )
            self.signal_manager.message_signal.emit(f"Snapshot '{snapshot_id}' creation initiated successfully.")
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['SnapshotAlreadyExists', 'CacheClusterNotFound', 'AccessDenied', 'UnauthorizedOperation']:
                if error_code == 'SnapshotAlreadyExists':
                    self.signal_manager.message_signal.emit(f"Snapshot ID '{snapshot_id}' already exists. Please choose a different ID.")
                elif error_code == 'CacheClusterNotFound':
                    self.signal_manager.message_signal.emit(f"Cluster ID '{cluster_id}' not found.")
                else:
                    self.signal_manager.message_signal.emit("Permission denied. Please ensure your AWS credentials have the necessary permissions.")
            else:
                self.signal_manager.message_signal.emit(f"Error creating snapshot: {str(e)}")
        finally:
            self.hide_loading()

    def restore_snapshot(self):
        snapshot_id, ok = QInputDialog.getText(
            self, "Restore from Snapshot", "Enter the Snapshot ID to restore from:"
        )
        if ok and snapshot_id:
            # Validate Snapshot ID format
            if not self.is_valid_snapshot_id(snapshot_id):
                self.signal_manager.message_signal.emit("Invalid Snapshot ID format.")
                return

            # Validate Snapshot exists
            if not self.is_snapshot_id_exists(snapshot_id):
                self.signal_manager.message_signal.emit(f"Snapshot ID '{snapshot_id}' does not exist.")
                return

            # Prompt for new Cluster ID
            new_cluster_id, ok = QInputDialog.getText(
                self, "Restore from Snapshot", "Enter new Cluster ID:"
            )
            if ok and new_cluster_id:
                # Validate Cluster ID format
                if not self.is_valid_cluster_id(new_cluster_id):
                    self.signal_manager.message_signal.emit("Invalid Cluster ID format.")
                    return

                # Validate Cluster ID uniqueness
                if self.is_cluster_id_exists(new_cluster_id):
                    self.signal_manager.message_signal.emit(f"Cluster ID '{new_cluster_id}' already exists. Please choose a different ID.")
                    return

                # Prompt for Node Type
                node_type, ok = QInputDialog.getItem(
                    self, "Restore from Snapshot", "Select Node Type:",
                    [
                        "cache.t2.micro", "cache.t2.small", "cache.t2.medium",
                        "cache.m4.large", "cache.m4.xlarge", "cache.m4.2xlarge",
                        "cache.m5.large", "cache.m5.xlarge", "cache.m5.2xlarge",
                        # Add more as needed
                    ],
                    0, False
                )
                if not ok:
                    return

                # Prompt for Engine Version
                engine_version, ok = QInputDialog.getText(
                    self, "Restore from Snapshot", "Enter Engine Version (e.g., 5.0.6):"
                )
                if not ok or not engine_version:
                    self.signal_manager.message_signal.emit("Engine Version is required.")
                    return

                # Proceed to restore snapshot
                self.show_loading()
                self.run_in_thread(
                    self._restore_snapshot,
                    snapshot_id,
                    new_cluster_id,
                    node_type,
                    engine_version
                )

    def _restore_snapshot(self, snapshot_id, new_cluster_id, node_type, engine_version):
        try:
            response = self.elasticache_client.restore_snapshot(
                SnapshotName=snapshot_id,
                CacheClusterId=new_cluster_id,
                CacheNodeType=node_type,
                EngineVersion=engine_version,
                SnapshotRetentionLimit=7,  # Example value
            )
            self.signal_manager.message_signal.emit(f"Snapshot '{snapshot_id}' restoration initiated as cluster '{new_cluster_id}'.")
            self.run_in_thread(self.load_clusters)  # Refresh clusters list
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['SnapshotNotFound', 'CacheClusterAlreadyExists', 'AccessDenied', 'UnauthorizedOperation']:
                if error_code == 'SnapshotNotFound':
                    self.signal_manager.message_signal.emit(f"Snapshot ID '{snapshot_id}' not found.")
                elif error_code == 'CacheClusterAlreadyExists':
                    self.signal_manager.message_signal.emit(f"Cluster ID '{new_cluster_id}' already exists. Please choose a different ID.")
                else:
                    self.signal_manager.message_signal.emit("Permission denied. Please ensure your AWS credentials have the necessary permissions.")
            else:
                self.signal_manager.message_signal.emit(f"Error restoring snapshot: {str(e)}")
        finally:
            self.hide_loading()

    def delete_snapshot(self):
        snapshot_id, ok = QInputDialog.getText(
            self, "Delete Snapshot", "Enter the Snapshot ID to delete:"
        )
        if ok and snapshot_id:
            # Validate Snapshot ID format
            if not self.is_valid_snapshot_id(snapshot_id):
                self.signal_manager.message_signal.emit("Invalid Snapshot ID format.")
                return

            # Validate Snapshot exists
            if not self.is_snapshot_id_exists(snapshot_id):
                self.signal_manager.message_signal.emit(f"Snapshot ID '{snapshot_id}' does not exist.")
                return

            confirm = QMessageBox.question(
                self, "Delete Snapshot",
                f"Are you sure you want to delete the snapshot '{snapshot_id}'?",
                QMessageBox.Yes | QMessageBox.No
            )

            if confirm == QMessageBox.Yes:
                self.show_loading()
                self.run_in_thread(self._delete_snapshot, snapshot_id)

    def _delete_snapshot(self, snapshot_id):
        try:
            self.elasticache_client.delete_snapshot(SnapshotName=snapshot_id)
            self.signal_manager.message_signal.emit(f"Snapshot '{snapshot_id}' deletion initiated.")
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['SnapshotNotFound', 'AccessDenied', 'UnauthorizedOperation']:
                if error_code == 'SnapshotNotFound':
                    self.signal_manager.message_signal.emit(f"Snapshot ID '{snapshot_id}' not found.")
                else:
                    self.signal_manager.message_signal.emit("Permission denied. Please ensure your AWS credentials have the necessary permissions.")
            else:
                self.signal_manager.message_signal.emit(f"Error deleting snapshot: {str(e)}")
        finally:
            self.hide_loading()

    def is_snapshot_id_exists(self, snapshot_id):
        try:
            self.elasticache_client.describe_snapshots(SnapshotName=snapshot_id)
            return True
        except self.elasticache_client.exceptions.SnapshotNotFoundFault:
            return False
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error checking snapshot existence: {str(e)}")
            return False

    def is_valid_snapshot_id(self, snapshot_id):
        """
        Validate the snapshot ID format: 20 characters or less, consisting of letters, numbers, and hyphens.
        """
        return bool(re.match(r'^[a-zA-Z0-9\-]{1,20}$', snapshot_id))

    # -------------------- Monitoring and Events Subtab --------------------
    def setup_monitoring_events_tab(self):
        layout = QFormLayout()

        # Select Cluster
        self.monitor_cluster_dropdown = QComboBox(self)
        self.monitor_cluster_dropdown.setPlaceholderText("Select a Cluster")
        layout.addRow(QLabel("Select Cluster:"), self.monitor_cluster_dropdown)

        # View Metrics Button
        self.view_metrics_button = QPushButton("View Metrics", self)
        self.view_metrics_button.clicked.connect(self.view_metrics)
        layout.addRow(self.view_metrics_button)

        # View Events Button
        self.view_events_button = QPushButton("View Events", self)
        self.view_events_button.clicked.connect(self.view_events)
        layout.addRow(self.view_events_button)

        self.monitoring_events_tab.setLayout(layout)
        self.populate_monitor_cluster_dropdown()

    def populate_monitor_cluster_dropdown(self):
        clusters = [cluster.split('(')[0].strip() for cluster in self.existing_clusters_dropdown.currentText().split('\n') if cluster]
        self.monitor_cluster_dropdown.clear()
        self.monitor_cluster_dropdown.addItems(clusters)

    def view_metrics(self):
        selected_cluster = self.monitor_cluster_dropdown.currentText()
        if not selected_cluster:
            self.signal_manager.message_signal.emit("Please select a cluster to view metrics.")
            return

        # Extract Cluster ID
        cluster_id = selected_cluster.split('(')[0].strip()

        self.show_loading()
        self.run_in_thread(self._view_metrics, cluster_id)

    def _view_metrics(self, cluster_id):
        try:
            metrics = self.elasticache_client.describe_cache_clusters(CacheClusterId=cluster_id, ShowCacheClusters=True)
            # For simplicity, we'll display basic metrics. For detailed CloudWatch metrics, integration with CloudWatch API is needed.
            cluster = metrics['CacheClusters'][0]
            memory_usage = cluster.get('PendingModifiedValues', {}).get('CacheNodeIdsToRemove', [])
            # Placeholder: Fetch actual metrics from CloudWatch if needed
            self.signal_manager.message_signal.emit(f"Metrics for Cluster '{cluster_id}':\nMemory Usage: Placeholder")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error fetching metrics: {str(e)}")
        finally:
            self.hide_loading()

    def view_events(self):
        selected_cluster = self.monitor_cluster_dropdown.currentText()
        if not selected_cluster:
            self.signal_manager.message_signal.emit("Please select a cluster to view events.")
            return

        # Extract Cluster ID
        cluster_id = selected_cluster.split('(')[0].strip()

        self.show_loading()
        self.run_in_thread(self._view_events, cluster_id)

    def _view_events(self, cluster_id):
        try:
            response = self.elasticache_client.describe_events(
                SourceIdentifier=cluster_id,
                SourceType='cache-cluster',
                MaxRecords=10,
                EventCategories=['engine', 'maintenance', 'availability']
            )
            events = response.get('Events', [])
            if not events:
                self.signal_manager.message_signal.emit(f"No recent events for Cluster '{cluster_id}'.")
                return
            event_messages = [f"{event['Date']} - {event['Message']}" for event in events]
            self.signal_manager.message_signal.emit(f"Recent Events for Cluster '{cluster_id}':\n" + "\n".join(event_messages))
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error fetching events: {str(e)}")
        finally:
            self.hide_loading()

    # -------------------- Helper Validation Methods --------------------
    def is_cluster_id_exists(self, cluster_id):
        try:
            self.elasticache_client.describe_cache_clusters(CacheClusterId=cluster_id, ShowCacheClusters=True)
            return True
        except self.elasticache_client.exceptions.CacheClusterNotFoundFault:
            return False
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error checking cluster existence: {str(e)}")
            return False

    def is_valid_parameter_group_name(self, param_group_name):
        """
        Validate the parameter group name format: 20 characters or less, consisting of letters, numbers, and hyphens.
        """
        return bool(re.match(r'^[a-zA-Z0-9\-]{1,20}$', param_group_name))

    # -------------------- Additional Best Practices Methods --------------------
    def is_valid_replication_group_id(self, rg_id):
        """
        Validate the replication group ID format: 20 characters or less, consisting of letters, numbers, and hyphens.
        """
        return bool(re.match(r'^[a-zA-Z0-9\-]{1,20}$', rg_id))

    # -------------------- Extensibility Example: SSL Certificate Management --------------------
    # Future implementation can be added here to manage SSL certificates

    # Placeholder for SSL Certificate Management
    def setup_ssl_certificate_tab(self):
        pass
