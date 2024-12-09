import json
import os
import subprocess
import threading

import yaml
from kubernetes import client, config, utils
from kubernetes.client import ApiException
from PyQt5.QtCore import QObject, Qt, pyqtSignal
from PyQt5.QtGui import QIntValidator
from PyQt5.QtWidgets import (QCheckBox, QComboBox, QDialog, QDialogButtonBox,
                             QFileDialog, QGroupBox, QHBoxLayout, QLabel,
                             QLineEdit, QMessageBox, QPushButton, QRadioButton,
                             QTextEdit, QVBoxLayout, QWidget)


class WorkerSignals(QObject):
    log_signal = pyqtSignal(str)
    finished = pyqtSignal()


class ServiceManagementTab(QWidget):
    def __init__(self, auth_manager, main_tab_widget):
        super().__init__()
        self.auth_manager = auth_manager
        self.main_tab_widget = main_tab_widget
        self.kubeconfig_path = os.path.expanduser("~/.kube/config")
        self.initUI()
        

    def initUI(self):
        # Main layout
        main_layout = QHBoxLayout()

        # Left Column: Service Actions
        left_column = QVBoxLayout()


        # Group 1: General Service Actions
        general_group_box = QGroupBox("General Service Actions")
        general_layout = QVBoxLayout()

        # Horizontal layout for SSL and Context Selector
        ssl_context_layout = QHBoxLayout()

        # SSL Verification Checkbox
        self.ssl_checkbox = QCheckBox("Enable SSL Verification")
        self.ssl_checkbox.setChecked(False)  # Default unchecked (SSL verification disabled)
        self.ssl_checkbox.setToolTip("Enable/disable SSL certificate verification.")
        ssl_context_layout.addWidget(self.ssl_checkbox)

        # Context Selection ComboBox
        self.context_selector = QComboBox(self)
        self.load_kube_contexts()
        self.context_selector.currentIndexChanged.connect(self.load_namespaces)
        self.context_selector.setFixedWidth(200)  # Adjust the width as needed
        ssl_context_layout.addWidget(self.context_selector)

        # Add the horizontal layout to the general layout
        general_layout.addLayout(ssl_context_layout)

        # Horizontal layout for Namespace and Service
        namespace_service_layout = QHBoxLayout()

        # Namespace Dropdown
        self.namespace_dropdown = QComboBox(self)
        self.namespace_dropdown.addItem("Select Namespace")
        self.namespace_dropdown.currentIndexChanged.connect(self.update_service_dropdown)
        self.namespace_dropdown.setFixedWidth(200)  # Adjust the width as needed
        namespace_service_layout.addWidget(self.namespace_dropdown)

        # Service Name Dropdown
        self.service_name_dropdown = QComboBox(self)
        self.service_name_dropdown.addItem("Select Service")
        self.service_name_dropdown.setFixedWidth(200)  # Adjust the width as needed
        namespace_service_layout.addWidget(self.service_name_dropdown)
        
        # Label Selector Input
        self.label_selector_input = QLineEdit(self)
        self.label_selector_input.setPlaceholderText("Enter Label Selector (key=value)")
        self.label_selector_input.setFixedWidth(100)  # Adjust the width as needed
        namespace_service_layout.addWidget(self.label_selector_input)

        # Add the horizontal layout to the general layout
        general_layout.addLayout(namespace_service_layout)

        # Horizontal layout for Action and Execute Button
        action_execute_layout = QHBoxLayout()

        # Action Combobox
        self.service_action_option = QComboBox(self)
        self.service_action_option.addItems([
            "Select Action",
            "Get Service Details",
            "Get Service YAML",
            "Edit Service",
            "Get Endpoint",
            "Export Service",
            "Filter Services",
            "Delete Service" 
        ])
        self.service_action_option.setFixedWidth(200)  # Adjust the width as needed
        action_execute_layout.addWidget(self.service_action_option)

        # Execute Button
        self.execute_button = QPushButton("Execute")
        self.execute_button.clicked.connect(self.execute_general_service_action)
        action_execute_layout.addWidget(self.execute_button)

        # Add the horizontal layout to the general layout
        general_layout.addLayout(action_execute_layout)

        # Set layout for general group box and add to left column
        general_group_box.setLayout(general_layout)
        left_column.addWidget(general_group_box)


        # Group 2: Create/Update Service
        create_update_group_box = QGroupBox("Create/Update Service")
        create_update_layout = QVBoxLayout()

        # Radio Buttons: New or Update
        self.create_radio = QRadioButton("New")
        self.update_radio = QRadioButton("Update")
        self.create_radio.setChecked(True)  # Default to "New"
        self.create_radio.toggled.connect(self.toggle_create_update_mode)

        radio_layout = QHBoxLayout()
        radio_layout.addWidget(self.create_radio)
        radio_layout.addWidget(self.update_radio)
        create_update_layout.addLayout(radio_layout)

        # Action Combobox for New/Update actions
        self.create_update_action_option = QComboBox(self)
        self.create_update_action_option.addItems([
            "Select Action",
            "Upload Service YAML"
        ])
        self.create_update_action_option.setEnabled(True)  # Enabled only in 'New' mode
        action_layout = QHBoxLayout()
        action_layout.addWidget(QLabel("Action:"))
        action_layout.addWidget(self.create_update_action_option)
        create_update_layout.addLayout(action_layout)

        # Components for creating or updating a service
        self.service_type_label = QLabel("Service Type:")
        self.service_type_input = QComboBox(self)
        self.service_type_input.addItems(["ClusterIP", "NodePort", "LoadBalancer"])
        self.service_type_input.setFixedWidth(120)

        type_layout = QHBoxLayout()
        type_layout.addWidget(self.service_type_label)
        type_layout.addWidget(self.service_type_input)

        self.port_label = QLabel("Port:")
        self.port_input = QLineEdit(self)
        self.port_input.setPlaceholderText("Port")
        self.port_input.setValidator(QIntValidator(1, 65535))
        self.port_input.setFixedWidth(80)

        self.target_port_label = QLabel("Target Port:")
        self.target_port_input = QLineEdit(self)
        self.target_port_input.setPlaceholderText("Target Port")
        self.target_port_input.setValidator(QIntValidator(1, 65535))
        self.target_port_input.setFixedWidth(80)

        port_layout = QHBoxLayout()
        port_layout.addWidget(self.port_label)
        port_layout.addWidget(self.port_input)
        port_layout.addWidget(self.target_port_label)
        port_layout.addWidget(self.target_port_input)

        self.selector_label = QLabel("Selector:")
        self.selector_input = QLineEdit(self)
        self.selector_input.setPlaceholderText("key=value")
        self.selector_input.setFixedWidth(150)

        self.labels_label = QLabel("Labels:")
        self.labels_input = QLineEdit(self)
        self.labels_input.setPlaceholderText("key=value,key=value")
        self.labels_input.setFixedWidth(150)

        selector_labels_layout = QHBoxLayout()
        selector_labels_layout.addWidget(self.selector_label)
        selector_labels_layout.addWidget(self.selector_input)
        selector_labels_layout.addWidget(self.labels_label)
        selector_labels_layout.addWidget(self.labels_input)

        self.annotations_label = QLabel("Annotations:")
        self.annotations_input = QLineEdit(self)
        self.annotations_input.setPlaceholderText("key=value,key=value")
        self.annotations_input.setFixedWidth(300)

        annotations_layout = QHBoxLayout()
        annotations_layout.addWidget(self.annotations_label)
        annotations_layout.addWidget(self.annotations_input)

        # Store UI components and labels for visibility toggling
        self.update_fields = [
            (self.service_type_label, self.service_type_input),
            (self.port_label, self.port_input),
            (self.target_port_label, self.target_port_input),
            (self.selector_label, self.selector_input),
            (self.labels_label, self.labels_input),
            (self.annotations_label, self.annotations_input),
        ]

        # Add all components to layout (but initially hide them for "New")
        create_update_layout.addLayout(type_layout)
        create_update_layout.addLayout(port_layout)
        create_update_layout.addLayout(selector_labels_layout)
        create_update_layout.addLayout(annotations_layout)

        # Hide all fields initially since the default mode is "New"
        for label, widget in self.update_fields:
            label.setVisible(False)
            widget.setVisible(False)

        # Execute Button for Create/Update
        self.create_update_action_button = QPushButton("Execute")
        self.create_update_action_button.clicked.connect(self.execute_create_update_service_action)
        create_update_layout.addWidget(self.create_update_action_button)

        create_update_group_box.setLayout(create_update_layout)
        left_column.addWidget(create_update_group_box)

        # Group 3: Advanced Actions
        advanced_group_box = QGroupBox("Advanced Actions")
        advanced_layout = QVBoxLayout()

        # First Line: Port Forward Inputs
        port_forward_layout = QHBoxLayout()

        # Local Port Input
        local_port_label = QLabel("Local Port:")
        local_port_label.setFixedWidth(70)
        self.local_port_input = QLineEdit(self)
        self.local_port_input.setPlaceholderText("Local Port")
        self.local_port_input.setFixedWidth(80)
        self.local_port_input.setValidator(QIntValidator(1, 65535))
        port_forward_layout.addWidget(local_port_label)
        port_forward_layout.addWidget(self.local_port_input)

        # Service Port Input
        service_port_label = QLabel("Service Port:")
        service_port_label.setFixedWidth(80)
        self.service_port_input = QLineEdit(self)
        self.service_port_input.setPlaceholderText("Service Port")
        self.service_port_input.setFixedWidth(80)
        self.service_port_input.setValidator(QIntValidator(1, 65535))
        port_forward_layout.addWidget(service_port_label)
        port_forward_layout.addWidget(self.service_port_input)

        advanced_layout.addLayout(port_forward_layout)

        # Second Line: Additional Inputs for Autoscaler
        autoscaler_layout = QHBoxLayout()

        min_replicas_label = QLabel("Min Replicas:")
        min_replicas_label.setFixedWidth(80)
        self.min_replicas_input = QLineEdit(self)
        self.min_replicas_input.setPlaceholderText("Min")
        self.min_replicas_input.setFixedWidth(50)
        self.min_replicas_input.setValidator(QIntValidator(0, 1000))
        autoscaler_layout.addWidget(min_replicas_label)
        autoscaler_layout.addWidget(self.min_replicas_input)

        max_replicas_label = QLabel("Max Replicas:")
        max_replicas_label.setFixedWidth(80)
        self.max_replicas_input = QLineEdit(self)
        self.max_replicas_input.setPlaceholderText("Max")
        self.max_replicas_input.setFixedWidth(50)
        self.max_replicas_input.setValidator(QIntValidator(0, 1000))
        autoscaler_layout.addWidget(max_replicas_label)
        autoscaler_layout.addWidget(self.max_replicas_input)

        cpu_util_label = QLabel("CPU Util%:")
        cpu_util_label.setFixedWidth(70)
        self.cpu_util_input = QLineEdit(self)
        self.cpu_util_input.setPlaceholderText("%")
        self.cpu_util_input.setFixedWidth(50)
        self.cpu_util_input.setValidator(QIntValidator(1, 100))
        autoscaler_layout.addWidget(cpu_util_label)
        autoscaler_layout.addWidget(self.cpu_util_input)

        advanced_layout.addLayout(autoscaler_layout)

        # Action Combobox and Execute Button for Advanced Actions
        action_layout = QHBoxLayout()
        self.advanced_action_option = QComboBox(self)
        self.advanced_action_option.addItems([
            "Select Action",
            "Port Forward Service",
            "Create Autoscaler",
            "Update Service Labels",
            "Update Service Annotations",
            "Bulk Operations"
        ])
        action_layout.addWidget(QLabel("Action:"))
        action_layout.addWidget(self.advanced_action_option)

        self.advanced_action_button = QPushButton("Execute")
        self.advanced_action_button.clicked.connect(self.execute_advanced_service_action)
        action_layout.addWidget(self.advanced_action_button)

        advanced_layout.addLayout(action_layout)

        advanced_group_box.setLayout(advanced_layout)
        left_column.addWidget(advanced_group_box)

        # Add left column to main layout
        main_layout.addLayout(left_column)

        # Right Column: Output, Editor, and Import JSON
        right_column = QVBoxLayout()

        # Output TextEdit
        self.service_command_output = QTextEdit(self)
        self.service_command_output.setReadOnly(True)
        right_column.addWidget(QLabel("Output:"))
        right_column.addWidget(self.service_command_output)


        # Add right column to main layout
        main_layout.addLayout(right_column)

        self.setLayout(main_layout)
        
        self.load_kube_contexts()
        self.load_namespaces()
        
    def toggle_create_update_mode(self):
        """Toggle between 'New' and 'Update' mode."""
        if self.update_radio.isChecked():
            # Show fields for editing an existing service
            for label, widget in self.update_fields:
                label.setVisible(True)
                widget.setVisible(True)
            
            self.create_update_action_option.setEnabled(False)  # Disable Upload action in 'Update'

            # Use the service selection from Group 1
            self.service_name_dropdown.setEnabled(True)

        else:  # New mode
            # Hide fields for creating a new service
            for label, widget in self.update_fields:
                label.setVisible(False)
                widget.setVisible(False)
            
            self.create_update_action_option.setEnabled(True)  # Enable Upload action in 'New'

            # Use the service selection from Group 1
            self.service_name_dropdown.setEnabled(False)
            
    def load_services_for_update(self):
        """Load services in the selected namespace for updating."""
        namespace = self.namespace_dropdown.currentText()
        v1 = self.get_k8s_api_client()
        if not v1:
            return

        try:
            services = v1.list_namespaced_service(namespace=namespace)
            self.service_name_dropdown_update.clear()
            self.service_name_dropdown_update.addItem("Select Service to Update")
            self.service_name_dropdown_update.addItems([svc.metadata.name for svc in services.items])
        except Exception as e:
            self.service_command_output.append(f"Error loading services for update: {e}")

    def get_k8s_api_client(self):
        """Helper to get a CoreV1Api client with current context and SSL settings."""
        try:
            config_obj = client.Configuration()
            config.load_kube_config(
                context=self.context_selector.currentText(),
                client_configuration=config_obj
            )
            # Set SSL verification based on checkbox or always skip verification
            config_obj.verify_ssl = self.ssl_checkbox.isChecked()  # or set to False if you always want to skip
            config_obj.ssl_ca_cert = None  # Ensure CA certificate is not used
            return client.CoreV1Api(client.ApiClient(config_obj))
        except Exception as e:
            self.service_command_output.append(f"Error loading Kubernetes API client: {e}")
            return None



    def load_kube_contexts(self):
        """Load contexts from the kubeconfig file."""
        self.context_selector.clear()
        try:
            contexts, active_context = config.list_kube_config_contexts()
            self.context_selector.addItems([ctx['name'] for ctx in contexts])
            if active_context:
                self.context_selector.setCurrentText(active_context['name'])
        except Exception as e:
            self.service_command_output.append(f"Error loading Kubernetes contexts: {e}")

    def load_namespaces(self):
        """Load namespaces and populate the namespace dropdown."""
        try:
            v1 = self.get_k8s_api_client()
            if v1 is None:
                return

            namespaces = v1.list_namespace().items
            self.namespace_dropdown.clear()
            self.namespace_dropdown.addItem("Select Namespace")
            self.namespace_dropdown.addItems([ns.metadata.name for ns in namespaces])
        except Exception as e:
            self.service_command_output.append(f"Error loading namespaces: {e}")

    def update_service_dropdown(self):
        """Load services based on the selected namespace."""
        selected_namespace = self.namespace_dropdown.currentText()
        if selected_namespace == "Select Namespace":
            return

        try:
            v1 = self.get_k8s_api_client()
            if v1 is None:
                return

            services = v1.list_namespaced_service(namespace=selected_namespace).items
            self.service_name_dropdown.clear()
            self.service_name_dropdown.addItem("Select Service")
            self.service_name_dropdown.addItems([svc.metadata.name for svc in services])
        except Exception as e:
            self.service_command_output.append(f"Error loading services: {e}")

    # --------------------- General Service Actions ---------------------

    def execute_general_service_action(self):
        """Execute the selected action based on the dropdown choices."""
        action = self.service_action_option.currentText()
        service_name = self.service_name_dropdown.currentText()
        namespace = self.namespace_dropdown.currentText()
        label_selector = self.label_selector_input.text()

        # Validate selections
        if namespace == "Select Namespace":
            self.service_command_output.append("Please select a valid namespace.")
            return
        if action in ["Get Service Details", "Get Service YAML", "Export Service", "Get Endpoint"] and service_name == "Select Service":
            self.service_command_output.append("Please select a valid service.")
            return
        if action == "Select Action":
            self.service_command_output.append("Please select a valid service action.")
            return

        # Get the Kubernetes API client
        v1 = self.get_k8s_api_client()
        if not isinstance(v1, client.CoreV1Api):
            self.service_command_output.append("Error: Kubernetes API client is not properly initialized.")
            return  # No valid Kubernetes API client

        # Execute the action
        self.service_command_output.append(f"Executing action '{action}' for service '{service_name}' in namespace '{namespace}'.")

        # Define the action methods
        action_methods = {
            "Get Service Details": lambda v1, ns, svc, lbl: self.get_service_details(ns, svc, lbl),
            "Get Service YAML": lambda v1, ns, svc, lbl: self.get_service_yaml(v1, ns, svc),
            "Edit Service": lambda v1, ns, svc, lbl: self.edit_service(ns, svc), 
            "Export Service": lambda v1, ns, svc, lbl: self.export_service(v1, ns, svc),
            "Filter Services": lambda v1, ns, svc, lbl: self.filter_services(v1, ns, svc, lbl),
            "Get Endpoint": lambda v1, ns, svc, lbl: self.get_service_endpoints(v1, ns, svc),
            "Delete Service": lambda v1, ns, svc, lbl: self.delete_service(v1, ns, svc), 
        }

        action_method = action_methods.get(action)
        if action_method:
            action_method(v1, namespace, service_name, label_selector)
        else:
            self.service_command_output.append("Please select a valid service action.")


    def get_k8s_api_client(self):
        """Helper to get a CoreV1Api client with current context and SSL settings."""
        try:
            config_obj = client.Configuration()
            config.load_kube_config(
                context=self.context_selector.currentText(),
                client_configuration=config_obj
            )
            config_obj.verify_ssl = self.ssl_checkbox.isChecked()
            return client.CoreV1Api(client.ApiClient(config_obj))
        except Exception as e:
            self.service_command_output.append(f"Error loading Kubernetes API client: {e}")
            return None

    def get_service_details(self, namespace, service_name, label_selector=None):
        """Get details of a specific service in a human-readable format."""
        v1 = self.get_k8s_api_client()
        if not v1:
            return  # No valid Kubernetes API client

        try:
            svc = v1.read_namespaced_service(name=service_name, namespace=namespace)

            # Extract and format the relevant details
            service_info = f"""
        Service Name: {svc.metadata.name}
        Namespace: {svc.metadata.namespace}
        Labels: {svc.metadata.labels}
        Annotations: {svc.metadata.annotations}
        Selector: {svc.spec.selector}
        Type: {svc.spec.type}
        Cluster IP: {svc.spec.cluster_ip}
        External IPs: {svc.spec.external_i_ps if svc.spec.external_i_ps else 'None'}
        Ports:
        """
            # Add each port with its details
            for port in svc.spec.ports:
                service_info += f"  - Port: {port.port}, Protocol: {port.protocol}, Target Port: {port.target_port}, Node Port: {port.node_port if svc.spec.type == 'NodePort' else 'N/A'}\n"

            service_info += f"""
        Session Affinity: {svc.spec.session_affinity}
        Creation Timestamp: {svc.metadata.creation_timestamp}
        """
            # Display the details in the output
            self.service_command_output.append(service_info)

        except Exception as e:
            self.service_command_output.append(f"Error getting service details: {e}")

    def get_service_yaml(self, v1, namespace, service_name, label_selector=None):
        """Get YAML of a specific service."""
        try:
            # Ensure `v1` is an instance of CoreV1Api
            if not isinstance(v1, client.CoreV1Api):
                self.service_command_output.append("Error: Kubernetes API client is not properly initialized.")
                return

            # Fetch the service details
            svc = v1.read_namespaced_service(name=service_name, namespace=namespace)
            
            # Use the Kubernetes API client to convert the service object to a dict
            svc_dict = v1.api_client.sanitize_for_serialization(svc)
            
            # Convert to YAML format
            yaml_content = yaml.dump(svc_dict, default_flow_style=False)
            
            # Display the YAML content in the output
            self.service_command_output.append("Service YAML:")
            self.service_command_output.append(yaml_content)
        
        except Exception as e:
            self.service_command_output.append(f"Error getting service YAML: {e}")

    def export_service(self, v1, namespace, service_name, label_selector=None):
        """Export the YAML of a specific service to a file."""
        try:
            # Fetch the service
            svc = v1.read_namespaced_service(name=service_name, namespace=namespace)
            yaml_output = client.ApiClient().sanitize_for_serialization(svc)

            # Create the default file name using the service name
            default_file_name = f"{service_name}.yaml"
            file_name, _ = QFileDialog.getSaveFileName(self, "Save Service YAML", default_file_name, "YAML Files (*.yaml)")
            
            # If a file name was provided, save the YAML
            if file_name:
                with open(file_name, 'w') as f:
                    yaml.dump(yaml_output, f)
                self.service_command_output.append(f"Service exported to {file_name}.")
        except Exception as e:
            self.service_command_output.append(f"Error exporting service: {e}")



    def filter_services(self, v1, namespace, service_name=None, label_selector=None):
        """Filter services based on label selector and display in a table-like format."""
        try:
            services = v1.list_namespaced_service(namespace=namespace, label_selector=label_selector)

            # Prepare table header
            header = f"{'Name':<25}{'Type':<15}{'Cluster IP':<20}{'External IP':<20}{'Ports':<20}{'Age':<20}"
            self.service_command_output.append(header)
            self.service_command_output.append('-' * len(header))

            # Display each service in a formatted row
            for svc in services.items:
                name = svc.metadata.name
                svc_type = svc.spec.type
                cluster_ip = svc.spec.cluster_ip
                external_ips = ", ".join(svc.spec.external_i_ps) if svc.spec.external_i_ps else "None"
                ports = ", ".join([f"{p.port}/{p.protocol}" for p in svc.spec.ports])
                age = self.get_age(svc.metadata.creation_timestamp)

                row = f"{name:<25}{svc_type:<15}{cluster_ip:<20}{external_ips:<20}{ports:<20}{age:<20}"
                self.service_command_output.append(row)

        except Exception as e:
            self.service_command_output.append(f"Error filtering services: {e}")
            
    def delete_service(self, v1, namespace, service_name):
        """Delete the selected service."""
        if not service_name:
            self.service_command_output.append("Please select a service to delete.")
            QMessageBox.warning(self, "Warning", "Please select a service to delete.")
            return

        try:
            # Confirm deletion with the user
            reply = QMessageBox.question(
                self, 'Confirm Delete',
                f"Are you sure you want to delete service '{service_name}' in namespace '{namespace}'?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                v1.delete_namespaced_service(name=service_name, namespace=namespace)
                self.service_command_output.append(f"Service '{service_name}' deleted successfully.")
                # Refresh the service dropdown after deletion
                self.update_service_dropdown()
            else:
                self.service_command_output.append("Service deletion canceled.")
        except ApiException as e:
            self.service_command_output.append(f"Kubernetes API error deleting service: {e}")
            QMessageBox.critical(self, "Error", f"Failed to delete service: {e}")
        except Exception as e:
            self.service_command_output.append(f"Error deleting service: {e}")
            QMessageBox.critical(self, "Error", f"Failed to delete service: {e}")


    def get_age(self, creation_timestamp):
        """Calculate and return the age of a resource given its creation timestamp."""
        from datetime import datetime

        # Calculate age from creation timestamp
        now = datetime.now(creation_timestamp.tzinfo)
        age_timedelta = now - creation_timestamp

        # Format the age in a human-readable way
        days = age_timedelta.days
        seconds = age_timedelta.seconds
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60

        if days > 0:
            return f"{days}d"
        elif hours > 0:
            return f"{hours}h"
        else:
            return f"{minutes}m"


    
    def get_service_endpoints(self, v1, namespace, service_name):
        """Get endpoints of a specific service."""
        try:
            # Get the endpoints for the service
            endpoints = v1.read_namespaced_endpoints(name=service_name, namespace=namespace)

            # Extract and format relevant endpoint information
            endpoint_info = f"Endpoints for service '{service_name}' in namespace '{namespace}':\n"
            if endpoints.subsets:
                for subset in endpoints.subsets:
                    addresses = ', '.join([addr.ip for addr in subset.addresses]) if subset.addresses else "None"
                    ports = ', '.join([f"{port.port}/{port.protocol}" for port in subset.ports]) if subset.ports else "None"
                    endpoint_info += f"  Addresses: {addresses}\n"
                    endpoint_info += f"  Ports: {ports}\n"
            else:
                endpoint_info += "  No endpoints found.\n"

            # Display the details in the output
            self.service_command_output.append(endpoint_info)

        except Exception as e:
            self.service_command_output.append(f"Error getting service endpoints: {e}")




    # --------------------- Create/Update Service Actions ---------------------

    def execute_create_update_service_action(self):
        """Handle creation or update based on UI selections."""
        action = self.create_update_action_option.currentText()
        
        if self.create_radio.isChecked():
            if action == "Upload Service YAML":
                self.upload_service_yaml()
            else:
                self.service_command_output.append("Please select a valid action for New Service.")

        elif self.update_radio.isChecked():
            # Handle the update functionality with existing service
            service_name = self.service_name_dropdown_update.currentText()
            if service_name == "Select Service to Update":
                self.service_command_output.append("Please select a valid service to update.")
                return
            self.update_service(service_name)

    def upload_service_yaml(self):
        """Upload a YAML file to create a new service."""
        file_name, _ = QFileDialog.getOpenFileName(self, "Open Service YAML", "", "YAML Files (*.yaml *.yml)")
        if file_name:
            try:
                v1 = self.get_k8s_api_client()
                if not v1:
                    return
                utils.create_from_yaml(v1.api_client, file_name)
                self.service_command_output.append(f"Service created from file: {file_name}")
            except Exception as e:
                self.service_command_output.append(f"Error uploading service YAML: {e}")

    def update_service(self, service_name):
        """Update the selected service."""
        # Retrieve the updated fields from the form
        namespace = self.namespace_dropdown.currentText()
        service_type = self.service_type_input.currentText()
        port = self.port_input.text()
        target_port = self.target_port_input.text()
        selector = self.selector_input.text()
        labels = self.labels_input.text()
        annotations = self.annotations_input.text()

        v1 = self.get_k8s_api_client()
        if not v1:
            return

        try:
            # Construct the update payload
            service_body = self.construct_service_body(service_name, service_type, port, target_port, selector, labels, annotations)
            v1.patch_namespaced_service(name=service_name, namespace=namespace, body=service_body)
            self.service_command_output.append(f"Service '{service_name}' updated successfully.")
        except Exception as e:
            self.service_command_output.append(f"Error updating service: {e}")

    


    def edit_service(self, namespace, service_name):
        """Load service YAML into the editor for editing."""
        if not service_name:
            self.service_command_output.append("Please enter a service name to edit.")
            QMessageBox.warning(self, "Warning", "Please enter a service name to edit.")
            return

        try:
            # Retrieve the Kubernetes API client
            v1 = self.get_k8s_api_client()

            # Retrieve the service as a dictionary
            svc = v1.read_namespaced_service(name=service_name, namespace=namespace).to_dict()

            # Filter out immutable fields to prevent update errors
            self.filter_immutable_fields_service(svc)

            # Convert the service definition to YAML
            pretty_yaml = yaml.dump(svc, sort_keys=False)

            # Create a dialog to edit the service YAML
            dialog = QDialog(self)
            dialog.setWindowTitle(f"Edit YAML for service '{service_name}'")
            dialog.resize(800, 600)
            dialog_layout = QVBoxLayout(dialog)

            # YAML editor
            yaml_editor = QTextEdit()
            yaml_editor.setPlainText(pretty_yaml)
            dialog_layout.addWidget(yaml_editor)

            # Save and cancel buttons
            button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            dialog_layout.addWidget(button_box)

            # Connect buttons to saving or canceling changes
            button_box.accepted.connect(lambda: self.save_service_changes(namespace, service_name, yaml_editor.toPlainText(), dialog))
            button_box.rejected.connect(dialog.reject)

            dialog.setLayout(dialog_layout)
            dialog.exec_()

        except ApiException as e:
            self.service_command_output.append(f"API error reading service: {e}")
            QMessageBox.critical(self, "Error", f"Failed to read service: {e}")
        except Exception as e:
            self.service_command_output.append(f"Error reading service: {e}")
            QMessageBox.critical(self, "Error", f"Failed to read service: {e}")

    def save_service_changes(self, namespace, service_name, new_yaml, dialog):
        """Save the changes made to the service YAML."""
        # Validate the YAML
        try:
            svc_definition = yaml.safe_load(new_yaml)
        except yaml.YAMLError as ye:
            QMessageBox.critical(self, "YAML Error", f"Invalid YAML format: {ye}")
            self.service_command_output.append(f"Invalid YAML format: {ye}")
            return

        try:
            # Retrieve the Kubernetes API client
            v1 = self.get_k8s_api_client()

            # Replace the service with the new definition
            v1.patch_namespaced_service(
                name=service_name,
                namespace=namespace,
                body=svc_definition
            )
            self.service_command_output.append(f"Service '{service_name}' updated successfully.")
            QMessageBox.information(self, "Success", f"Service '{service_name}' updated successfully.")
            dialog.accept()  # Close the editor dialog after saving changes
        except ApiException as e:
            self.service_command_output.append(f"Kubernetes API error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to update service YAML: {e}")
        except Exception as e:
            self.service_command_output.append(f"Error updating service YAML: {e}")
            QMessageBox.critical(self, "Error", f"Failed to update service YAML: {e}")

    def filter_immutable_fields_service(self, svc_dict):
        """Filter out immutable and non-updatable fields from the Service definition."""
        # Remove metadata fields that are immutable
        immutable_metadata_keys = [
            'creation_timestamp', 'deletion_grace_period_seconds', 'deletion_timestamp',
            'generate_name', 'managed_fields', 'resource_version', 'self_link',
            'uid', 'owner_references', 'annotations'
        ]
        for key in immutable_metadata_keys:
            svc_dict['metadata'].pop(key, None)

        # Remove status field entirely as it cannot be updated
        svc_dict.pop('status', None)

        # Remove any fields from spec that are immutable or non-updatable for a Service
        immutable_spec_keys = ['cluster_ip', 'clusterIPs', 'external_name']
        for key in immutable_spec_keys:
            svc_dict['spec'].pop(key, None)





    # def save_service_changes(self, service_name, namespace):
    #     """Save edited YAML back to the Kubernetes cluster."""
    #     context = self.context_option.currentText()
    #     yaml_content = self.yaml_editor.toPlainText()
    #     try:
    #         svc_definition = yaml.safe_load(yaml_content)
    #     except yaml.YAMLError as ye:
    #         self.service_command_output.append(f"Invalid YAML format: {ye}")
    #         QMessageBox.critical(self, "YAML Error", f"Invalid YAML format: {ye}")
    #         return

    #     try:
    #         configuration = client.Configuration.get_default_copy()
    #         configuration.verify_ssl = self.ssl_checkbox.isChecked()
    #         config.load_kube_config(config_file=self.kubeconfig_path, context=context)
    #         api_client = client.ApiClient(configuration)
    #         v1 = client.CoreV1Api(api_client)
    #         v1.replace_namespaced_service(name=service_name, namespace=namespace, body=svc_definition)
    #         self.service_command_output.append(f"Service '{service_name}' updated successfully with edited YAML.")
    #         QMessageBox.information(self, "Success", f"Service '{service_name}' updated successfully with edited YAML.")
    #     except ApiException as e:
    #         self.service_command_output.append(f"API error saving service changes: {e}")
    #         QMessageBox.critical(self, "Error", f"Failed to save service changes: {e}")
    #     except Exception as e:
    #         self.service_command_output.append(f"Error saving service changes: {e}")
    #         QMessageBox.critical(self, "Error", f"Failed to save service changes: {e}")
            
    def construct_service_body(self, service_name, service_type, port, target_port, selector, labels, annotations):
        """Construct the service body from the input form fields."""
        metadata = {
            'name': service_name,
            'labels': self.parse_key_value_pairs(labels),
            'annotations': self.parse_key_value_pairs(annotations)
        }
        spec = {
            'type': service_type,
            'ports': [{'port': int(port), 'targetPort': int(target_port)}],
            'selector': self.parse_key_value_pairs(selector)
        }
        return {'metadata': metadata, 'spec': spec}
    
    
    def parse_key_value_pairs(self, input_text):
        """Parse key-value pairs from text and return a dictionary."""
        if not input_text:
            return {}
        return dict(pair.split('=') for pair in input_text.split(','))

    # --------------------- Advanced Service Actions ---------------------

    def execute_advanced_service_action(self):
        """Execute actions from the Advanced Actions group."""
        action = self.advanced_action_option.currentText()
        service_name = self.service_name_input.text().strip()
        namespace = self.namespace_input.text().strip() or 'default'
        context = self.context_option.currentText()
        local_port = self.local_port_input.text().strip()
        service_port = self.service_port_input.text().strip()
        min_replicas = self.min_replicas_input.text().strip()
        max_replicas = self.max_replicas_input.text().strip()
        cpu_util = self.cpu_util_input.text().strip()

        if action == "Select Action":
            self.service_command_output.append("Please select a valid advanced service action.")
            QMessageBox.warning(self, "Warning", "Please select a valid advanced service action.")
            return

        # Load kubeconfig with selected context and SSL settings
        try:
            configuration = client.Configuration.get_default_copy()
            configuration.verify_ssl = self.ssl_checkbox.isChecked()
            config.load_kube_config(config_file=self.kubeconfig_path, context=context)
            api_client = client.ApiClient(configuration)
            v1 = client.CoreV1Api(api_client)
            autoscaling_v1 = client.AutoscalingV1Api(api_client)
        except Exception as e:
            self.service_command_output.append(f"Error loading kubeconfig: {e}")
            QMessageBox.critical(self, "Error", f"Failed to load kubeconfig: {e}")
            return

        # Dispatch to specific function based on selected action
        action_methods = {
            "Port Forward Service": self.port_forward_service,
            "Create Autoscaler": self.create_autoscaler,
            "Update Service Labels": self.update_service_labels,
            "Update Service Annotations": self.update_service_annotations,
            "Bulk Operations": self.bulk_operations
        }

        action_method = action_methods.get(action, None)
        if action_method:
            action_method(v1, autoscaling_v1, namespace, service_name,
                         local_port, service_port, min_replicas, max_replicas, cpu_util)
        else:
            self.service_command_output.append("Please select a valid advanced service action.")
            QMessageBox.warning(self, "Warning", "Please select a valid advanced service action.")

    def port_forward_service(self, v1, autoscaling_v1, namespace, service_name,
                             local_port, service_port, min_replicas, max_replicas, cpu_util):
        """Port forward a service from local machine to Kubernetes cluster."""
        if not service_name:
            self.service_command_output.append("Please enter a service name for port forwarding.")
            QMessageBox.warning(self, "Warning", "Please enter a service name for port forwarding.")
            return
        if not local_port or not service_port:
            self.service_command_output.append("Please enter both local and service ports.")
            QMessageBox.warning(self, "Warning", "Please enter both local and service ports.")
            return
        try:
            subprocess.Popen([
                'kubectl', 'port-forward', f'service/{service_name}',
                f'{local_port}:{service_port}', '-n', namespace, '--context', context
            ])
            self.service_command_output.append(f"Port forwarding established from local port {local_port} to service '{service_name}' on port {service_port}.")
            QMessageBox.information(self, "Success", f"Port forwarding established from local port {local_port} to service '{service_name}' on port {service_port}.")
        except Exception as e:
            self.service_command_output.append(f"Error establishing port forwarding: {e}")
            QMessageBox.critical(self, "Error", f"Failed to establish port forwarding: {e}")

    def create_autoscaler(self, v1, autoscaling_v1, namespace, service_name,
                          local_port, service_port, min_replicas, max_replicas, cpu_util):
        """Create a Horizontal Pod Autoscaler for a service."""
        if not service_name:
            self.service_command_output.append("Please enter a service name to create an autoscaler.")
            QMessageBox.warning(self, "Warning", "Please enter a service name to create an autoscaler.")
            return
        if not min_replicas or not max_replicas or not cpu_util:
            self.service_command_output.append("Please enter Min Replicas, Max Replicas, and CPU Utilization.")
            QMessageBox.warning(self, "Warning", "Please enter Min Replicas, Max Replicas, and CPU Utilization.")
            return
        try:
            min_replicas_int = int(min_replicas)
            max_replicas_int = int(max_replicas)
            cpu_util_int = int(cpu_util)
        except ValueError:
            self.service_command_output.append("Min Replicas, Max Replicas, and CPU Utilization must be integers.")
            QMessageBox.warning(self, "Warning", "Min Replicas, Max Replicas, and CPU Utilization must be integers.")
            return

        # Create Autoscaler manifest
        autoscaler_manifest = client.V1HorizontalPodAutoscaler(
            metadata=client.V1ObjectMeta(name=f"{service_name}-autoscaler"),
            spec=client.V1HorizontalPodAutoscalerSpec(
                scale_target_ref=client.V1CrossVersionObjectReference(
                    api_version="apps/v1",
                    kind="Deployment",  # Assuming service is associated with a Deployment
                    name=service_name
                ),
                min_replicas=min_replicas_int,
                max_replicas=max_replicas_int,
                target_cpu_utilization_percentage=cpu_util_int
            )
        )

        try:
            autoscaling_v1.create_namespaced_horizontal_pod_autoscaler(namespace=namespace, body=autoscaler_manifest)
            self.service_command_output.append(f"Autoscaler for service '{service_name}' created successfully.")
            QMessageBox.information(self, "Success", f"Autoscaler for service '{service_name}' created successfully.")
        except ApiException as e:
            self.service_command_output.append(f"API error creating autoscaler: {e}")
            QMessageBox.critical(self, "Error", f"Failed to create autoscaler: {e}")
        except Exception as e:
            self.service_command_output.append(f"Error creating autoscaler: {e}")
            QMessageBox.critical(self, "Error", f"Failed to create autoscaler: {e}")

    def update_service_labels(self, v1, autoscaling_v1, namespace, service_name,
                              local_port, service_port, min_replicas, max_replicas, cpu_util):
        """Update labels of an existing service."""
        if not service_name:
            self.service_command_output.append("Please enter a service name to update labels.")
            QMessageBox.warning(self, "Warning", "Please enter a service name to update labels.")
            return
        labels_text = self.labels_input.text().strip()
        if not labels_text:
            self.service_command_output.append("Please enter labels in key=value format.")
            QMessageBox.warning(self, "Warning", "Please enter labels in key=value format.")
            return
        try:
            labels = dict(item.split("=") for item in labels_text.split(","))
            patch_body = {'metadata': {'labels': labels}}
            v1.patch_namespaced_service(name=service_name, namespace=namespace, body=patch_body)
            self.service_command_output.append(f"Labels updated for service '{service_name}'.")
            QMessageBox.information(self, "Success", f"Labels updated for service '{service_name}'.")
        except ApiException as e:
            self.service_command_output.append(f"API error updating service labels: {e}")
            QMessageBox.critical(self, "Error", f"Failed to update service labels: {e}")
        except Exception as e:
            self.service_command_output.append(f"Error updating service labels: {e}")
            QMessageBox.critical(self, "Error", f"Failed to update service labels: {e}")

    def update_service_annotations(self, v1, autoscaling_v1, namespace, service_name,
                                   local_port, service_port, min_replicas, max_replicas, cpu_util):
        """Update annotations of an existing service."""
        if not service_name:
            self.service_command_output.append("Please enter a service name to update annotations.")
            QMessageBox.warning(self, "Warning", "Please enter a service name to update annotations.")
            return
        annotations_text = self.annotations_input.text().strip()
        if not annotations_text:
            self.service_command_output.append("Please enter annotations in key=value format.")
            QMessageBox.warning(self, "Warning", "Please enter annotations in key=value format.")
            return
        try:
            annotations = dict(item.split("=") for item in annotations_text.split(","))
            patch_body = {'metadata': {'annotations': annotations}}
            v1.patch_namespaced_service(name=service_name, namespace=namespace, body=patch_body)
            self.service_command_output.append(f"Annotations updated for service '{service_name}'.")
            QMessageBox.information(self, "Success", f"Annotations updated for service '{service_name}'.")
        except ApiException as e:
            self.service_command_output.append(f"API error updating service annotations: {e}")
            QMessageBox.critical(self, "Error", f"Failed to update service annotations: {e}")
        except Exception as e:
            self.service_command_output.append(f"Error updating service annotations: {e}")
            QMessageBox.critical(self, "Error", f"Failed to update service annotations: {e}")

    def bulk_operations(self, v1, autoscaling_v1, namespace, service_name,
                        local_port, service_port, min_replicas, max_replicas, cpu_util):
        """Placeholder for bulk operations logic."""
        self.service_command_output.append("Bulk operations are not implemented yet.")
        QMessageBox.information(self, "Info", "Bulk operations are not implemented yet.")



    # --------------------- Helper Functions ---------------------

    def command_output_append(self, text):
        """Append text to the service_command_output safely."""
        self.service_command_output.append(text)
