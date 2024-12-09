import json
import os
import subprocess
import threading
from datetime import datetime

import yaml
from kubernetes import client, config, utils
from kubernetes.client import ApiException
from PyQt5.QtCore import QObject, Qt, pyqtSignal
from PyQt5.QtGui import QIntValidator
from PyQt5.QtWidgets import (QCheckBox, QComboBox, QDialog, QDialogButtonBox,
                             QFileDialog, QGroupBox, QHBoxLayout, QInputDialog,
                             QLabel, QLineEdit, QMessageBox, QPushButton,
                             QRadioButton, QTextEdit, QVBoxLayout, QWidget)


class DeploymentManagementTab(QWidget):
    def __init__(self, auth_manager, main_tab_widget):
        super().__init__()
        self.auth_manager = auth_manager
        self.main_tab_widget = main_tab_widget
        self.kubeconfig_path = os.path.expanduser("~/.kube/config")
        self.initUI()

    def initUI(self):
        # Main layout
        main_layout = QHBoxLayout()

        # Left Column: Deployment Actions
        left_column = QVBoxLayout()

        # Group: Deployment Management
        deploy_group_box = QGroupBox("Deployment Management")
        deploy_layout = QVBoxLayout()

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
        deploy_layout.addLayout(ssl_context_layout)

        # Horizontal layout for Namespace and Deployment
        namespace_deployment_layout = QHBoxLayout()

        # Namespace Dropdown
        self.namespace_dropdown = QComboBox(self)
        self.namespace_dropdown.addItem("Select Namespace")
        self.namespace_dropdown.currentIndexChanged.connect(self.load_deployments)
        self.namespace_dropdown.setFixedWidth(200)  # Adjust the width as needed
        namespace_deployment_layout.addWidget(self.namespace_dropdown)

        # Deployment Name Dropdown
        self.deployment_name_dropdown = QComboBox(self)
        self.deployment_name_dropdown.addItem("Select Deployment")
        self.deployment_name_dropdown.setFixedWidth(200)  # Adjust the width as needed
        namespace_deployment_layout.addWidget(self.deployment_name_dropdown)
        
        # Label Selector Input
        self.label_selector_input = QLineEdit(self)
        self.label_selector_input.setPlaceholderText("Label Selector (key=value)")
        self.label_selector_input.setFixedWidth(150)
        namespace_deployment_layout.addWidget(QLabel("Label Filter:"))
        namespace_deployment_layout.addWidget(self.label_selector_input)

        # Add the horizontal layout to the general layout
        deploy_layout.addLayout(namespace_deployment_layout)

        # Horizontal layout for Action and Execute Button
        action_execute_layout = QHBoxLayout()

        # Action Combobox for Deployment Management
        self.deployment_action_option = QComboBox(self)
        self.deployment_action_option.addItems([
            "Select Action",
            "Deploy Deployment",
            "Edit Deployment",
            "Scale Deployment",
            "Rollout Deployment",
            "Filter Deployments",
            "Display Deployments",
            "Delete Deployment",
        ])
        self.deployment_action_option.setFixedWidth(200)  # Adjust the width as needed
        action_execute_layout.addWidget(self.deployment_action_option)

        # Execute Button for Deployment Actions
        self.deployment_execute_button = QPushButton("Execute")
        self.deployment_execute_button.clicked.connect(self.execute_deployment_action)
        action_execute_layout.addWidget(self.deployment_execute_button)

        # Add the horizontal layout to the general layout
        deploy_layout.addLayout(action_execute_layout)

        # Set layout for deployment group box and add to left column
        deploy_group_box.setLayout(deploy_layout)
        left_column.addWidget(deploy_group_box)

        # Right Column: Output, Editor, and Import JSON
        right_column = QVBoxLayout()

        # Output TextEdit
        self.deployment_command_output = QTextEdit(self)
        self.deployment_command_output.setReadOnly(True)
        right_column.addWidget(QLabel("Output:"))
        right_column.addWidget(self.deployment_command_output)

        # Add left and right columns to main layout
        main_layout.addLayout(left_column)
        main_layout.addLayout(right_column)

        self.setLayout(main_layout)
        self.load_kube_contexts()
        self.load_namespaces()

    def get_core_v1_client(self):
        """Helper to get a CoreV1Api client for namespace-related operations."""
        try:
            config_obj = client.Configuration()
            config.load_kube_config(
                context=self.context_selector.currentText(),
                client_configuration=config_obj
            )
            config_obj.verify_ssl = self.ssl_checkbox.isChecked()
            return client.CoreV1Api(client.ApiClient(config_obj))
        except Exception as e:
            self.deployment_command_output.append(f"Error loading Kubernetes CoreV1Api client: {e}")
            return None

    def get_apps_v1_client(self):
        """Helper to get an AppsV1Api client for deployment-related operations."""
        try:
            config_obj = client.Configuration()
            config.load_kube_config(
                context=self.context_selector.currentText(),
                client_configuration=config_obj
            )
            config_obj.verify_ssl = self.ssl_checkbox.isChecked()
            return client.AppsV1Api(client.ApiClient(config_obj))
        except Exception as e:
            self.deployment_command_output.append(f"Error loading Kubernetes AppsV1Api client: {e}")
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
            self.deployment_command_output.append(f"Error loading Kubernetes contexts: {e}")

    def load_namespaces(self):
        """Load namespaces and populate the namespace dropdown."""
        try:
            v1 = self.get_core_v1_client()
            if v1 is None:
                return

            namespaces = v1.list_namespace().items
            self.namespace_dropdown.clear()
            self.namespace_dropdown.addItem("Select Namespace")
            self.namespace_dropdown.addItems([ns.metadata.name for ns in namespaces])
        except Exception as e:
            self.deployment_command_output.append(f"Error loading namespaces: {e}")

            
    

    def load_deployments(self):
        """Load deployments based on the selected namespace."""
        selected_namespace = self.namespace_dropdown.currentText()
        if selected_namespace == "Select Namespace":
            self.deployment_command_output.append("Please select a valid namespace.")
            return

        try:
            v1 = self.get_apps_v1_client()
            if v1 is None:
                return

            # Fetch the deployments
            deployments = v1.list_namespaced_deployment(namespace=selected_namespace).items

            # Populate the deployment dropdown
            self.deployment_name_dropdown.clear()
            self.deployment_name_dropdown.addItem("Select Deployment")
            self.deployment_name_dropdown.addItems([dep.metadata.name for dep in deployments])
            
            # Display all deployments using the common display function
            self.display_deployments(deployments, selected_namespace)

        except ApiException as e:
            self.deployment_command_output.append(f"Kubernetes API error: {e.reason}")
        except Exception as e:
            self.deployment_command_output.append(f"Error loading deployments: {e}")



    def get_age(self, creation_timestamp):
        """Helper function to calculate the age of a deployment."""
        from datetime import datetime
        age = datetime.now() - creation_timestamp.replace(tzinfo=None)
        days = age.days
        hours, remainder = divmod(age.seconds, 3600)
        minutes, _ = divmod(remainder, 60)
        
        # Return age in a human-readable format (e.g., '5d2h' or '2h30m')
        if days > 0:
            return f"{days}d{hours}h"
        elif hours > 0:
            return f"{hours}h{minutes}m"
        else:
            return f"{minutes}m"

            
            
    
            
            
    #### DEPLOYMENT ACTIONS ####

    def execute_deployment_action(self):
        """Execute the selected deployment action based on dropdown choices."""
        action = self.deployment_action_option.currentText()
        deployment_name = self.deployment_name_dropdown.currentText()
        namespace = self.namespace_dropdown.currentText()

        # Validate selections
        if namespace == "Select Namespace":
            self.deployment_command_output.append("Please select a valid namespace.")
            return
        if action in ["Edit Deployment", "Delete Deployment"] and deployment_name == "Select Deployment":
            self.deployment_command_output.append("Please select a valid deployment.")
            return
        if action == "Select Action":
            self.deployment_command_output.append("Please select a valid deployment action.")
            return

        # Get the Kubernetes API client
        v1 = self.get_apps_v1_client()
        if not isinstance(v1, client.AppsV1Api):
            self.deployment_command_output.append("Error: Kubernetes API client is not properly initialized.")
            return  # No valid Kubernetes API client

        # Execute the action
        self.deployment_command_output.append(f"Executing action '{action}' for namespace '{namespace}'.")

        # Define the action methods
        action_methods = {
            "Deploy Deployment": self.deploy_deployment,
            "Edit Deployment": self.edit_deployment,
            "Delete Deployment": self.delete_deployment,
            "Filter Deployments": self.filter_deployments,
            "Display Deployments:": self.display_deployments,
            "Scale Deployment": self.scale_deployment,
            "Rollout Deployment": self.rollout_deployment,
        }

        action_method = action_methods.get(action)
        if action_method:
            action_method(v1, namespace, deployment_name)
        else:
            self.deployment_command_output.append("Please select a valid deployment action.")


    def deploy_deployment(self, v1, namespace, deployment_name):
        """Handle deployment creation logic."""
        # Prompt user for YAML file to deploy
        yaml_file, _ = QFileDialog.getOpenFileName(self, "Select Deployment YAML", "", "YAML Files (*.yaml);;All Files (*)")

        if not yaml_file:
            self.deployment_command_output.append("Deployment creation canceled. No YAML file selected.")
            return

        # Read YAML file content
        with open(yaml_file, 'r') as file:
            try:
                deployment_yaml = yaml.safe_load(file)
            except yaml.YAMLError as ye:
                self.deployment_command_output.append(f"Invalid YAML file: {ye}")
                return

        # Extract name from the YAML
        new_deployment_name = deployment_yaml.get('metadata', {}).get('name', None)
        if not new_deployment_name:
            self.deployment_command_output.append("Invalid YAML: Deployment name not found in metadata.")
            return

        try:
            # Check if deployment already exists in the specified namespace
            existing_deployment = v1.read_namespaced_deployment(name=new_deployment_name, namespace=namespace)

            # If it exists, prompt for update or create new
            reply = QMessageBox.question(
                self,
                "Deployment Exists",
                f"A deployment named '{new_deployment_name}' already exists in namespace '{namespace}'.\n"
                f"Do you want to update it or create a new one?",
                QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel,
                QMessageBox.Cancel
            )

            if reply == QMessageBox.Cancel:
                self.deployment_command_output.append("Deployment operation canceled.")
                return
            elif reply == QMessageBox.Yes:
                # Update the existing deployment
                try:
                    v1.patch_namespaced_deployment(name=new_deployment_name, namespace=namespace, body=deployment_yaml)
                    self.deployment_command_output.append(f"Deployment '{new_deployment_name}' updated successfully.")
                except ApiException as e:
                    self.deployment_command_output.append(f"Kubernetes API error while updating deployment: {e}")
            elif reply == QMessageBox.No:
                # Create a new deployment by prompting for a new name
                new_name, ok = QInputDialog.getText(self, 'New Deployment Name', 'Enter a new name for the deployment:')
                if not ok or not new_name.strip():
                    self.deployment_command_output.append("Deployment creation canceled.")
                    return
                new_name = new_name.strip()

                # Update the deployment name in YAML
                deployment_yaml['metadata']['name'] = new_name

                # Apply the new deployment
                try:
                    utils.create_from_yaml(client.ApiClient(), yaml_objects=[deployment_yaml], namespace=namespace)
                    self.deployment_command_output.append(f"New deployment '{new_name}' created successfully.")
                except ApiException as e:
                    self.deployment_command_output.append(f"Kubernetes API error while creating deployment: {e}")

        except ApiException as e:
            if e.status == 404:
                # If deployment does not exist, create a new one
                try:
                    utils.create_from_yaml(client.ApiClient(), yaml_objects=[deployment_yaml], namespace=namespace)
                    self.deployment_command_output.append(f"Deployment '{new_deployment_name}' created successfully.")
                except ApiException as e:
                    self.deployment_command_output.append(f"Kubernetes API error while creating deployment: {e}")
            else:
                self.deployment_command_output.append(f"Kubernetes API error while checking for existing deployment: {e}")


    def edit_deployment(self, v1, namespace, deployment_name):
        """Handle editing a deployment's YAML definition."""
        if deployment_name == "Select Deployment":
            self.deployment_command_output.append("Please select a valid deployment to edit.")
            return

        try:
            # Retrieve the deployment
            deployment = v1.read_namespaced_deployment(name=deployment_name, namespace=namespace)
            
            # Convert the deployment to a dictionary and filter out immutable fields
            deployment_dict = deployment.to_dict()
            self.filter_immutable_fields(deployment_dict)
            
            # Convert the modified dictionary to YAML format
            deployment_yaml = yaml.dump(deployment_dict, default_flow_style=False)

            # Open a dialog with a text editor to modify the YAML
            dialog = QDialog(self)
            dialog.setWindowTitle(f"Edit YAML for Deployment {deployment_name}")
            dialog.resize(800, 600)
            dialog_layout = QVBoxLayout(dialog)

            yaml_editor = QTextEdit()
            yaml_editor.setPlainText(deployment_yaml)
            dialog_layout.addWidget(yaml_editor)

            button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            dialog_layout.addWidget(button_box)

            button_box.accepted.connect(dialog.accept)
            button_box.rejected.connect(dialog.reject)

            if dialog.exec_() == QDialog.Accepted:
                new_deployment_yaml = yaml_editor.toPlainText()
                # Validate YAML
                try:
                    deployment_definition = yaml.safe_load(new_deployment_yaml)
                except yaml.YAMLError as ye:
                    QMessageBox.critical(self, "YAML Error", f"Invalid YAML format: {ye}")
                    self.deployment_command_output.append(f"Invalid YAML format: {ye}")
                    return
                
                # Convert back to JSON to ensure proper formatting
                deployment_json = json.loads(json.dumps(deployment_definition))
                
                # Replace the deployment
                try:
                    # Patch the Deployment instead of replacing it to avoid altering immutable fields
                    v1.patch_namespaced_deployment(
                        name=deployment_name,
                        namespace=namespace,
                        body=deployment_json
                    )
                    self.deployment_command_output.append(f"Deployment '{deployment_name}' updated successfully.")
                    QMessageBox.information(self, "Success", f"Deployment '{deployment_name}' updated successfully.")
                    # Refresh the deployment list
                    self.load_deployments()
                except ApiException as e:
                    self.deployment_command_output.append(f"Kubernetes API error: {e}")
                    QMessageBox.critical(self, "Error", f"Failed to update deployment YAML: {e}")
                except Exception as e:
                    self.deployment_command_output.append(f"Error updating deployment YAML: {e}")
                    QMessageBox.critical(self, "Error", f"Failed to update deployment YAML: {e}")
            else:
                self.deployment_command_output.append("Deployment editing cancelled.")

        except ApiException as e:
            self.deployment_command_output.append(f"Kubernetes API error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to retrieve deployment YAML: {e}")
        except Exception as e:
            self.deployment_command_output.append(f"Error retrieving deployment YAML: {e}")
            QMessageBox.critical(self, "Error", f"Failed to retrieve deployment YAML: {e}")

    def filter_immutable_fields(self, resource_dict):
        """Filter out immutable and non-updatable fields from the resource definition."""
        # Remove metadata fields that are immutable
        immutable_metadata_keys = [
            'creation_timestamp', 'deletion_grace_period_seconds', 'deletion_timestamp',
            'generate_name', 'managed_fields', 'resource_version', 'self_link',
            'uid', 'owner_references', 'annotations'
        ]
        for key in immutable_metadata_keys:
            resource_dict['metadata'].pop(key, None)
        
        # Remove status field entirely as it cannot be updated
        resource_dict.pop('status', None)
        
        # Remove immutable fields from spec for deployments
        immutable_spec_keys = ['service_account', 'service_account_name', 'node_name', 'volumes', 'restart_policy']
        for key in immutable_spec_keys:
            resource_dict['spec'].pop(key, None)

        # Remove fields from containers within spec that are not updatable
        if 'containers' in resource_dict['spec']['template']['spec']:
            for container in resource_dict['spec']['template']['spec']['containers']:
                # Correct the ports structure
                if 'ports' in container:
                    for port in container['ports']:
                        # Ensure correct key naming
                        if 'container_port' in port:
                            port['containerPort'] = port.pop('container_port')
                        # Remove unnecessary fields
                        port.pop('host_ip', None)
                        port.pop('host_port', None)
                        port.pop('name', None)
                # Remove other fields that are not updatable
                for key in ['volume_mounts', 'liveness_probe', 'readiness_probe', 'env_from', 'resources']:
                    container.pop(key, None)

    # Additional adjustments for init containers or volume mounts if needed

        # Additional adjustments for specific container attributes, init containers, or volume mounts can be added as required.

        
    def filter_deployments(self, v1, namespace, deployment_name=None):
        """Filter deployments based on label selector."""
        label_selector = self.label_selector_input.text().strip()
        
        if not label_selector:
            self.deployment_command_output.append("Please enter a valid label selector to filter deployments.")
            return

        try:
            # Fetch the deployments with the label selector
            self.deployment_command_output.append(f"Filtering deployments for namespace: {namespace} with label: '{label_selector}'")
            deployments = v1.list_namespaced_deployment(namespace=namespace, label_selector=label_selector).items

            # Display filtered deployments
            if deployments:
                self.display_deployments(deployments, namespace)
            else:
                self.deployment_command_output.append(f"No deployments found with label selector '{label_selector}' in namespace '{namespace}'.")

        except ApiException as e:
            self.deployment_command_output.append(f"Kubernetes API error: {e.reason}")
        except Exception as e:
            self.deployment_command_output.append(f"Error filtering deployments: {e}")
            
    def scale_deployment(self, v1, namespace, deployment_name):
        """Open a dialog to scale the deployment with multiple options."""
        if deployment_name == "Select Deployment":
            self.deployment_command_output.append("Please select a valid deployment to scale.")
            return

        # Open dialog to select scaling options
        scale_dialog = QDialog(self)
        scale_dialog.setWindowTitle("Scale Deployment")

        # Layout for the dialog
        dialog_layout = QVBoxLayout()

        # Scaling option: Replicas
        self.scale_replicas_checkbox = QCheckBox("Replicas")
        self.scale_replicas_input = QLineEdit()
        self.scale_replicas_input.setPlaceholderText("Enter new replicas")
        self.scale_replicas_input.setValidator(QIntValidator(1, 1000))  # Validate as integer input
        self.scale_replicas_input.setEnabled(False)  # Disable input by default
        self.scale_replicas_checkbox.stateChanged.connect(lambda: self.toggle_input(self.scale_replicas_checkbox, self.scale_replicas_input))

        # Scaling option: Record
        self.scale_record_checkbox = QCheckBox("Record Changes")
        self.scale_record_checkbox.setToolTip("Record the changes for audit logs")

        # Add checkboxes and inputs to the layout
        dialog_layout.addWidget(self.scale_replicas_checkbox)
        dialog_layout.addWidget(self.scale_replicas_input)
        dialog_layout.addWidget(self.scale_record_checkbox)

        # Buttons for dialog
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(lambda: self.apply_scaling(v1, namespace, deployment_name, scale_dialog))
        button_box.rejected.connect(scale_dialog.reject)
        dialog_layout.addWidget(button_box)

        # Set layout and show dialog
        scale_dialog.setLayout(dialog_layout)
        scale_dialog.exec_()

    def toggle_input(self, checkbox, input_field):
        """Enable or disable input fields based on checkbox state."""
        input_field.setEnabled(checkbox.isChecked())

        
        
    def apply_scaling(self, v1, namespace, deployment_name, dialog):
        """Apply the scaling operation based on the user's input."""
        scale_params = {}

        # Handle replicas scaling
        if self.scale_replicas_checkbox.isChecked():
            scale_value = self.scale_replicas_input.text().strip()
            if not scale_value.isdigit():
                self.deployment_command_output.append("Please enter a valid number for replicas.")
                return
            scale_params["replicas"] = int(scale_value)

        # Handle recording changes
        record_changes = self.scale_record_checkbox.isChecked()

        # Check if at least one option is selected
        if not scale_params and not record_changes:
            self.deployment_command_output.append("Please select at least one scaling option to apply.")
            return

        try:
            if "replicas" in scale_params:
                # Scale the deployment by setting the replicas
                body = {"spec": {"replicas": scale_params["replicas"]}}
                v1.patch_namespaced_deployment_scale(
                    name=deployment_name,
                    namespace=namespace,
                    body=body
                )
                self.deployment_command_output.append(f"Deployment '{deployment_name}' scaled to {scale_params['replicas']} replicas successfully.")
            
            if record_changes:
                # Record changes (as an example, you might want to log the change or send it to an audit log)
                self.deployment_command_output.append(f"Recording changes for deployment '{deployment_name}'.")

        except ApiException as e:
            self.deployment_command_output.append(f"Kubernetes API error during scaling: {e.reason}")
        except Exception as e:
            self.deployment_command_output.append(f"Error scaling deployment: {e}")

        # Close the dialog after applying scaling
        dialog.accept()




            
    def display_deployments(self, deployments, namespace, label_selector=None):
        """Display the list of deployments in a table format based on namespace or label filtering."""
        # Clear the output and add a header
        self.deployment_command_output.clear()
        
        # Display header message
        if label_selector:
            self.deployment_command_output.append(f"Deployments in namespace '{namespace}' with label selector '{label_selector}':\n")
        else:
            self.deployment_command_output.append(f"Deployments in namespace '{namespace}':\n")
        
        # Table header
        table_header = f"{'NAME':<20}{'READY':<10}{'UP-TO-DATE':<15}{'AVAILABLE':<10}{'AGE':<10}"
        self.deployment_command_output.append(table_header)
        self.deployment_command_output.append("-" * len(table_header))
        
        # Format and display each deployment's details
        for dep in deployments:
            name = dep.metadata.name
            ready_replicas = f"{dep.status.ready_replicas or 0}/{dep.spec.replicas or 0}"
            up_to_date = dep.status.updated_replicas or 0
            available = dep.status.available_replicas or 0
            age = self.get_age(dep.metadata.creation_timestamp)

            # Add the formatted deployment details to the output
            self.deployment_command_output.append(
                f"{name:<20}{ready_replicas:<10}{up_to_date:<15}{available:<10}{age:<10}"
            )



    def delete_deployment(self, v1, namespace, deployment_name):
        """Handle deployment deletion logic."""
        try:
            v1.delete_namespaced_deployment(name=deployment_name, namespace=namespace)
            self.deployment_command_output.append(f"Deployment '{deployment_name}' deleted successfully.")
        except Exception as e:
            self.deployment_command_output.append(f"Error deleting deployment: {e}")
            
    def rollout_deployment(self, v1, namespace, deployment_name):
        """Open a dialog to select a rollout action for the deployment."""
        if deployment_name == "Select Deployment":
            self.deployment_command_output.append("Please select a valid deployment for rollout actions.")
            return

        # Open a dialog for rollout options
        rollout_dialog = QDialog(self)
        rollout_dialog.setWindowTitle("Rollout Deployment")

        # Layout for the dialog
        dialog_layout = QVBoxLayout()

        # Rollout Option Dropdown
        self.rollout_option_dropdown = QComboBox(self)
        self.rollout_option_dropdown.addItems([
            "Select Rollout Action",
            "History",
            "Pause",
            "Restart",
            "Resume",
            "Status",
            "Undo"
        ])
        dialog_layout.addWidget(QLabel("Select Rollout Action:"))
        dialog_layout.addWidget(self.rollout_option_dropdown)

        # Execute button for the rollout action
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(lambda: self.execute_rollout_action(v1, namespace, deployment_name, rollout_dialog))
        button_box.rejected.connect(rollout_dialog.reject)
        dialog_layout.addWidget(button_box)

        # Set layout and show dialog
        rollout_dialog.setLayout(dialog_layout)
        rollout_dialog.exec_()
        
    def execute_rollout_action(self, v1, namespace, deployment_name, dialog):
        rollout_action = self.rollout_option_dropdown.currentText()

        if rollout_action == "Select Rollout Action":
            self.deployment_command_output.append("Please select a valid rollout action.")
            return

        try:
            if rollout_action == "History":
                self.rollout_history(namespace, deployment_name)  # Remove `v1` as a parameter
            elif rollout_action == "Pause":
                self.rollout_pause(v1, namespace, deployment_name)
            elif rollout_action == "Restart":
                self.rollout_restart(v1, namespace, deployment_name)
            elif rollout_action == "Resume":
                self.rollout_resume(v1, namespace, deployment_name)
            elif rollout_action == "Status":
                self.rollout_status(v1, namespace, deployment_name)
            elif rollout_action == "Undo":
                self.rollout_undo(v1, namespace, deployment_name)

            dialog.accept()
        except Exception as e:
            self.deployment_command_output.append(f"Error executing rollout action '{rollout_action}': {e}")


        
        
    def rollout_history(self, namespace, deployment_name):
        """Show rollout history of a deployment."""
        try:
            v1 = self.get_apps_v1_client()
            if not v1:
                self.deployment_command_output.append("Failed to initialize Kubernetes API client.")
                return

            # Retrieve the deployment
            deployment = v1.read_namespaced_deployment(name=deployment_name, namespace=namespace)

            # Check for annotations and handle cases where they may be None
            revision_annotation = deployment.metadata.annotations or {}
            template_annotation = deployment.spec.template.metadata.annotations or {}

            # Extract revision and change-cause
            revision = revision_annotation.get("deployment.kubernetes.io/revision", "N/A")
            change_cause = template_annotation.get("kubernetes.io/change-cause", "N/A")

            # Display the revision and change-cause information
            self.deployment_command_output.append(f"Rollout history for '{deployment_name}':")
            self.deployment_command_output.append(f"Revision: {revision}")
            self.deployment_command_output.append(f"Cause: {change_cause}")

        except ApiException as e:
            self.deployment_command_output.append(f"Kubernetes API error: {e.reason}")
        except Exception as e:
            self.deployment_command_output.append(f"Error fetching rollout history: {e}")






    def rollout_pause(self, v1, namespace, deployment_name):
        """Pause the rollout of a deployment."""
        try:
            patch_body = {"spec": {"paused": True}}
            v1.patch_namespaced_deployment(name=deployment_name, namespace=namespace, body=patch_body)
            self.deployment_command_output.append(f"Paused rollout for '{deployment_name}' in namespace '{namespace}'.")
        except Exception as e:
            self.deployment_command_output.append(f"Error pausing rollout: {e}")

    def rollout_restart(self, v1, namespace, deployment_name):
        """Restart the rollout of a deployment."""
        try:
            patch_body = {"spec": {"template": {"metadata": {"annotations": {"kubectl.kubernetes.io/restartedAt": datetime.utcnow().isoformat()}}}}}
            v1.patch_namespaced_deployment(name=deployment_name, namespace=namespace, body=patch_body)
            self.deployment_command_output.append(f"Restarted rollout for '{deployment_name}' in namespace '{namespace}'.")
        except Exception as e:
            self.deployment_command_output.append(f"Error restarting rollout: {e}")

    def rollout_resume(self, v1, namespace, deployment_name):
        """Resume the rollout of a paused deployment."""
        try:
            patch_body = {"spec": {"paused": False}}
            v1.patch_namespaced_deployment(name=deployment_name, namespace=namespace, body=patch_body)
            self.deployment_command_output.append(f"Resumed rollout for '{deployment_name}' in namespace '{namespace}'.")
        except Exception as e:
            self.deployment_command_output.append(f"Error resuming rollout: {e}")

    def rollout_status(self, v1, namespace, deployment_name):
        """Check the status of the rollout of a deployment."""
        try:
            deployment = v1.read_namespaced_deployment_status(name=deployment_name, namespace=namespace)
            status = deployment.status
            available_replicas = status.available_replicas or 0
            ready_replicas = status.ready_replicas or 0
            updated_replicas = status.updated_replicas or 0
            replicas = status.replicas or 0
            
            status_info = f"""
            Deployment Status for '{deployment_name}':
            - Replicas: {replicas}
            - Updated Replicas: {updated_replicas}
            - Ready Replicas: {ready_replicas}
            - Available Replicas: {available_replicas}
            """
            self.deployment_command_output.append(status_info)
        except Exception as e:
            self.deployment_command_output.append(f"Error fetching rollout status: {e}")

    def rollout_undo(self, v1, namespace, deployment_name):
        """Undo the last rollout of a deployment."""
        try:
            deployment = v1.read_namespaced_deployment(name=deployment_name, namespace=namespace)
            current_revision = deployment.metadata.annotations.get("deployment.kubernetes.io/revision", None)
            if current_revision is not None:
                patch_body = {"spec": {"rollbackTo": {"revision": int(current_revision) - 1}}}
                v1.patch_namespaced_deployment(name=deployment_name, namespace=namespace, body=patch_body)
                self.deployment_command_output.append(f"Rolled back '{deployment_name}' to revision {int(current_revision) - 1} successfully.")
            else:
                self.deployment_command_output.append("No previous revision found to undo.")
        except Exception as e:
            self.deployment_command_output.append(f"Error undoing rollout: {e}")


