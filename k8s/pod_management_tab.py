import json
import os
import subprocess
import threading

import yaml
from kubernetes import client, config, stream, utils, watch
from kubernetes.client.exceptions import ApiException
from PyQt5.QtCore import Q_ARG, QMetaObject, QObject, Qt, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QIntValidator
from PyQt5.QtWidgets import (QCheckBox, QComboBox, QDialog, QDialogButtonBox,
                             QFileDialog, QHBoxLayout, QLabel, QLineEdit,
                             QMessageBox, QPushButton, QTabWidget, QTextEdit,
                             QVBoxLayout, QWidget)


class WorkerSignals(QObject):
    log_signal = pyqtSignal(str)
    finished = pyqtSignal()


class ClusterManagementTab(QWidget):
    def __init__(self, auth_manager, main_tab_widget):
        super().__init__()
        self.auth_manager = auth_manager
        self.main_tab_widget = main_tab_widget
        self.kubeconfig_path = os.path.expanduser("~/.kube/config")
        self.initUI()

    def initUI(self):
        # Two-column layout
        main_layout = QHBoxLayout()

        # Left column
        left_column = QVBoxLayout()

        # Right column: Output
        right_column = QVBoxLayout()
        self.command_output = QTextEdit(self)
        self.command_output.setReadOnly(True)
        self.command_output.setToolTip("Displays output and logs.")
        right_column.addWidget(QLabel("Output:"))
        right_column.addWidget(self.command_output)

        # Context Selection ComboBox
        self.context_selector = QComboBox(self)
        self.load_kubeconfig_contexts()
        left_column.addWidget(QLabel("Select Kubernetes Context:"))
        left_column.addWidget(self.context_selector)

        # SSL Verification Checkbox
        self.ssl_checkbox = QCheckBox("Enable SSL Verification")
        self.ssl_checkbox.setChecked(False)  # Default unchecked (SSL verification disabled)
        self.ssl_checkbox.setToolTip("Enable/disable SSL certificate verification.")
        self.ssl_checkbox.stateChanged.connect(self.load_kubeconfig_contexts)
        left_column.addWidget(self.ssl_checkbox)

        # Switch Context Button
        self.switch_context_button = QPushButton("Switch Context")
        self.switch_context_button.clicked.connect(self.switch_kube_context)
        left_column.addWidget(self.switch_context_button)

        # Reload Kubeconfig Button
        self.reload_button = QPushButton("Reload Kubeconfig")
        self.reload_button.clicked.connect(self.load_kubeconfig_contexts)
        left_column.addWidget(self.reload_button)

        # Management Actions Dropdown
        left_column.addWidget(QLabel("Select Management Action:"))
        self.action_selector = QComboBox()
        self.action_selector.addItems(["Select Action", "Deploy Resource", "Destroy Resource", "Edit Resource"])
        left_column.addWidget(self.action_selector)

        # Execute Button
        self.execute_button = QPushButton("Execute")
        self.execute_button.clicked.connect(self.execute_action)
        left_column.addWidget(self.execute_button)

        # Add left and right columns to the main layout
        main_layout.addLayout(left_column)
        main_layout.addLayout(right_column)

        # Set the layout for this subtab
        self.setLayout(main_layout)

    def load_kubeconfig_contexts(self):
        """Load contexts from the kubeconfig file, respecting SSL verification."""
        self.context_selector.clear()
        try:
            # Create a new Configuration object
            config_obj = client.Configuration()
            config.load_kube_config(
                config_file=self.kubeconfig_path,
                context=self.context_selector.currentText() if self.context_selector.currentText() else None,
                client_configuration=config_obj
            )
            # Set SSL verification based on the checkbox
            config_obj.verify_ssl = self.ssl_checkbox.isChecked()

            # Initialize CoreV1Api with the updated configuration
            v1 = client.CoreV1Api(client.ApiClient(config_obj))

            # Load contexts from kubeconfig
            with open(self.kubeconfig_path, 'r') as kubeconfig_file:
                kubeconfig = yaml.safe_load(kubeconfig_file)
                contexts = [context['name'] for context in kubeconfig.get('contexts', [])]
                self.context_selector.addItems(contexts)
                self.command_output.append(f"Loaded {len(contexts)} contexts from {self.kubeconfig_path}")

        except FileNotFoundError:
            self.command_output.append(f"Kubeconfig file not found at {self.kubeconfig_path}.")
        except ApiException as e:
            self.command_output.append(f"Kubernetes API error: {e}")
        except Exception as e:
            self.command_output.append(f"Error loading kubeconfig: {str(e)}")

    def switch_kube_context(self):
        """Switch to the selected Kubernetes context."""
        selected_context = self.context_selector.currentText()
        if selected_context:
            try:
                # Create a new Configuration object
                config_obj = client.Configuration()
                config.load_kube_config(
                    config_file=self.kubeconfig_path,
                    context=selected_context,
                    client_configuration=config_obj
                )
                # Set SSL verification based on the checkbox
                config_obj.verify_ssl = self.ssl_checkbox.isChecked()

                # Apply the new configuration
                client.Configuration.set_default(config_obj)
                self.command_output.append(f"Switched to context: {selected_context}")

            except ApiException as e:
                self.command_output.append(f"Kubernetes API error: {e}")
                QMessageBox.critical(self, "Error", f"Failed to switch context: {e}")
            except Exception as e:
                self.command_output.append(f"Error switching context: {e}")
                QMessageBox.critical(self, "Error", f"Failed to switch context: {e}")
        else:
            self.command_output.append("No context selected.")


class PodManagementTab(QWidget):
    # Signal to update the UI from the thread
    append_output_signal = pyqtSignal(str)
    
    def __init__(self, auth_manager, main_tab_widget):
        super().__init__()
        self.auth_manager = auth_manager
        self.main_tab_widget = main_tab_widget
        self.append_output_signal.connect(self.append_output)
        self.initUI()

    def initUI(self):
        # Main layout
        main_layout = QVBoxLayout()

        # Context Display and Selection
        context_layout = QHBoxLayout()
        context_label = QLabel("Current Context:")
        self.current_context_label = QLabel()
        context_layout.addWidget(context_label)
        context_layout.addWidget(self.current_context_label)
        context_layout.addStretch()
        
        # SSL Verification Checkbox
        self.ssl_verify_checkbox = QCheckBox("Verify SSL")
        self.ssl_verify_checkbox.setChecked(False)  # Default to unchecked (no SSL verification)
        self.ssl_verify_checkbox.setToolTip("Enable/disable SSL certificate verification.")
        self.ssl_verify_checkbox.stateChanged.connect(self.load_namespaces)
        context_layout.addWidget(self.ssl_verify_checkbox)

        # Context Selection ComboBox
        try:
            contexts, active_context = config.list_kube_config_contexts()
            self.context_option = QComboBox(self)
            self.context_option.addItems([ctx['name'] for ctx in contexts])
            if active_context:
                self.context_option.setCurrentText(active_context['name'])
            self.context_option.setToolTip("Select the Kubernetes context to use.")
            context_layout.addWidget(QLabel("Switch Context:"))
            context_layout.addWidget(self.context_option)
        except Exception as e:
            self.context_option = QComboBox(self)
            self.context_option.addItem("Error loading contexts")
            self.context_option.setToolTip("Error loading contexts.")
            context_layout.addWidget(QLabel("Switch Context:"))
            context_layout.addWidget(self.context_option)
            self.current_context_label.setText("Unavailable")
            QMessageBox.critical(self, "Error", f"Failed to load Kubernetes contexts: {e}")

        # Update the current context label
        self.current_context_label.setText(self.context_option.currentText())

        # Connect context change signal
        self.context_option.currentTextChanged.connect(self.change_context)

        main_layout.addLayout(context_layout)

        # Create the main content layout
        content_layout = QHBoxLayout()

        # Right Column: Output
        right_column = QVBoxLayout()
        self.pod_command_output = QTextEdit(self)
        self.pod_command_output.setReadOnly(True)
        self.pod_command_output.setToolTip("Displays output and logs.")
        right_column.addWidget(QLabel("Output:"))
        right_column.addWidget(self.pod_command_output)

        # Left Column: Pod Actions (using tabs to organize sections)
        left_column = QVBoxLayout()
        self.tabs = QTabWidget()

        # General Pod Actions Tab
        self.general_tab = QWidget()
        self.init_general_tab()
        self.tabs.addTab(self.general_tab, "General Actions")

        # Pod Monitoring and Logs Tab
        self.monitoring_tab = QWidget()
        self.init_monitoring_tab()
        self.tabs.addTab(self.monitoring_tab, "Monitoring & Logs")

        # Advanced Pod Actions Tab
        self.advanced_tab = QWidget()
        self.init_advanced_tab()
        self.tabs.addTab(self.advanced_tab, "Advanced Actions")

        left_column.addWidget(self.tabs)

        # Add left and right columns to the content layout
        content_layout.addLayout(left_column)
        content_layout.addLayout(right_column)

        # Add the content layout to the main layout
        main_layout.addLayout(content_layout)

        # Set the layout for this subtab
        self.setLayout(main_layout)

        # Initialize the UI components
        self.load_namespaces()

        # Hide optional inputs initially
        self.update_input_visibility()

        # Connect action selection changes to update input visibility
        self.pod_action_option.currentTextChanged.connect(self.update_input_visibility)
        self.pod_log_action_option.currentTextChanged.connect(self.update_input_visibility)
        self.advanced_pod_action_option.currentTextChanged.connect(self.update_input_visibility)
        self.namespace_option.currentTextChanged.connect(self.load_pods_in_namespace)

    def get_api_client(self):
        """Helper method to get an ApiClient with SSL settings based on the checkbox."""
        try:
            config_obj = client.Configuration()
            config.load_kube_config(
                context=self.context_option.currentText(),
                client_configuration=config_obj
            )
            config_obj.verify_ssl = self.ssl_verify_checkbox.isChecked()
            return client.ApiClient(config_obj)
        except Exception as e:
            self.pod_command_output.append(f"Error loading API client: {e}")
            QMessageBox.critical(self, "Error", f"Failed to load API client: {e}")
            return None
        
    @pyqtSlot(str)
    def append_output(self, output):
        """Append output to the text edit."""
        self.pod_command_output.append(output)


    def change_context(self):
        new_context = self.context_option.currentText()
        self.current_context_label.setText(new_context)
        self.pod_command_output.append(f"Switching to context '{new_context}'...")
        
        # Reload the Kubernetes configuration with the new context
        try:
            config.load_kube_config(context=new_context)
            self.pod_command_output.append(f"Switched to context '{new_context}'.")
            
            # Reload namespaces and pods
            self.load_namespaces()
        except Exception as e:
            self.pod_command_output.append(f"Error changing context: {e}")
            QMessageBox.critical(self, "Error", f"Failed to switch context: {e}")

    def init_general_tab(self):
        general_layout = QVBoxLayout()

        # Namespace Selection (Dropdown)
        self.namespace_option = QComboBox(self)
        self.namespace_option.setToolTip("Select the Kubernetes namespace.")
        general_layout.addWidget(QLabel("Namespace:"))
        general_layout.addWidget(self.namespace_option)

        # Pod Name Selection (Dropdown)
        self.pod_name_option = QComboBox(self)
        self.pod_name_option.setToolTip("Select the pod.")
        general_layout.addWidget(QLabel("Pod Name:"))
        general_layout.addWidget(self.pod_name_option)

        # Label Selector Input
        self.label_selector_input = QLineEdit(self)
        self.label_selector_input.setPlaceholderText("Enter Label Selector (key=value)")
        self.label_selector_input.setToolTip("Filter pods using label selectors.")
        general_layout.addWidget(QLabel("Label Selector:"))
        general_layout.addWidget(self.label_selector_input)

        # Command Input for Exec into Pod
        self.command_input = QLineEdit(self)
        self.command_input.setPlaceholderText("Enter command to execute")
        self.command_input.setToolTip("Type a command to send to the pod session.")
        self.command_input.returnPressed.connect(self.send_command_to_pod)
        self.command_input.hide()  # Hide by default, shown only when session is active
        general_layout.addWidget(QLabel("Command to Pod (Exec Mode):"))
        general_layout.addWidget(self.command_input)
        
        
        # Button to send command to the pod
        self.send_command_button = QPushButton("Send Command")
        self.send_command_button.setToolTip("Send the entered command to the pod.")
        self.send_command_button.clicked.connect(self.send_command_to_pod)
        general_layout.addWidget(self.send_command_button)
        self.send_command_button.hide()  # Hide initially until a session is started
        
        
        

        # Pod Action Combobox
        self.pod_action_option = QComboBox(self)
        self.pod_action_option.addItems([
            "Select Action",
            "Create Pod", 
            "List Pods",
            "Describe Pod",
            "Delete Pod",
            "Restart Pod",
            "Exec into Pod",
            "Update Pod Labels",
            "Update Pod Annotations",
            "Get Pod Events",
            "View Health Checks",
            "Edit Pod YAML"
        ])
        self.pod_action_option.setToolTip("Select a pod action to perform.")
        general_layout.addWidget(QLabel("Pod Action:"))
        general_layout.addWidget(self.pod_action_option)

        # Execute Button
        self.pod_action_button = QPushButton("Execute")
        self.pod_action_button.clicked.connect(self.execute_pod_action)
        self.pod_action_button.setToolTip("Click to execute the selected pod action.")
        general_layout.addWidget(self.pod_action_button)

        self.general_tab.setLayout(general_layout)

    def init_monitoring_tab(self):
        monitoring_layout = QVBoxLayout()

        # Pod Log Action Combobox
        self.pod_log_action_option = QComboBox(self)
        self.pod_log_action_option.addItems([
            "Select Action",
            "View Pod Logs",
            "Stream Pod Logs",
            "Get Pod Metrics"
        ])
        self.pod_log_action_option.setToolTip("Select a pod log action to perform.")
        monitoring_layout.addWidget(QLabel("Monitoring Action:"))
        monitoring_layout.addWidget(self.pod_log_action_option)

        # Container Name and Tail Lines Inputs on a Single Line
        container_tail_layout = QHBoxLayout()

        # Container Name Input
        container_label = QLabel("Container:")
        container_label.setFixedWidth(70)
        self.container_name_input = QLineEdit(self)
        self.container_name_input.setPlaceholderText("Container Name")
        self.container_name_input.setFixedWidth(150)
        self.container_name_input.setToolTip("Specify the container name if the pod has multiple containers.")
        container_tail_layout.addWidget(container_label)
        container_tail_layout.addWidget(self.container_name_input)

        # Tail Lines Input
        tail_lines_label = QLabel("Tail Lines:")
        tail_lines_label.setFixedWidth(70)
        self.tail_lines_input = QLineEdit(self)
        self.tail_lines_input.setPlaceholderText("Lines")
        self.tail_lines_input.setFixedWidth(50)
        self.tail_lines_input.setValidator(QIntValidator(1, 10000))
        self.tail_lines_input.setToolTip("Specify the number of lines from the end of the logs to show.")
        container_tail_layout.addWidget(tail_lines_label)
        container_tail_layout.addWidget(self.tail_lines_input)

        monitoring_layout.addLayout(container_tail_layout)

        # Live Stream Checkbox
        self.live_stream_checkbox = QCheckBox("Live Stream")
        self.live_stream_checkbox.setToolTip("Enable live streaming of pod logs.")
        monitoring_layout.addWidget(self.live_stream_checkbox)

        # Execute Button
        self.pod_log_action_button = QPushButton("Execute")
        self.pod_log_action_button.clicked.connect(self.execute_pod_log_action)
        self.pod_log_action_button.setToolTip("Click to execute the selected monitoring action.")
        monitoring_layout.addWidget(self.pod_log_action_button)

        self.monitoring_tab.setLayout(monitoring_layout)

    def init_advanced_tab(self):
        advanced_layout = QVBoxLayout()

        # Advanced Pod Action Combobox
        self.advanced_pod_action_option = QComboBox(self)
        self.advanced_pod_action_option.addItems([
            "Select Action",
            "Port Forward Pod",
            "Evict Pod",
            "Copy Files To Pod",
            "Copy Files From Pod",
            "Attach to Pod",
            "Set Pod Resource Limits",
            "Run Network Diagnostic",
            "Manage Pod Disruption Budget"
        ])
        self.advanced_pod_action_option.setToolTip("Select an advanced pod action to perform.")
        advanced_layout.addWidget(QLabel("Advanced Action:"))
        advanced_layout.addWidget(self.advanced_pod_action_option)

        # Inputs for Advanced Actions

        # First Line: Port Forward
        port_forward_layout = QHBoxLayout()

        # Local Port Input
        local_port_label = QLabel("Local Port:")
        local_port_label.setFixedWidth(70)
        self.local_port_input = QLineEdit(self)
        self.local_port_input.setPlaceholderText("Local Port")
        self.local_port_input.setFixedWidth(80)
        self.local_port_input.setValidator(QIntValidator(1, 65535))
        self.local_port_input.setToolTip("Specify the local port for port forwarding.")
        port_forward_layout.addWidget(local_port_label)
        port_forward_layout.addWidget(self.local_port_input)

        # Remote Port Input
        remote_port_label = QLabel("Remote Port:")
        remote_port_label.setFixedWidth(80)
        self.remote_port_input = QLineEdit(self)
        self.remote_port_input.setPlaceholderText("Remote Port")
        self.remote_port_input.setFixedWidth(80)
        self.remote_port_input.setValidator(QIntValidator(1, 65535))
        self.remote_port_input.setToolTip("Specify the remote port on the pod for port forwarding.")
        port_forward_layout.addWidget(remote_port_label)
        port_forward_layout.addWidget(self.remote_port_input)

        advanced_layout.addLayout(port_forward_layout)

        # Second Line: Copy Files Inputs
        copy_files_layout = QHBoxLayout()

        # Local Path Input
        local_path_label = QLabel("Local Path:")
        local_path_label.setFixedWidth(70)
        self.local_path_input = QLineEdit(self)
        self.local_path_input.setPlaceholderText("Local Path")
        self.local_path_input.setFixedWidth(150)
        self.local_path_input.setToolTip("Specify the local file path.")
        copy_files_layout.addWidget(local_path_label)
        copy_files_layout.addWidget(self.local_path_input)

        # Remote Path Input
        remote_path_label = QLabel("Remote Path:")
        remote_path_label.setFixedWidth(80)
        self.remote_path_input = QLineEdit(self)
        self.remote_path_input.setPlaceholderText("Remote Path")
        self.remote_path_input.setFixedWidth(150)
        self.remote_path_input.setToolTip("Specify the file path inside the pod.")
        copy_files_layout.addWidget(remote_path_label)
        copy_files_layout.addWidget(self.remote_path_input)

        advanced_layout.addLayout(copy_files_layout)

        # Network Diagnostic Input
        network_diag_layout = QHBoxLayout()
        target_label = QLabel("Target Address:")
        target_label.setFixedWidth(100)
        self.target_address_input = QLineEdit(self)
        self.target_address_input.setPlaceholderText("e.g., google.com")
        self.target_address_input.setFixedWidth(200)
        self.target_address_input.setToolTip("Enter the target address for network diagnostics.")
        network_diag_layout.addWidget(target_label)
        network_diag_layout.addWidget(self.target_address_input)
        advanced_layout.addLayout(network_diag_layout)
        self.target_address_input.hide()  # Hidden by default

        # Pod Disruption Budget Inputs
        pdb_layout = QHBoxLayout()
        pdb_min_available_label = QLabel("minAvailable:")
        pdb_min_available_label.setFixedWidth(100)
        self.pdb_min_available_input = QLineEdit(self)
        self.pdb_min_available_input.setPlaceholderText("minAvailable")
        self.pdb_min_available_input.setValidator(QIntValidator(0, 1000))
        self.pdb_min_available_input.setToolTip("Specify minimum number of pods that must be available.")
        pdb_layout.addWidget(pdb_min_available_label)
        pdb_layout.addWidget(self.pdb_min_available_input)

        pdb_max_unavailable_label = QLabel("maxUnavailable:")
        pdb_max_unavailable_label.setFixedWidth(100)
        self.pdb_max_unavailable_input = QLineEdit(self)
        self.pdb_max_unavailable_input.setPlaceholderText("maxUnavailable")
        self.pdb_max_unavailable_input.setValidator(QIntValidator(0, 1000))
        self.pdb_max_unavailable_input.setToolTip("Specify maximum number of pods that can be unavailable.")
        pdb_layout.addWidget(pdb_max_unavailable_label)
        pdb_layout.addWidget(self.pdb_max_unavailable_input)

        advanced_layout.addLayout(pdb_layout)
        self.pdb_min_available_input.hide()
        self.pdb_max_unavailable_input.hide()

        # Execute Button
        self.advanced_pod_action_button = QPushButton("Execute")
        self.advanced_pod_action_button.clicked.connect(self.execute_advanced_pod_action)
        self.advanced_pod_action_button.setToolTip("Click to execute the selected advanced pod action.")
        advanced_layout.addWidget(self.advanced_pod_action_button)

        self.advanced_tab.setLayout(advanced_layout)
        
    def append_output_on_main_thread(self, output):
        """Safely append output to the text edit on the main thread."""
        QMetaObject.invokeMethod(self, "append_output", Qt.QueuedConnection, Q_ARG(str, output))




    def load_namespaces(self):
        """Load namespaces based on the current context and SSL settings."""
        try:
            # Get the API client with current SSL settings
            api_client = self.get_api_client()
            if not api_client:
                return

            v1 = client.CoreV1Api(api_client)

            # Fetch all namespaces
            namespaces = v1.list_namespace()
            namespace_names = [ns.metadata.name for ns in namespaces.items]

            # Clear and update namespace dropdown
            self.namespace_option.clear()
            self.namespace_option.addItems(namespace_names)

            # Debugging output
            self.pod_command_output.append(f"Loaded {len(namespace_names)} namespaces.")

            # Load pods for the first namespace
            if namespace_names:
                self.namespace_option.setCurrentIndex(0)
                self.load_pods_in_namespace()

        except ApiException as e:
            self.pod_command_output.append(f"Kubernetes API error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to load namespaces: {e}")
        except Exception as e:
            self.pod_command_output.append(f"Error loading namespaces: {e}")
            QMessageBox.critical(self, "Error", f"Failed to load namespaces: {e}")

    def load_pods_in_namespace(self):
        """Load pods within the selected namespace based on current context and SSL settings."""
        namespace = self.namespace_option.currentText()
        if not namespace:
            self.pod_command_output.append("No namespace selected.")
            return

        try:
            # Get the API client with current SSL settings
            api_client = self.get_api_client()
            if not api_client:
                return

            v1 = client.CoreV1Api(api_client)

            # Get pods within the selected namespace
            pods = v1.list_namespaced_pod(namespace=namespace)
            pod_names = [pod.metadata.name for pod in pods.items]

            # Clear and update pod dropdown
            self.pod_name_option.clear()
            self.pod_name_option.addItems(pod_names)

            # Debugging output
            self.pod_command_output.append(f"Loaded {len(pod_names)} pods in namespace '{namespace}'.")

        except ApiException as e:
            self.pod_command_output.append(f"Kubernetes API error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to load pods: {e}")
        except Exception as e:
            self.pod_command_output.append(f"Error loading pods in namespace '{namespace}': {e}")
            QMessageBox.critical(self, "Error", f"Failed to load pods: {e}")

    def update_input_visibility(self):
        """Show or hide input fields based on the selected action."""
        # Hide all optional inputs
        self.command_input.hide()  # Update this to the correct input field
        self.send_command_button.hide()  # Hide the send button by default
        self.container_name_input.hide()
        self.tail_lines_input.hide()
        self.live_stream_checkbox.hide()
        self.local_port_input.hide()
        self.remote_port_input.hide()
        self.local_path_input.hide()
        self.remote_path_input.hide()
        self.target_address_input.hide()
        self.pdb_min_available_input.hide()
        self.pdb_max_unavailable_input.hide()

        # Show inputs based on selected actions
        if self.pod_action_option.currentText() == "Exec into Pod":
            # Show the input for commands and the send button when executing into a pod
            self.command_input.show()
            self.send_command_button.show()

        if self.pod_log_action_option.currentText() in ["View Pod Logs", "Stream Pod Logs"]:
            self.container_name_input.show()
            self.tail_lines_input.show()
            self.live_stream_checkbox.show()

        if self.advanced_pod_action_option.currentText() == "Port Forward Pod":
            self.local_port_input.show()
            self.remote_port_input.show()
        elif self.advanced_pod_action_option.currentText() in ["Copy Files To Pod", "Copy Files From Pod"]:
            self.local_path_input.show()
            self.remote_path_input.show()
        elif self.advanced_pod_action_option.currentText() == "Run Network Diagnostic":
            self.target_address_input.show()
        elif self.advanced_pod_action_option.currentText() == "Manage Pod Disruption Budget":
            self.pdb_min_available_input.show()
            self.pdb_max_unavailable_input.show()


    def execute_pod_action(self):
        """Dispatch the selected pod action to its respective function."""
        selected_action = self.pod_action_option.currentText()
        namespace = self.namespace_option.currentText()
        pod_name = self.pod_name_option.currentText()
        label_selector = self.label_selector_input.text().strip()

        if selected_action == "Select Action":
            self.pod_command_output.append("Please select a valid pod action.")
            QMessageBox.warning(self, "Warning", "Please select a valid pod action.")
            return
        
        # Separate handling for 'Create Pod' as it only requires namespace
        if selected_action == "Create Pod":
            self.create_pod(namespace)
            return
        
        # Separate handling for 'Exec into Pod' for persistent session
        if selected_action == "Exec into Pod":
            self.exec_into_pod(namespace, pod_name)
            return

        # Dispatch to the appropriate function
        action_map = {
            "List Pods": self.list_pods,
            "Describe Pod": self.describe_pod,
            "Delete Pod": self.delete_pod,
            "Restart Pod": self.restart_pod,
            "Update Pod Labels": self.update_pod_labels,
            "Update Pod Annotations": self.update_pod_annotations,
            "Get Pod Events": self.get_pod_events,
            "View Health Checks": self.view_health_checks,
            "Edit Pod YAML": self.edit_pod_yaml
        }

        action_func = action_map.get(selected_action, None)
        if action_func:
            action_func(namespace, pod_name, label_selector)
        else:
            self.pod_command_output.append("Selected pod action is not implemented.")
            QMessageBox.warning(self, "Warning", "Selected pod action is not implemented.")
            
    def create_pod(self, namespace):
        """Prompt user for pod name and image, then create a new pod."""
        # Create a dialog to get pod details
        create_pod_dialog = QDialog(self)
        create_pod_dialog.setWindowTitle("Create Pod")
        
        # Layout for the dialog
        layout = QVBoxLayout()
        
        # Pod Name
        name_label = QLabel("Pod Name:")
        pod_name_input = QLineEdit()
        layout.addWidget(name_label)
        layout.addWidget(pod_name_input)
        
        # Pod Image
        image_label = QLabel("Pod Image:")
        pod_image_input = QLineEdit()
        layout.addWidget(image_label)
        layout.addWidget(pod_image_input)
        
        # Dialog buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(lambda: self.confirm_create_pod(namespace, create_pod_dialog, pod_name_input.text().strip(), pod_image_input.text().strip()))
        button_box.rejected.connect(create_pod_dialog.reject)
        layout.addWidget(button_box)
        
        create_pod_dialog.setLayout(layout)
        create_pod_dialog.exec_()
        

    def confirm_create_pod(self, namespace, dialog, pod_name, pod_image):
        """Create a new pod with the specified name and image."""
        if not pod_name or not pod_image:
            self.pod_command_output.append("Pod name and image cannot be empty.")
            QMessageBox.warning(self, "Warning", "Pod name and image cannot be empty.")
            return

        try:
            # Define pod specification
            pod_spec = client.V1Pod(
                metadata=client.V1ObjectMeta(name=pod_name),
                spec=client.V1PodSpec(
                    containers=[client.V1Container(
                        name=pod_name,
                        image=pod_image,
                        ports=[client.V1ContainerPort(container_port=80)]  # Optional: Set container port
                    )]
                )
            )

            # Get API client
            api_client = self.get_api_client()
            v1 = client.CoreV1Api(api_client)

            # Create the pod
            v1.create_namespaced_pod(namespace=namespace, body=pod_spec)

            self.pod_command_output.append(f"Pod '{pod_name}' created successfully in namespace '{namespace}' with image '{pod_image}'.")
            QMessageBox.information(self, "Success", f"Pod '{pod_name}' created successfully.")
            
            # Refresh the list of pods
            self.load_pods_in_namespace()
            
            # Close the dialog
            dialog.accept()

        except ApiException as e:
            self.pod_command_output.append(f"Kubernetes API error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to create pod: {e}")
        except Exception as e:
            self.pod_command_output.append(f"Error creating pod: {e}")
            QMessageBox.critical(self, "Error", f"Failed to create pod: {e}")




    def list_pods(self, namespace, pod_name, label_selector):
        """List pods in the selected namespace with optional label filtering."""
        try:
            api_client = self.get_api_client()
            if not api_client:
                return
            v1 = client.CoreV1Api(api_client)

            pods = v1.list_namespaced_pod(namespace=namespace, label_selector=label_selector)
            pod_names = [pod.metadata.name for pod in pods.items]

            self.pod_command_output.append(f"Pods in namespace '{namespace}':")
            for name in pod_names:
                self.pod_command_output.append(f"- {name}")

        except ApiException as e:
            self.pod_command_output.append(f"Kubernetes API error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to list pods: {e}")
        except Exception as e:
            self.pod_command_output.append(f"Error listing pods: {e}")
            QMessageBox.critical(self, "Error", f"Failed to list pods: {e}")

    def describe_pod(self, namespace, pod_name, label_selector):
        """Describe the selected pod."""
        if not pod_name:
            self.pod_command_output.append("Please select a pod to describe.")
            QMessageBox.warning(self, "Warning", "Please select a pod to describe.")
            return

        try:
            api_client = self.get_api_client()
            if not api_client:
                return
            v1 = client.CoreV1Api(api_client)

            pod = v1.read_namespaced_pod(name=pod_name, namespace=namespace)
            pod_details = client.ApiClient().sanitize_for_serialization(pod)
            pod_yaml = yaml.dump(pod_details, sort_keys=False)
            self.pod_command_output.append(f"Details for pod '{pod_name}':\n{pod_yaml}")

        except ApiException as e:
            self.pod_command_output.append(f"Kubernetes API error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to describe pod: {e}")
        except Exception as e:
            self.pod_command_output.append(f"Error describing pod: {e}")
            QMessageBox.critical(self, "Error", f"Failed to describe pod: {e}")

    def delete_pod(self, namespace, pod_name, label_selector):
        """Delete the selected pod."""
        if not pod_name:
            self.pod_command_output.append("Please select a pod to delete.")
            QMessageBox.warning(self, "Warning", "Please select a pod to delete.")
            return

        try:
            reply = QMessageBox.question(
                self, 'Confirm Delete',
                f"Are you sure you want to delete pod '{pod_name}'?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                api_client = self.get_api_client()
                if not api_client:
                    return
                v1 = client.CoreV1Api(api_client)
                v1.delete_namespaced_pod(name=pod_name, namespace=namespace)
                self.pod_command_output.append(f"Pod '{pod_name}' deleted successfully.")
                # Refresh pod list
                self.load_pods_in_namespace()
        except ApiException as e:
            self.pod_command_output.append(f"Kubernetes API error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to delete pod: {e}")
        except Exception as e:
            self.pod_command_output.append(f"Error deleting pod: {e}")
            QMessageBox.critical(self, "Error", f"Failed to delete pod: {e}")

    def restart_pod(self, namespace, pod_name, label_selector):
        """Restart the selected pod by deleting it. It will be recreated if part of a deployment or replica set."""
        if not pod_name:
            self.pod_command_output.append("Please select a pod to restart.")
            QMessageBox.warning(self, "Warning", "Please select a pod to restart.")
            return

        try:
            reply = QMessageBox.question(
                self, 'Confirm Restart',
                f"Are you sure you want to restart pod '{pod_name}'?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                api_client = self.get_api_client()
                if not api_client:
                    return
                v1 = client.CoreV1Api(api_client)
                v1.delete_namespaced_pod(name=pod_name, namespace=namespace)
                self.pod_command_output.append(f"Pod '{pod_name}' restarted successfully.")
                # Refresh pod list
                self.load_pods_in_namespace()
        except ApiException as e:
            self.pod_command_output.append(f"Kubernetes API error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to restart pod: {e}")
        except Exception as e:
            self.pod_command_output.append(f"Error restarting pod: {e}")
            QMessageBox.critical(self, "Error", f"Failed to restart pod: {e}")


    def exec_into_pod(self, namespace, pod_name, label_selector=None):
        """Start a persistent session with the pod, allowing subsequent commands to be run."""
        if not pod_name or pod_name == "Select Pod":
            self.pod_command_output.append("Please select a pod to login and execute commands.")
            self.show_warning_on_main_thread("Please select a pod to login.", "Warning")
            return

        # Check if a session is already active
        if self.is_session_active():
            self.pod_command_output.append("A session is already active. Please close the current session before starting a new one.")
            self.show_warning_on_main_thread("A session is already active. Please close the current session before starting a new one.", "Warning")
            return

        # Start a thread to handle the persistent session login
        exec_thread = threading.Thread(target=self.start_persistent_session, args=(namespace, pod_name), daemon=True)
        exec_thread.start()



    def start_persistent_session(self, namespace, pod_name):
        """Start a persistent session in the pod."""
        try:
            # Define an interactive shell command to start the session
            exec_command = ['/bin/sh']

            # Get the API client with updated SSL settings
            api_client = self.get_api_client()
            v1 = client.CoreV1Api(api_client)

            # Start an interactive session in the pod
            self.append_output_on_main_thread(f"Connecting to pod '{pod_name}' for interactive session...")
            self.persistent_session = stream.stream(
                v1.connect_get_namespaced_pod_exec,
                pod_name,
                namespace,
                command=exec_command,
                stderr=True,
                stdin=True,  # Enable stdin for sending subsequent commands
                stdout=True,
                tty=True,
                _preload_content=False  # Allow real-time streaming
            )

            # Read and display initial session connection output
            self.read_session_output()

        except ApiException as e:
            self.append_output_on_main_thread(f"Kubernetes API error during session start: {e}")
            self.show_warning_on_main_thread(f"Failed to start session in pod: {e}", "Error")
        except Exception as e:
            self.append_output_on_main_thread(f"Error starting session in pod: {e}")
            self.show_warning_on_main_thread(f"Failed to start session in pod: {e}", "Error")


    def show_warning_on_main_thread(self, message, title):
        """Show a warning message box on the main thread."""
        QMetaObject.invokeMethod(
            self,
            lambda: QMessageBox.warning(self, title, message),
            Qt.QueuedConnection
    )


    def read_session_output(self):
        """Read and display output from the session in real-time."""
        try:
            while self.persistent_session.is_open():
                self.persistent_session.update(timeout=1)
                if self.persistent_session.peek_stdout():
                    output = self.persistent_session.read_stdout()
                    self.append_output_signal.emit(output)
                if self.persistent_session.peek_stderr():
                    error_output = self.persistent_session.read_stderr()
                    self.append_output_signal.emit(error_output)
        except Exception as e:
            self.append_output_signal.emit(f"Error reading session output: {e}")


    def send_command_to_pod(self):
        """Send a command to the persistent session running in the pod."""
        if not hasattr(self, 'persistent_session') or not self.persistent_session.is_open():
            self.pod_command_output.append("No active session. Please start a session by clicking 'Exec' first.")
            return

        # Get the command from the input field
        command = self.command_input.text().strip()
        if not command:
            self.pod_command_output.append("Please enter a command to execute.")
            return

        try:
            # Send the command to the open session
            self.persistent_session.write_stdin(command + "\n")
            self.command_input.clear()  # Clear input after sending command

        except Exception as e:
            self.pod_command_output.append(f"Error sending command to pod: {e}")
            QMessageBox.critical(self, "Error", f"Failed to send command to pod: {e}")
            
        
    def is_session_active(self):
        """Check if a persistent session is currently active."""
        return hasattr(self, 'persistent_session') and self.persistent_session.is_open()





    def update_pod_labels(self, namespace, pod_name, label_selector):
        """Update labels of the selected pod."""
        if not pod_name:
            self.pod_command_output.append("Please select a pod to update labels.")
            QMessageBox.warning(self, "Warning", "Please select a pod to update labels.")
            return

        labels_text = self.label_selector_input.text().strip()
        if not labels_text:
            self.pod_command_output.append("Please enter labels in key=value format.")
            QMessageBox.warning(self, "Warning", "Please enter labels in key=value format.")
            return

        try:
            labels = dict(item.split("=") for item in labels_text.split(","))
            body = {'metadata': {'labels': labels}}

            api_client = self.get_api_client()
            if not api_client:
                return
            v1 = client.CoreV1Api(api_client)

            v1.patch_namespaced_pod(name=pod_name, namespace=namespace, body=body)
            self.pod_command_output.append(f"Labels updated for pod '{pod_name}'.")

        except ValueError:
            self.pod_command_output.append("Invalid label format. Use key=value.")
            QMessageBox.warning(self, "Warning", "Invalid label format. Use key=value.")
        except ApiException as e:
            self.pod_command_output.append(f"Kubernetes API error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to update pod labels: {e}")
        except Exception as e:
            self.pod_command_output.append(f"Error updating pod labels: {e}")
            QMessageBox.critical(self, "Error", f"Failed to update pod labels: {e}")

    def update_pod_annotations(self, namespace, pod_name, label_selector):
        """Update annotations of the selected pod."""
        if not pod_name:
            self.pod_command_output.append("Please select a pod to update annotations.")
            QMessageBox.warning(self, "Warning", "Please select a pod to update annotations.")
            return

        annotations_text = self.label_selector_input.text().strip()
        if not annotations_text:
            self.pod_command_output.append("Please enter annotations in key=value format.")
            QMessageBox.warning(self, "Warning", "Please enter annotations in key=value format.")
            return

        try:
            annotations = dict(item.split("=") for item in annotations_text.split(","))
            body = {'metadata': {'annotations': annotations}}

            api_client = self.get_api_client()
            if not api_client:
                return
            v1 = client.CoreV1Api(api_client)

            v1.patch_namespaced_pod(name=pod_name, namespace=namespace, body=body)
            self.pod_command_output.append(f"Annotations updated for pod '{pod_name}'.")

        except ValueError:
            self.pod_command_output.append("Invalid annotation format. Use key=value.")
            QMessageBox.warning(self, "Warning", "Invalid annotation format. Use key=value.")
        except ApiException as e:
            self.pod_command_output.append(f"Kubernetes API error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to update pod annotations: {e}")
        except Exception as e:
            self.pod_command_output.append(f"Error updating pod annotations: {e}")
            QMessageBox.critical(self, "Error", f"Failed to update pod annotations: {e}")

    def get_pod_events(self, namespace, pod_name, label_selector):
        """Retrieve events related to the selected pod."""
        if not pod_name:
            self.pod_command_output.append("Please select a pod to get events.")
            QMessageBox.warning(self, "Warning", "Please select a pod to get events.")
            return

        try:
            api_client = self.get_api_client()
            if not api_client:
                return
            v1 = client.CoreV1Api(api_client)

            field_selector = f"involvedObject.name={pod_name}"
            events = v1.list_namespaced_event(namespace=namespace, field_selector=field_selector)

            self.pod_command_output.append(f"Events for pod '{pod_name}':")
            for event in events.items:
                message = event.message
                timestamp = event.last_timestamp
                self.pod_command_output.append(f"{timestamp}: {message}")

        except ApiException as e:
            self.pod_command_output.append(f"Kubernetes API error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to get pod events: {e}")
        except Exception as e:
            self.pod_command_output.append(f"Error getting pod events: {e}")
            QMessageBox.critical(self, "Error", f"Failed to get pod events: {e}")

    def view_health_checks(self, namespace, pod_name, label_selector):
        """View health checks (readiness and liveness probes) of the selected pod."""
        if not pod_name:
            self.pod_command_output.append("Please select a pod to view health checks.")
            QMessageBox.warning(self, "Warning", "Please select a pod to view health checks.")
            return

        try:
            api_client = self.get_api_client()
            if not api_client:
                return
            v1 = client.CoreV1Api(api_client)

            pod = v1.read_namespaced_pod(name=pod_name, namespace=namespace)
            self.pod_command_output.append(f"Health checks for pod '{pod_name}':")
            containers = pod.spec.containers
            for container in containers:
                self.pod_command_output.append(f"Container: {container.name}")
                readiness_probe = container.readiness_probe
                liveness_probe = container.liveness_probe
                if readiness_probe:
                    self.pod_command_output.append(f"  Readiness Probe: {readiness_probe}")
                else:
                    self.pod_command_output.append("  Readiness Probe: None")
                if liveness_probe:
                    self.pod_command_output.append(f"  Liveness Probe: {liveness_probe}")
                else:
                    self.pod_command_output.append("  Liveness Probe: None")

        except ApiException as e:
            self.pod_command_output.append(f"Kubernetes API error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to view health checks: {e}")
        except Exception as e:
            self.pod_command_output.append(f"Error viewing health checks: {e}")
            QMessageBox.critical(self, "Error", f"Failed to view health checks: {e}")

    def edit_pod_yaml(self, namespace, pod_name, label_selector):
        """Edit the YAML of the selected pod."""
        if not pod_name:
            self.pod_command_output.append("Please select a pod to edit.")
            QMessageBox.warning(self, "Warning", "Please select a pod to edit.")
            return

        try:
            api_client = self.get_api_client()
            if not api_client:
                return
            v1 = client.CoreV1Api(api_client)

            # Retrieve the pod as a JSON object
            pod = v1.read_namespaced_pod(name=pod_name, namespace=namespace)
            
            # Convert the pod to a dictionary and filter out immutable fields
            pod_dict = pod.to_dict()
            self.filter_immutable_fields(pod_dict)
            
            # Convert the modified dictionary to YAML format
            pod_yaml = yaml.dump(pod_dict, default_flow_style=False)

            # Open a dialog with a text editor to modify the YAML
            dialog = QDialog(self)
            dialog.setWindowTitle(f"Edit YAML for Pod {pod_name}")
            dialog.resize(800, 600)
            dialog_layout = QVBoxLayout(dialog)

            yaml_editor = QTextEdit()
            yaml_editor.setPlainText(pod_yaml)
            dialog_layout.addWidget(yaml_editor)

            button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            dialog_layout.addWidget(button_box)

            button_box.accepted.connect(dialog.accept)
            button_box.rejected.connect(dialog.reject)

            if dialog.exec_() == QDialog.Accepted:
                new_pod_yaml = yaml_editor.toPlainText()
                # Validate YAML
                try:
                    pod_definition = yaml.safe_load(new_pod_yaml)
                except yaml.YAMLError as ye:
                    QMessageBox.critical(self, "YAML Error", f"Invalid YAML format: {ye}")
                    self.pod_command_output.append(f"Invalid YAML format: {ye}")
                    return
                
                # Convert back to JSON to ensure correct formatting
                pod_json = json.loads(json.dumps(pod_definition))
                
                # Replace the pod using the converted JSON
                try:
                    # Patch the Pod instead of replacing it to avoid altering immutable fields
                    v1.patch_namespaced_pod(
                        name=pod_name,
                        namespace=namespace,
                        body=pod_json
                    )
                    self.pod_command_output.append(f"Pod '{pod_name}' updated successfully.")
                    QMessageBox.information(self, "Success", f"Pod '{pod_name}' updated successfully.")
                    # Refresh pod list
                    self.load_pods_in_namespace()
                except ApiException as e:
                    self.pod_command_output.append(f"Kubernetes API error: {e}")
                    QMessageBox.critical(self, "Error", f"Failed to update pod YAML: {e}")
                except Exception as e:
                    self.pod_command_output.append(f"Error updating pod YAML: {e}")
                    QMessageBox.critical(self, "Error", f"Failed to update pod YAML: {e}")
            else:
                self.pod_command_output.append("Pod editing cancelled.")

        except ApiException as e:
            self.pod_command_output.append(f"Kubernetes API error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to retrieve pod YAML: {e}")
        except Exception as e:
            self.pod_command_output.append(f"Error retrieving pod YAML: {e}")
            QMessageBox.critical(self, "Error", f"Failed to retrieve pod YAML: {e}")

    def filter_immutable_fields(self, pod_dict):
        """Filter out immutable and non-updatable fields from the Pod definition."""
        # Remove metadata fields that are immutable
        immutable_metadata_keys = ['creation_timestamp', 'deletion_grace_period_seconds', 'deletion_timestamp',
                                'generate_name', 'managed_fields', 'resource_version', 'self_link',
                                'uid', 'owner_references', 'annotations']
        for key in immutable_metadata_keys:
            pod_dict['metadata'].pop(key, None)
        
        # Remove status field entirely as it cannot be updated
        pod_dict.pop('status', None)
        
        # Remove immutable fields from spec
        immutable_spec_keys = ['service_account', 'service_account_name', 'node_name', 'volumes', 'restart_policy']
        for key in immutable_spec_keys:
            pod_dict['spec'].pop(key, None)

        # Remove fields from containers within spec that are not updatable
        if 'containers' in pod_dict['spec']:
            for container in pod_dict['spec']['containers']:
                for key in ['volume_mounts', 'liveness_probe', 'readiness_probe', 'env_from', 'resources']:
                    container.pop(key, None)


    def execute_pod_log_action(self):
        """Handle pod log actions: View Logs, Stream Logs, Get Metrics."""
        selected_action = self.pod_log_action_option.currentText()
        namespace = self.namespace_option.currentText()
        pod_name = self.pod_name_option.currentText()
        container_name = self.container_name_input.text().strip()
        tail_lines = self.tail_lines_input.text().strip()
        live_stream = self.live_stream_checkbox.isChecked()

        if not pod_name:
            self.pod_command_output.append("Please select a pod for log actions.")
            QMessageBox.warning(self, "Warning", "Please select a pod for log actions.")
            return

        # Dispatch to the appropriate function
        action_map = {
            "View Pod Logs": self.view_pod_logs,
            "Stream Pod Logs": self.stream_pod_logs,
            "Get Pod Metrics": self.get_pod_metrics
        }

        action_func = action_map.get(selected_action, None)
        if action_func:
            action_func(namespace, pod_name, container_name, tail_lines, live_stream)
        else:
            self.pod_command_output.append("Selected monitoring action is not implemented.")
            QMessageBox.warning(self, "Warning", "Selected monitoring action is not implemented.")

    def view_pod_logs(self, namespace, pod_name, container_name, tail_lines, live_stream):
        """View logs of the selected pod."""
        try:
            api_client = self.get_api_client()
            if not api_client:
                return
            v1 = client.CoreV1Api(api_client)

            tail = int(tail_lines) if tail_lines else None
            logs = v1.read_namespaced_pod_log(
                name=pod_name,
                namespace=namespace,
                container=container_name or None,
                tail_lines=tail
            )
            self.pod_command_output.append(f"Logs for pod '{pod_name}':\n{logs}")

        except ValueError:
            self.pod_command_output.append("Invalid number for tail lines.")
            QMessageBox.warning(self, "Warning", "Invalid number for tail lines.")
        except ApiException as e:
            self.pod_command_output.append(f"Kubernetes API error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to get pod logs: {e}")
        except Exception as e:
            self.pod_command_output.append(f"Error getting pod logs: {e}")
            QMessageBox.critical(self, "Error", f"Failed to get pod logs: {e}")

    def stream_pod_logs(self, namespace, pod_name, container_name, tail_lines, live_stream):
        """Stream logs of the selected pod."""
        if not live_stream:
            self.pod_command_output.append("Live Stream is not enabled.")
            QMessageBox.warning(self, "Warning", "Live Stream is not enabled.")
            return

        self.pod_command_output.append(f"Starting live log stream for pod '{pod_name}'...")
        self.pod_log_action_button.setEnabled(False)

        def stream_logs():
            try:
                api_client = self.get_api_client()
                if not api_client:
                    return
                v1 = client.CoreV1Api(api_client)
                w = watch.Watch()
                for event in w.stream(
                    v1.read_namespaced_pod_log,
                    name=pod_name,
                    namespace=namespace,
                    container=container_name or None,
                    follow=True,
                    tail_lines=int(tail_lines) if tail_lines else None
                ):
                    log_line = event
                    self.pod_command_output.append(log_line)
            except ApiException as e:
                self.pod_command_output.append(f"Kubernetes API error: {e}")
                QMessageBox.critical(self, "Error", f"Failed to stream pod logs: {e}")
            except Exception as e:
                self.pod_command_output.append(f"Error streaming pod logs: {e}")
                QMessageBox.critical(self, "Error", f"Failed to stream pod logs: {e}")
            finally:
                self.pod_command_output.append("Live log streaming ended.")
                self.pod_log_action_button.setEnabled(True)

        self.stream_thread = threading.Thread(
            target=stream_logs,
            daemon=True
        )
        self.stream_thread.start()

    def get_pod_metrics(self, namespace, pod_name, container_name, tail_lines, live_stream):
        """Retrieve metrics of the selected pod."""
        self.pod_command_output.append("Note: 'Get Pod Metrics' requires the Kubernetes Metrics Server to be installed in the cluster.")
        try:
            api_client = self.get_api_client()
            if not api_client:
                return
            custom_api = client.CustomObjectsApi(api_client)

            metrics = custom_api.get_namespaced_custom_object(
                group="metrics.k8s.io",
                version="v1beta1",
                namespace=namespace,
                plural="pods",
                name=pod_name
            )
            self.pod_command_output.append(f"Metrics for pod '{pod_name}':")
            for container in metrics['containers']:
                name = container['name']
                usage = container['usage']
                cpu = usage.get('cpu', 'N/A')
                memory = usage.get('memory', 'N/A')
                self.pod_command_output.append(f"Container: {name}, CPU: {cpu}, Memory: {memory}")

        except ApiException as e:
            self.pod_command_output.append(f"Kubernetes API error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to get pod metrics: {e}")
        except Exception as e:
            self.pod_command_output.append(f"Error getting pod metrics: {e}")
            QMessageBox.critical(self, "Error", f"Failed to get pod metrics: {e}")

    def execute_advanced_pod_action(self):
        """Handle advanced pod actions."""
        selected_action = self.advanced_pod_action_option.currentText()
        namespace = self.namespace_option.currentText()
        pod_name = self.pod_name_option.currentText()
        local_port = self.local_port_input.text().strip()
        remote_port = self.remote_port_input.text().strip()
        local_path = self.local_path_input.text().strip()
        remote_path = self.remote_path_input.text().strip()
        target_address = self.target_address_input.text().strip()
        min_available = self.pdb_min_available_input.text().strip()
        max_unavailable = self.pdb_max_unavailable_input.text().strip()

        if not pod_name:
            self.pod_command_output.append("Please select a pod for advanced actions.")
            QMessageBox.warning(self, "Warning", "Please select a pod for advanced actions.")
            return

        # Dispatch to the appropriate function
        action_map = {
            "Port Forward Pod": self.port_forward_pod,
            "Evict Pod": self.evict_pod,
            "Copy Files To Pod": self.copy_files_to_pod,
            "Copy Files From Pod": self.copy_files_from_pod,
            "Attach to Pod": self.attach_to_pod,
            "Set Pod Resource Limits": self.set_pod_resource_limits,
            "Run Network Diagnostic": self.run_network_diagnostic,
            "Manage Pod Disruption Budget": self.manage_pod_disruption_budget
        }

        action_func = action_map.get(selected_action, None)
        if action_func:
            action_func(
                namespace, pod_name, local_port, remote_port,
                local_path, remote_path, target_address,
                min_available, max_unavailable
            )
        else:
            self.pod_command_output.append("Selected advanced pod action is not implemented.")
            QMessageBox.warning(self, "Warning", "Selected advanced pod action is not implemented.")

    def port_forward_pod(self, namespace, pod_name, local_port, remote_port, *args):
        """Port forward from local machine to the pod."""
        if not local_port or not remote_port:
            self.pod_command_output.append("Please enter both local and remote ports.")
            QMessageBox.warning(self, "Warning", "Please enter both local and remote ports.")
            return

        try:
            cmd = [
                'kubectl', 'port-forward', f'pod/{pod_name}',
                f'{local_port}:{remote_port}', '-n', namespace
            ]
            subprocess.Popen(cmd)
            self.pod_command_output.append(
                f"Port forwarding established from local port {local_port} to pod '{pod_name}' on port {remote_port}."
            )
        except Exception as e:
            self.pod_command_output.append(f"Error establishing port forwarding: {e}")
            QMessageBox.critical(self, "Error", f"Failed to establish port forwarding: {e}")

    def evict_pod(self, namespace, pod_name, *args):
        """Evict the selected pod."""
        try:
            eviction = client.V1Eviction(
                metadata=client.V1ObjectMeta(name=pod_name, namespace=namespace)
            )
            api_client = self.get_api_client()
            if not api_client:
                return
            v1 = client.CoreV1Api(api_client)
            v1.create_namespaced_pod_eviction(name=pod_name, namespace=namespace, body=eviction)
            self.pod_command_output.append(f"Pod '{pod_name}' evicted successfully.")
            # Refresh pod list
            self.load_pods_in_namespace()
        except ApiException as e:
            self.pod_command_output.append(f"Kubernetes API error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to evict pod: {e}")
        except Exception as e:
            self.pod_command_output.append(f"Error evicting pod: {e}")
            QMessageBox.critical(self, "Error", f"Failed to evict pod: {e}")

    def copy_files_to_pod(self, namespace, pod_name, local_port, remote_port, local_path, remote_path, *args):
        """Copy files to the selected pod."""
        if not local_path or not remote_path:
            self.pod_command_output.append("Please enter both local and remote paths.")
            QMessageBox.warning(self, "Warning", "Please enter both local and remote paths.")
            return

        try:
            cmd = [
                'kubectl', 'cp', local_path,
                f"{namespace}/{pod_name}:{remote_path}"
            ]
            subprocess.run(cmd, check=True)
            self.pod_command_output.append(f"Copied '{local_path}' to pod '{pod_name}':'{remote_path}'.")
        except subprocess.CalledProcessError as e:
            self.pod_command_output.append(f"Error copying files to pod: {e}")
            QMessageBox.critical(self, "Error", f"Failed to copy files to pod: {e}")
        except Exception as e:
            self.pod_command_output.append(f"Error copying files to pod: {e}")
            QMessageBox.critical(self, "Error", f"Failed to copy files to pod: {e}")

    def copy_files_from_pod(self, namespace, pod_name, local_port, remote_port, local_path, remote_path, *args):
        """Copy files from the selected pod."""
        if not local_path or not remote_path:
            self.pod_command_output.append("Please enter both local and remote paths.")
            QMessageBox.warning(self, "Warning", "Please enter both local and remote paths.")
            return

        try:
            cmd = [
                'kubectl', 'cp',
                f"{namespace}/{pod_name}:{remote_path}", local_path
            ]
            subprocess.run(cmd, check=True)
            self.pod_command_output.append(f"Copied '{remote_path}' from pod '{pod_name}' to '{local_path}'.")
        except subprocess.CalledProcessError as e:
            self.pod_command_output.append(f"Error copying files from pod: {e}")
            QMessageBox.critical(self, "Error", f"Failed to copy files from pod: {e}")
        except Exception as e:
            self.pod_command_output.append(f"Error copying files from pod: {e}")
            QMessageBox.critical(self, "Error", f"Failed to copy files from pod: {e}")

    def attach_to_pod(self, namespace, pod_name, local_port, remote_port, local_path, remote_path, *args):
        """Attach to the selected pod."""
        try:
            exec_command = ['/bin/sh']
            api_client = self.get_api_client()
            if not api_client:
                return
            v1 = client.CoreV1Api(api_client)

            resp = stream.stream(
                v1.connect_get_namespaced_pod_attach,
                pod_name,
                namespace,
                command=exec_command,
                stderr=True,
                stdin=True,
                stdout=True,
                tty=True
            )
            self.pod_command_output.append(f"Attached to pod '{pod_name}':\n{resp}")
        except ApiException as e:
            self.pod_command_output.append(f"Kubernetes API error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to attach to pod: {e}")
        except Exception as e:
            self.pod_command_output.append(f"Error attaching to pod: {e}")
            QMessageBox.critical(self, "Error", f"Failed to attach to pod: {e}")

    def set_pod_resource_limits(self, namespace, pod_name, local_port, remote_port, local_path, remote_path, *args):
        """Set resource limits for the selected pod."""
        self.pod_command_output.append("Setting pod resource limits is not implemented in this UI.")
        QMessageBox.information(self, "Info", "Setting pod resource limits is not implemented yet.")

    def run_network_diagnostic(self, namespace, pod_name, local_port, remote_port, local_path, remote_path, target_address, *args):
        """Run network diagnostics (e.g., ping) from the selected pod."""
        if not target_address:
            self.pod_command_output.append("Please enter a target address.")
            QMessageBox.warning(self, "Warning", "Please enter a target address.")
            return

        try:
            exec_command = ['ping', '-c', '4', target_address]
            api_client = self.get_api_client()
            if not api_client:
                return
            v1 = client.CoreV1Api(api_client)

            resp = stream.stream(
                v1.connect_get_namespaced_pod_exec,
                pod_name,
                namespace,
                command=exec_command,
                stderr=True,
                stdin=False,
                stdout=True,
                tty=False
            )
            self.pod_command_output.append(f"Ping results from pod '{pod_name}':\n{resp}")
        except ApiException as e:
            self.pod_command_output.append(f"Kubernetes API error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to run network diagnostic: {e}")
        except Exception as e:
            self.pod_command_output.append(f"Error running network diagnostic: {e}")
            QMessageBox.critical(self, "Error", f"Failed to run network diagnostic: {e}")

    def manage_pod_disruption_budget(self, namespace, pod_name, local_port, remote_port, local_path, remote_path, target_address, min_available, max_unavailable):
        """Manage Pod Disruption Budget for the selected pod."""
        try:
            if not min_available and not max_unavailable:
                self.pod_command_output.append("Please specify either minAvailable or maxUnavailable.")
                QMessageBox.warning(self, "Warning", "Please specify either minAvailable or maxUnavailable.")
                return

            pdb_api = client.PolicyV1beta1Api(self.get_api_client())
            if not pdb_api:
                return

            pdb_name = f"{pod_name}-pdb"
            label_selector = {"app": pod_name}  # Adjust based on your label selectors

            pdb_spec = client.V1beta1PodDisruptionBudgetSpec(
                selector=client.V1LabelSelector(match_labels=label_selector)
            )
            if min_available:
                pdb_spec.min_available = int(min_available)
            if max_unavailable:
                pdb_spec.max_unavailable = int(max_unavailable)

            pdb_body = client.V1beta1PodDisruptionBudget(
                metadata=client.V1ObjectMeta(name=pdb_name),
                spec=pdb_spec
            )

            # Attempt to create the PDB
            try:
                pdb_api.create_namespaced_pod_disruption_budget(
                    namespace=namespace,
                    body=pdb_body
                )
                self.pod_command_output.append(f"Pod Disruption Budget '{pdb_name}' created successfully.")
            except ApiException as e:
                if e.status == 409:
                    # PDB already exists, attempt to replace it
                    pdb_api.replace_namespaced_pod_disruption_budget(
                        name=pdb_name,
                        namespace=namespace,
                        body=pdb_body
                    )
                    self.pod_command_output.append(f"Pod Disruption Budget '{pdb_name}' updated successfully.")
                else:
                    raise e

        except ApiException as e:
            self.pod_command_output.append(f"Kubernetes API error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to manage Pod Disruption Budget: {e}")
        except Exception as e:
            self.pod_command_output.append(f"Error managing Pod Disruption Budget: {e}")
            QMessageBox.critical(self, "Error", f"Failed to manage Pod Disruption Budget: {e}")

    def deploy_resource(self, file_path):
        """Deploy resources from a YAML file."""
        try:
            api_client = self.get_api_client()
            if not api_client:
                return

            utils.create_from_yaml(api_client, file_path)
            self.pod_command_output.append(f"Resource deployed from {file_path}")

        except ApiException as e:
            self.pod_command_output.append(f"Kubernetes API error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to deploy resource: {e}")
        except Exception as e:
            self.pod_command_output.append(f"Error deploying resource: {e}")
            QMessageBox.critical(self, "Error", f"Failed to deploy resource: {e}")

    def destroy_resource(self, file_path):
        """Destroy resources from a YAML file."""
        try:
            api_client = self.get_api_client()
            if not api_client:
                return

            utils.delete_from_yaml(api_client, file_path)
            self.pod_command_output.append(f"Resource destroyed from {file_path}")

        except ApiException as e:
            self.pod_command_output.append(f"Kubernetes API error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to destroy resource: {e}")
        except Exception as e:
            self.pod_command_output.append(f"Error destroying resource: {e}")
            QMessageBox.critical(self, "Error", f"Failed to destroy resource: {e}")

    def edit_resource(self, file_path):
        """Edit and reapply a resource from a YAML file."""
        try:
            # Open the file in a dialog for editing
            with open(file_path, 'r') as file:
                yaml_content = file.read()
            
            # Open a file dialog for the user to modify the file
            edited_file_path, _ = QFileDialog.getSaveFileName(self, "Edit Resource", file_path, "YAML Files (*.yaml *.yml)")
            
            if edited_file_path:
                with open(edited_file_path, 'w') as file:
                    file.write(yaml_content)

                # Reapply the edited resource
                api_client = self.get_api_client()
                if not api_client:
                    return
                utils.create_from_yaml(api_client, edited_file_path)

                self.pod_command_output.append(f"Resource edited and applied from {edited_file_path}")

        except yaml.YAMLError as ye:
            self.pod_command_output.append(f"YAML Error: {ye}")
            QMessageBox.critical(self, "YAML Error", f"Invalid YAML format: {ye}")
        except ApiException as e:
            self.pod_command_output.append(f"Kubernetes API error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to apply edited resource: {e}")
        except Exception as e:
            self.pod_command_output.append(f"Error editing resource: {e}")
            QMessageBox.critical(self, "Error", f"Failed to edit resource: {e}")
