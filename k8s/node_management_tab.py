import subprocess
import threading

import yaml
from kubernetes import client, config, stream, watch
from PyQt5.QtCore import QObject, QRunnable, Qt, QThreadPool, pyqtSignal
from PyQt5.QtGui import QIntValidator
from PyQt5.QtWidgets import (QCheckBox, QComboBox, QDialog, QDialogButtonBox,
                             QGroupBox, QHBoxLayout, QInputDialog, QLabel,
                             QLineEdit, QListWidget, QListWidgetItem,
                             QMessageBox, QPushButton, QTabWidget, QTextEdit,
                             QVBoxLayout, QWidget)


class WorkerSignals(QObject):
    log_signal = pyqtSignal(str)
    finished = pyqtSignal()
    error = pyqtSignal(tuple)
    result = pyqtSignal(object)
    
    
class Worker(QRunnable):
    def __init__(self, fn, *args, **kwargs):
        super().__init__()

        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()

    def run(self):
        try:
            result = self.fn(*self.args, **self.kwargs)
        except Exception as e:
            import sys
            import traceback
            exctype, value = sys.exc_info()[:2]
            self.signals.error.emit((exctype, value, traceback.format_exc()))
        else:
            self.signals.result.emit(result)
        finally:
            self.signals.finished.emit()


class NodeManagementTab(QWidget):
    def __init__(self, auth_manager, main_tab_widget):
        super().__init__()
        self.auth_manager = auth_manager
        self.main_tab_widget = main_tab_widget
        self.threadpool = QThreadPool()
        self.initUI()
        self.load_nodes_in_background()

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
        self.node_command_output = QTextEdit(self)
        self.node_command_output.setReadOnly(True)
        self.node_command_output.setToolTip("Displays output and logs.")
        right_column.addWidget(QLabel("Output:"))
        right_column.addWidget(self.node_command_output)

        # Left Column: Node Actions (using tabs to organize sections)
        left_column = QVBoxLayout()
        self.tabs = QTabWidget()

        # General Node Actions Tab
        self.general_tab = QWidget()
        self.init_general_tab()
        self.tabs.addTab(self.general_tab, "General Actions")

        # Advanced Node Management Tab
        self.advanced_tab = QWidget()
        self.init_advanced_tab()
        self.tabs.addTab(self.advanced_tab, "Advanced Management")

        # Security and RBAC Tab
        self.security_tab = QWidget()
        self.init_security_tab()
        self.tabs.addTab(self.security_tab, "Security & RBAC")

        left_column.addWidget(self.tabs)

        # Add left and right columns to the content layout
        content_layout.addLayout(left_column)
        content_layout.addLayout(right_column)

        # Add the content layout to the main layout
        main_layout.addLayout(content_layout)

        # Set the layout for this tab
        self.setLayout(main_layout)

        # Initialize the UI components
        #self.load_nodes()
        
    def load_nodes_in_background(self):
        context = self.context_option.currentText()
        worker = Worker(self.load_nodes, context)
        worker.signals.result.connect(self.on_nodes_loaded)
        worker.signals.error.connect(self.on_load_nodes_error)
        self.threadpool.start(worker)

    def change_context(self):
        new_context = self.context_option.currentText()
        self.current_context_label.setText(new_context)
        self.node_command_output.append(f"Switching to context '{new_context}'...")
        try:
            config.load_kube_config(context=new_context)
            self.node_command_output.append(f"Switched to context '{new_context}'.")
            self.load_nodes_in_background()
        except Exception as e:
            self.node_command_output.append(f"Error changing context: {e}")
            QMessageBox.critical(self, "Error", f"Failed to switch context: {e}")

    def init_general_tab(self):
        general_layout = QVBoxLayout()

        # Node Selection (Dropdown)
        self.node_option = QComboBox(self)
        self.node_option.setToolTip("Select the node to manage.")
        general_layout.addWidget(QLabel("Node:"))
        general_layout.addWidget(self.node_option)

        # Service Action Combobox
        self.service_action_option = QComboBox(self)
        self.service_action_option.addItems(["Select Action", "Start Service", "Stop Service", "Restart Service"])
        self.service_action_option.setToolTip("Select a service action to perform.")
        general_layout.addWidget(QLabel("Service Action:"))
        general_layout.addWidget(self.service_action_option)

        # Service Command Input
        self.service_command_input = QLineEdit(self)
        self.service_command_input.setPlaceholderText("Enter Service Command (e.g., nginx)")
        self.service_command_input.setToolTip("Specify the service name to manage.")
        general_layout.addWidget(QLabel("Service Name:"))
        general_layout.addWidget(self.service_command_input)

        # Execute Button
        self.service_action_button = QPushButton("Execute Service Action")
        self.service_action_button.clicked.connect(self.execute_service_action)
        self.service_action_button.setToolTip("Click to execute the selected service action.")
        general_layout.addWidget(self.service_action_button)

        # Add Spacer
        general_layout.addStretch()

        self.general_tab.setLayout(general_layout)

    def init_advanced_tab(self):
        advanced_layout = QVBoxLayout()

        # Advanced Node Actions Combobox
        self.advanced_node_action_option = QComboBox(self)
        self.advanced_node_action_option.addItems([
            "Select Action",
            "Cordon Node",
            "Uncordon Node",
            "Drain Node",
            "Label Node",
            "Taint Node",
            "Reboot Node",
            "Power Off Node",
            "Edit Node YAML"
        ])
        self.advanced_node_action_option.setToolTip("Select an advanced node action to perform.")
        advanced_layout.addWidget(QLabel("Advanced Node Action:"))
        advanced_layout.addWidget(self.advanced_node_action_option)

        # Inputs for Advanced Actions

        # Label Inputs
        self.label_key_input = QLineEdit(self)
        self.label_key_input.setPlaceholderText("Label Key")
        self.label_key_input.setToolTip("Enter the label key.")
        self.label_value_input = QLineEdit(self)
        self.label_value_input.setPlaceholderText("Label Value")
        self.label_value_input.setToolTip("Enter the label value.")
        label_layout = QHBoxLayout()
        label_layout.addWidget(QLabel("Label Key:"))
        label_layout.addWidget(self.label_key_input)
        label_layout.addWidget(QLabel("Label Value:"))
        label_layout.addWidget(self.label_value_input)
        advanced_layout.addLayout(label_layout)
        self.label_key_input.hide()
        self.label_value_input.hide()

        # Taint Inputs
        self.taint_key_input = QLineEdit(self)
        self.taint_key_input.setPlaceholderText("Taint Key")
        self.taint_key_input.setToolTip("Enter the taint key.")
        self.taint_value_input = QLineEdit(self)
        self.taint_value_input.setPlaceholderText("Taint Value")
        self.taint_value_input.setToolTip("Enter the taint value.")
        self.taint_effect_input = QComboBox(self)
        self.taint_effect_input.addItems(["NoSchedule", "PreferNoSchedule", "NoExecute"])
        self.taint_effect_input.setToolTip("Select the taint effect.")
        taint_layout = QHBoxLayout()
        taint_layout.addWidget(QLabel("Taint Key:"))
        taint_layout.addWidget(self.taint_key_input)
        taint_layout.addWidget(QLabel("Taint Value:"))
        taint_layout.addWidget(self.taint_value_input)
        taint_layout.addWidget(QLabel("Effect:"))
        taint_layout.addWidget(self.taint_effect_input)
        advanced_layout.addLayout(taint_layout)
        self.taint_key_input.hide()
        self.taint_value_input.hide()
        self.taint_effect_input.hide()

        # Execute Button
        self.advanced_node_action_button = QPushButton("Execute Advanced Action")
        self.advanced_node_action_button.clicked.connect(self.execute_advanced_node_action)
        self.advanced_node_action_button.setToolTip("Click to execute the selected advanced node action.")
        advanced_layout.addWidget(self.advanced_node_action_button)

        # Add Spacer
        advanced_layout.addStretch()

        self.advanced_tab.setLayout(advanced_layout)

    def init_security_tab(self):
        security_layout = QVBoxLayout()

        # RBAC Actions
        self.rbac_action_option = QComboBox(self)
        self.rbac_action_option.addItems([
            "Select Action",
            "Create Role",
            "Create RoleBinding",
            "Delete Role",
            "Delete RoleBinding"
        ])
        self.rbac_action_option.setToolTip("Select an RBAC action to perform.")
        security_layout.addWidget(QLabel("RBAC Action:"))
        security_layout.addWidget(self.rbac_action_option)

        # RBAC Inputs
        self.rbac_name_input = QLineEdit(self)
        self.rbac_name_input.setPlaceholderText("Role/RoleBinding Name")
        self.rbac_name_input.setToolTip("Enter the name for the RBAC resource.")
        security_layout.addWidget(QLabel("RBAC Name:"))
        security_layout.addWidget(self.rbac_name_input)

        # RBAC Rules Input (for Roles)
        self.rbac_rules_input = QLineEdit(self)
        self.rbac_rules_input.setPlaceholderText("Rules (e.g., get,list,watch)")
        self.rbac_rules_input.setToolTip("Specify the rules for the Role (comma-separated).")
        security_layout.addWidget(QLabel("Rules:"))
        security_layout.addWidget(self.rbac_rules_input)
        self.rbac_rules_input.hide()

        # Execute Button
        self.rbac_action_button = QPushButton("Execute RBAC Action")
        self.rbac_action_button.clicked.connect(self.execute_rbac_action)
        self.rbac_action_button.setToolTip("Click to execute the selected RBAC action.")
        security_layout.addWidget(self.rbac_action_button)

        # Add Spacer
        security_layout.addStretch()

        self.security_tab.setLayout(security_layout)

        # Connect RBAC Action Selection to show/hide inputs
        self.rbac_action_option.currentTextChanged.connect(self.update_rbac_input_visibility)

    def update_rbac_input_visibility(self):
        action = self.rbac_action_option.currentText()
        if action in ["Create Role"]:
            self.rbac_rules_input.show()
        else:
            self.rbac_rules_input.hide()

    def load_nodes(self, context):
        try:
            # Load the kubeconfig for the given context
            kube_config = client.Configuration()
            config.load_kube_config(context=context, client_configuration=kube_config)
            kube_config.verify_ssl = False
            v1 = client.CoreV1Api(client.ApiClient(kube_config))
            nodes = v1.list_node()
            node_names = [node.metadata.name for node in nodes.items]
            return node_names
        except Exception as e:
            raise e
        
    def on_nodes_loaded(self, node_names):
        # Update the node dropdown
        self.node_option.clear()
        self.node_option.addItems(node_names)
        # Update the output log
        self.node_command_output.append(f"Context: {self.context_option.currentText()}")
        self.node_command_output.append(f"Found {len(node_names)} nodes")
        self.node_command_output.append("Nodes loaded successfully.")
        
    def on_load_nodes_error(self, error_tuple):
        exctype, value, traceback_str = error_tuple
        self.node_command_output.append(f"Error loading nodes: {value}")
        QMessageBox.critical(self, "Error", f"Failed to load nodes: {value}")




    def execute_service_action(self):
        selected_action = self.service_action_option.currentText()
        node_name = self.node_option.currentText()
        service_name = self.service_command_input.text().strip()

        if selected_action == "Select Action":
            self.node_command_output.append("Please select a valid service action.")
            QMessageBox.warning(self, "Warning", "Please select a valid service action.")
            return

        if not service_name:
            self.node_command_output.append("Please enter a service name.")
            QMessageBox.warning(self, "Warning", "Please enter a service name.")
            return

        try:
            # SSH into the node and execute the service command
            # This example uses SSH; ensure that passwordless SSH is set up
            ssh_command = [
                'ssh', node_name,
                f'sudo systemctl {selected_action.lower()} {service_name}'
            ]
            self.node_command_output.append(f"Executing: {' '.join(ssh_command)}")
            process = subprocess.Popen(
                ssh_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate()

            if stdout:
                self.node_command_output.append(f"Output:\n{stdout}")
            if stderr:
                self.node_command_output.append(f"Error:\n{stderr}")
                QMessageBox.critical(self, "Error", f"Service action failed: {stderr}")
            else:
                self.node_command_output.append(f"Service '{service_name}' {selected_action.lower()}ed successfully.")

        except Exception as e:
            self.node_command_output.append(f"Error executing service action: {e}")
            QMessageBox.critical(self, "Error", f"Failed to execute service action: {e}")

    def execute_advanced_node_action(self):
        selected_action = self.advanced_node_action_option.currentText()
        node_name = self.node_option.currentText()

        if selected_action == "Select Action":
            self.node_command_output.append("Please select a valid advanced node action.")
            QMessageBox.warning(self, "Warning", "Please select a valid advanced node action.")
            return

        try:
            v1 = client.CoreV1Api()
            if selected_action == "Cordon Node":
                node = v1.read_node(name=node_name)
                node.spec.unschedulable = True
                v1.patch_node(name=node_name, body=node)
                self.node_command_output.append(f"Node '{node_name}' cordoned successfully.")

            elif selected_action == "Uncordon Node":
                node = v1.read_node(name=node_name)
                node.spec.unschedulable = False
                v1.patch_node(name=node_name, body=node)
                self.node_command_output.append(f"Node '{node_name}' uncordoned successfully.")

            elif selected_action == "Drain Node":
                # Implement node draining using kubectl via subprocess
                cmd = [
                    'kubectl', 'drain', node_name,
                    '--ignore-daemonsets',
                    '--delete-local-data',
                    '--force',
                    '--context', self.context_option.currentText()
                ]
                self.node_command_output.append(f"Executing: {' '.join(cmd)}")
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                stdout, stderr = process.communicate()

                if stdout:
                    self.node_command_output.append(f"Output:\n{stdout}")
                if stderr:
                    self.node_command_output.append(f"Error:\n{stderr}")
                    QMessageBox.critical(self, "Error", f"Drain action failed: {stderr}")
                else:
                    self.node_command_output.append(f"Node '{node_name}' drained successfully.")

            elif selected_action == "Label Node":
                key, ok1 = QInputDialog.getText(self, "Label Key", "Enter label key:")
                if not ok1 or not key:
                    return
                value, ok2 = QInputDialog.getText(self, "Label Value", "Enter label value:")
                if not ok2 or not value:
                    return
                patch = {"metadata": {"labels": {key: value}}}
                v1.patch_node(name=node_name, body=patch)
                self.node_command_output.append(f"Label '{key}={value}' applied to node '{node_name}' successfully.")

            elif selected_action == "Taint Node":
                key, ok1 = QInputDialog.getText(self, "Taint Key", "Enter taint key:")
                if not ok1 or not key:
                    return
                value, ok2 = QInputDialog.getText(self, "Taint Value", "Enter taint value:")
                if not ok2 or not value:
                    return
                effect, ok3 = QInputDialog.getItem(
                    self, "Taint Effect", "Select taint effect:", ["NoSchedule", "PreferNoSchedule", "NoExecute"], 0, False
                )
                if not ok3:
                    return
                taint = client.V1Taint(
                    key=key,
                    value=value,
                    effect=effect
                )
                patch = {
                    "metadata": {
                        "taints": [taint.to_dict()]
                    }
                }
                v1.patch_node(name=node_name, body=patch)
                self.node_command_output.append(f"Taint '{key}={value}:{effect}' applied to node '{node_name}' successfully.")

            elif selected_action == "Reboot Node":
                reply = QMessageBox.question(
                    self, 'Confirm Reboot',
                    f"Are you sure you want to reboot node '{node_name}'?",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No
                )
                if reply == QMessageBox.Yes:
                    ssh_command = ['ssh', node_name, 'sudo reboot']
                    self.node_command_output.append(f"Executing: {' '.join(ssh_command)}")
                    process = subprocess.Popen(
                        ssh_command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    stdout, stderr = process.communicate()

                    if stdout:
                        self.node_command_output.append(f"Output:\n{stdout}")
                    if stderr:
                        self.node_command_output.append(f"Error:\n{stderr}")
                        QMessageBox.critical(self, "Error", f"Reboot action failed: {stderr}")
                    else:
                        self.node_command_output.append(f"Node '{node_name}' reboot initiated successfully.")

            elif selected_action == "Power Off Node":
                reply = QMessageBox.question(
                    self, 'Confirm Power Off',
                    f"Are you sure you want to power off node '{node_name}'?",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No
                )
                if reply == QMessageBox.Yes:
                    ssh_command = ['ssh', node_name, 'sudo shutdown -h now']
                    self.node_command_output.append(f"Executing: {' '.join(ssh_command)}")
                    process = subprocess.Popen(
                        ssh_command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    stdout, stderr = process.communicate()

                    if stdout:
                        self.node_command_output.append(f"Output:\n{stdout}")
                    if stderr:
                        self.node_command_output.append(f"Error:\n{stderr}")
                        QMessageBox.critical(self, "Error", f"Power off action failed: {stderr}")
                    else:
                        self.node_command_output.append(f"Node '{node_name}' power off initiated successfully.")

            elif selected_action == "Edit Node YAML":
                try:
                    node = client.CoreV1Api().read_node(name=node_name, _preload_content=False)
                    node_yaml = node.data.decode('utf-8')

                    # Open a dialog with a YAML editor
                    dialog = QDialog(self)
                    dialog.setWindowTitle(f"Edit YAML for Node {node_name}")
                    dialog.resize(800, 600)
                    dialog_layout = QVBoxLayout(dialog)

                    yaml_editor = QTextEdit()
                    yaml_editor.setPlainText(node_yaml)
                    dialog_layout.addWidget(yaml_editor)

                    button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
                    dialog_layout.addWidget(button_box)

                    button_box.accepted.connect(dialog.accept)
                    button_box.rejected.connect(dialog.reject)

                    if dialog.exec_() == QDialog.Accepted:
                        new_node_yaml = yaml_editor.toPlainText()
                        # Validate YAML
                        try:
                            node_definition = yaml.safe_load(new_node_yaml)
                        except yaml.YAMLError as ye:
                            QMessageBox.critical(self, "YAML Error", f"Invalid YAML format: {ye}")
                            self.node_command_output.append(f"Invalid YAML format: {ye}")
                            return

                        # Replace the node
                        try:
                            client.CoreV1Api().replace_node(name=node_name, body=node_definition)
                            self.node_command_output.append(f"Node '{node_name}' updated successfully.")
                            QMessageBox.information(self, "Success", f"Node '{node_name}' updated successfully.")
                        except Exception as e:
                            self.node_command_output.append(f"Error updating node YAML: {e}")
                            QMessageBox.critical(self, "Error", f"Failed to update node YAML: {e}")
                    else:
                        self.node_command_output.append("Node YAML editing cancelled.")
                except Exception as e:
                    self.node_command_output.append(f"Error editing node YAML: {e}")
                    QMessageBox.critical(self, "Error", f"Failed to edit node YAML: {e}")

            else:
                self.node_command_output.append("Please select a valid advanced node action.")
                QMessageBox.warning(self, "Warning", "Please select a valid advanced node action.")

        except Exception as e:
            self.node_command_output.append(f"Error executing node action: {e}")

    def execute_rbac_action(self):
        selected_action = self.rbac_action_option.currentText()
        rbac_name = self.rbac_name_input.text().strip()
        rules = self.rbac_rules_input.text().strip()

        if selected_action == "Select Action":
            self.node_command_output.append("Please select a valid RBAC action.")
            QMessageBox.warning(self, "Warning", "Please select a valid RBAC action.")
            return

        if not rbac_name:
            self.node_command_output.append("Please enter a Role or RoleBinding name.")
            QMessageBox.warning(self, "Warning", "Please enter a Role or RoleBinding name.")
            return

        try:
            rbac_api = client.RbacAuthorizationV1Api()

            if selected_action in ["Create Role", "Delete Role"]:
                if selected_action == "Create Role":
                    if not rules:
                        self.node_command_output.append("Please enter rules for the Role.")
                        QMessageBox.warning(self, "Warning", "Please enter rules for the Role.")
                        return
                    rules_list = [rule.strip() for rule in rules.split(",")]
                    role = client.V1Role(
                        metadata=client.V1ObjectMeta(name=rbac_name),
                        rules=[client.V1PolicyRule(
                            api_groups=[""],
                            resources=["pods"],
                            verbs=rules_list
                        )]
                    )
                    rbac_api.create_namespaced_role(namespace=self.node_option.currentText(), body=role)
                    self.node_command_output.append(f"Role '{rbac_name}' created successfully.")
                    QMessageBox.information(self, "Success", f"Role '{rbac_name}' created successfully.")

                elif selected_action == "Delete Role":
                    rbac_api.delete_namespaced_role(name=rbac_name, namespace=self.node_option.currentText())
                    self.node_command_output.append(f"Role '{rbac_name}' deleted successfully.")
                    QMessageBox.information(self, "Success", f"Role '{rbac_name}' deleted successfully.")

            elif selected_action in ["Create RoleBinding", "Delete RoleBinding"]:
                if selected_action == "Create RoleBinding":
                    if not rules:
                        self.node_command_output.append("Please enter subjects for the RoleBinding.")
                        QMessageBox.warning(self, "Warning", "Please enter subjects for the RoleBinding.")
                        return
                    subjects = [client.V1Subject(kind="User", name=subject.strip(), api_group="rbac.authorization.k8s.io") for subject in rules.split(",")]
                    role_binding = client.V1RoleBinding(
                        metadata=client.V1ObjectMeta(name=rbac_name),
                        subjects=subjects,
                        role_ref=client.V1RoleRef(
                            kind="Role",
                            name=rbac_name,
                            api_group="rbac.authorization.k8s.io"
                        )
                    )
                    rbac_api.create_namespaced_role_binding(namespace=self.node_option.currentText(), body=role_binding)
                    self.node_command_output.append(f"RoleBinding '{rbac_name}' created successfully.")
                    QMessageBox.information(self, "Success", f"RoleBinding '{rbac_name}' created successfully.")

                elif selected_action == "Delete RoleBinding":
                    rbac_api.delete_namespaced_role_binding(name=rbac_name, namespace=self.node_option.currentText())
                    self.node_command_output.append(f"RoleBinding '{rbac_name}' deleted successfully.")
                    QMessageBox.information(self, "Success", f"RoleBinding '{rbac_name}' deleted successfully.")

            else:
                self.node_command_output.append("Please select a valid RBAC action.")
                QMessageBox.warning(self, "Warning", "Please select a valid RBAC action.")

        except Exception as e:
            self.node_command_output.append(f"Error executing RBAC action: {e}")
            QMessageBox.critical(self, "Error", f"Failed to execute RBAC action: {e}")
