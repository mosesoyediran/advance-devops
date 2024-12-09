import base64
import os
import random
import re
import shutil
import string
import subprocess
import tempfile
import time
from copy import deepcopy

import urllib3
import yaml
from kubernetes import client, config, utils
from kubernetes.client.rest import ApiException
from kubernetes.config.kube_config import KubeConfigLoader
from PyQt5.QtCore import (Q_ARG, QMetaObject, QObject, QRunnable, Qt,
                          QThreadPool, pyqtSignal, pyqtSlot)
from PyQt5.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QGroupBox,
                             QHBoxLayout, QInputDialog, QLabel, QMessageBox,
                             QPushButton, QTextEdit, QVBoxLayout, QWidget)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Worker and WorkerSignals classes as defined earlier
class WorkerSignals(QObject):
    finished = pyqtSignal()
    error = pyqtSignal(tuple)
    result = pyqtSignal(object)
    progress = pyqtSignal(int)

class Worker(QRunnable):
    def __init__(self, fn, *args, **kwargs):
        super().__init__()

        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()

        # Add the callback to our kwargs
        self.kwargs['progress_callback'] = self.signals.progress

    def run(self):
        try:
            result = self.fn(*self.args, **self.kwargs)
        except subprocess.CalledProcessError as e:
            # Emit stderr as error
            self.signals.error.emit((e.returncode, e.stderr))
        except Exception as e:
            import sys
            import traceback
            exctype, value = sys.exc_info()[:2]
            self.signals.error.emit((exctype, value, traceback.format_exc()))
        else:
            self.signals.result.emit(result)
        finally:
            self.signals.finished.emit()

class ClusterManagementTab(QWidget):
    def __init__(self, auth_manager, main_tab_widget):
        super().__init__()
        self.auth_manager = auth_manager
        self.main_tab_widget = main_tab_widget
        self.kubeconfig_path = os.path.expanduser("~/.kube/config")
        self.ssl_verification = False  # Default to False
        self.temp_kubeconfig = None  # Initialize the variable
        self.threadpool = QThreadPool()  # Initialize thread pool
        self.current_username = None
        self.initUI()
        

    def initUI(self):
        # Two-column layout
        main_layout = QHBoxLayout()

        # Left column
        left_column = QVBoxLayout()

        # Add right column (kubeconfig details)
        right_column = QVBoxLayout()
        self.command_output = QTextEdit(self)
        self.command_output.setReadOnly(True)
        right_column.addWidget(QLabel("Command Output:"))
        right_column.addWidget(self.command_output)

        # ------------------ Context Selection Section ------------------
        # Create a horizontal layout for the context selection
        context_layout = QHBoxLayout()

        # Add the label to the horizontal layout
        context_label = QLabel("Select Kubernetes Context:")
        context_layout.addWidget(context_label)

        # Add the context selector combo box to the horizontal layout
        self.context_selector = QComboBox(self)
        context_layout.addWidget(self.context_selector)

        # Add the switch context button to the horizontal layout
        self.switch_context_button = QPushButton("Switch Context")
        self.switch_context_button.clicked.connect(self.switch_kube_context)
        context_layout.addWidget(self.switch_context_button)

        # Add the horizontal context layout to the left column layout
        left_column.addLayout(context_layout)

        # ------------------ User Account Management Section ------------------
        account_management_group = QGroupBox("Account Management")
        account_group_layout = QVBoxLayout()
        
        
        # Horizontal layout for ClusterRole and ServiceAccount selectors
        role_sa_layout = QHBoxLayout()

        # ClusterRole Selector
        self.cluster_role_selector = QComboBox(self)
        self.cluster_role_selector.addItems(["Select ClusterRole"])  # Populate this dynamically
        role_sa_layout.addWidget(self.cluster_role_selector)

        # ServiceAccount Selector
        self.service_account_selector = QComboBox(self)
        self.service_account_selector.addItems(["Select ServiceAccount"])  # Populate this dynamically
        role_sa_layout.addWidget(self.service_account_selector)

        # Add the horizontal layout for selectors to the account group layout
        account_group_layout.addLayout(role_sa_layout)

        # Action Selector
        self.user_action_selector = QComboBox(self)
        self.user_action_selector.addItems(["Select Action", "Configure User"])
        account_group_layout.addWidget(QLabel("Select Action:"))
        account_group_layout.addWidget(self.user_action_selector)

        # Execute Button
        self.user_execute_button = QPushButton("Execute")
        self.user_execute_button.clicked.connect(self.execute_user_management_action)
        account_group_layout.addWidget(self.user_execute_button)

        # Set the layout for the group box
        account_management_group.setLayout(account_group_layout)

        # Add the account management group box to the left column
        left_column.addWidget(account_management_group)

        ####### Namespace Selector
        self.namespace_selector = QComboBox(self)
        left_column.addWidget(QLabel("Select Namespace:"))
        left_column.addWidget(self.namespace_selector)

        self.ssl_checkbox = QCheckBox("Enable SSL Verification")
        self.ssl_checkbox.setChecked(False)  # Default unchecked (SSL verification disabled)
        self.ssl_checkbox.stateChanged.connect(self.toggle_ssl_verification)
        left_column.addWidget(self.ssl_checkbox)

        self.reload_button = QPushButton("Reload Kubeconfig")
        self.reload_button.clicked.connect(self.load_kubeconfig_contexts)
        left_column.addWidget(self.reload_button)

        # Add a section for management actions
        left_column.addWidget(QLabel("Select Management Action:"))
        self.action_selector = QComboBox()
        self.action_selector.addItems(["Select Action", "Configure Ingress", "Configure Volume", "Configure ConfigMap or Secret", "Configure Data Backup", "Configure Namespace"])
        left_column.addWidget(self.action_selector)

        self.execute_button = QPushButton("Execute")
        self.execute_button.clicked.connect(self.execute_management_action)
        left_column.addWidget(self.execute_button)

        # Add left and right columns to the main layout
        main_layout.addLayout(left_column, 1)
        main_layout.addLayout(right_column, 2)

        # Set the layout for this subtab
        self.setLayout(main_layout)
        
        # Load contexts on initialization
        self.load_kubeconfig_contexts()

       
    
        

    def load_kubeconfig_contexts(self):
        """Load contexts from the kubeconfig file using a worker thread."""
        self.switch_context_button.setEnabled(False)
        self.reload_button.setEnabled(False)
        self.execute_button.setEnabled(False)

        worker = Worker(self._load_kubeconfig_contexts)
        worker.signals.result.connect(self.on_contexts_loaded)
        worker.signals.error.connect(self.on_error)
        worker.signals.finished.connect(self.on_contexts_loaded_finished)

        self.threadpool.start(worker)
        
        
        
    def get_clusters(kubeconfig_path):
        loader = KubeConfigLoader(config_file=kubeconfig_path)
        return loader.get_clusters()

    def _load_kubeconfig_contexts(self, progress_callback):
        """Function to load kubeconfig contexts."""
        try:
            with open(self.kubeconfig_path, 'r') as kubeconfig_file:
                kubeconfig = yaml.safe_load(kubeconfig_file)
                contexts = [context['name'] for context in kubeconfig.get('contexts', [])]
                return contexts
        except FileNotFoundError:
            raise Exception(f"Kubeconfig file not found at {self.kubeconfig_path}.")
        except Exception as e:
            raise e

    def on_contexts_loaded(self, contexts):
        """Handle the loaded contexts."""
        self.context_selector.clear()
        self.context_selector.addItems(contexts)
        self.command_output.append(f"Loaded {len(contexts)} contexts from {self.kubeconfig_path}")

    def on_contexts_loaded_finished(self):
        """Re-enable buttons after contexts are loaded."""
        self.switch_context_button.setEnabled(True)
        self.reload_button.setEnabled(True)
        self.execute_button.setEnabled(True)
        # Optionally, load namespaces for the first context
        if self.context_selector.count() > 0:
            self.load_kube_namespaces()

    def on_error(self, error_tuple):
        """Handle errors from worker threads."""
        if len(error_tuple) == 2:
            returncode, stderr = error_tuple
            self.command_output.append(f"Error (Return Code: {returncode}):\n{stderr}")
        elif len(error_tuple) == 3:
            exctype, value, traceback_str = error_tuple
            self.command_output.append(f"Error: {value}\n{traceback_str}")
        else:
            self.command_output.append("An unknown error occurred.")

    def load_kube_namespaces(self):
        """Load namespaces from the Kubernetes cluster using a worker thread."""
        self.execute_button.setEnabled(False)

        worker = Worker(self._load_kube_namespaces)
        worker.signals.result.connect(self.on_namespaces_loaded)
        worker.signals.error.connect(self.on_error)
        worker.signals.finished.connect(self.on_namespaces_loaded_finished)

        self.threadpool.start(worker)

    def _load_kube_namespaces(self, progress_callback):
        """Function to load namespaces."""
        kubeconfig_to_use = self.get_current_kubeconfig()
        helm_command = [
            'kubectl', 'get', 'namespaces',
            '--kubeconfig', kubeconfig_to_use,
            '-o', 'jsonpath={.items[*].metadata.name}'
        ]
        result = subprocess.run(helm_command, capture_output=True, text=True, check=True)
        namespaces = result.stdout.strip().split()
        return namespaces

    def on_namespaces_loaded(self, namespaces):
        """Handle the loaded namespaces."""
        self.namespace_selector.clear()
        if namespaces:
            self.namespace_selector.addItems(namespaces)
            self.command_output.append(f"Loaded {len(namespaces)} namespaces from cluster.")
        else:
            self.command_output.append("No namespaces found in the cluster.")

    def on_namespaces_loaded_finished(self):
        """Re-enable buttons after namespaces are loaded."""
        self.execute_button.setEnabled(True)

    def toggle_ssl_verification(self):
        """Toggle SSL verification based on checkbox state."""
        self.ssl_verification = self.ssl_checkbox.isChecked()
        self.command_output.append(f"SSL verification set to: {self.ssl_verification}")
        # Reload namespaces to apply SSL verification settings
        self.load_kube_namespaces()

    def switch_kube_context(self):
        """Switch to the selected Kubernetes context using a worker thread."""
        selected_context = self.context_selector.currentText()
        if selected_context:
            self.switch_context_button.setEnabled(False)
            self.execute_button.setEnabled(False)

            worker = Worker(self._switch_kube_context, selected_context)
            worker.signals.result.connect(self.on_context_switched)
            worker.signals.error.connect(self.on_error)
            worker.signals.finished.connect(self.on_context_switched_finished)

            self.threadpool.start(worker)
        else:
            self.command_output.append("No context selected.")

    def _switch_kube_context(self, context_name, progress_callback):
        """Function to switch Kubernetes context."""
        config.load_kube_config(context=context_name)
        return context_name

    def on_context_switched(self, context_name):
        """Handle successful context switch."""
        self.command_output.append(f"Switched to context: {context_name}")
        self.load_kube_namespaces()

    def on_context_switched_finished(self):
        """Re-enable buttons after context switch."""
        self.switch_context_button.setEnabled(True)
        self.execute_button.setEnabled(True)
        
        
    ################# User Management Tab Functions #################

    def execute_user_management_action(self):
        selected_action = self.user_action_selector.currentText()

        if selected_action == "Select Action":
            self.command_output.append("Please select a valid action.")
            return

        if selected_action == "Configure User":
            self.configure_user_action()
        else:
            self.command_output.append("Unknown action selected.")
            
    def configure_user_action(self):
        """Display a dialog to choose user management actions (Create, Add Role, Edit, Delete)."""
        # Define user actions
        action_options = ["Create User", "Add Role", "Add ServiceAccount"]
        action, ok = QInputDialog.getItem(self, "Configure User", "Select Action:", action_options, 0, False)

        if not ok or action not in action_options:
            self.command_output.append("No valid action selected for user configuration.")
            return

        # Call appropriate method based on user selection
        if action == "Create User":
            self.create_user()
        elif action == "Add Role":
            self.create_role()  
        elif action == "Add ServiceAccount":
            self.create_service_account()




    def create_user(self):
        """Initiate the user creation process."""
        # Prompt for username
        username, ok = QInputDialog.getText(self, 'Create User', 'Enter new username:')
        if not ok or not username.strip():
            self.command_output.append("User creation canceled or invalid username.")
            return

        username = username.strip()
        self.current_username = username  # Store the username for later use

        # Start the worker to create the user
        worker = Worker(self._create_user, username)
        worker.signals.result.connect(self.on_create_user_result)
        worker.signals.error.connect(self.on_error)
        worker.signals.finished.connect(self.on_create_user_finished)

        self.user_execute_button.setEnabled(False)
        self.command_output.append(f"Starting creation of user '{username}'...")
        self.threadpool.start(worker)

    def _create_user(self, username, progress_callback):
        """
        Function to create a Kubernetes user by generating keys, creating CSR, approving it,
        fetching the certificate, and generating a kubeconfig file.
        """
        # Define file paths
        temp_dir = tempfile.mkdtemp()
        key_path = os.path.join(temp_dir, f"{username}.key")
        csr_path = os.path.join(temp_dir, f"{username}.csr")
        csr_yaml_path = os.path.join(temp_dir, f"{username}-csr.yaml")
        cert_path = os.path.join(temp_dir, f"{username}.crt")
        kubeconfig_path = os.path.join(temp_dir, f"{username}-kubeconfig.yaml")

        # Determine which kubeconfig to use
        kubeconfig_to_use = self.get_current_kubeconfig()
        if not kubeconfig_to_use:
            raise Exception("Failed to determine a valid kubeconfig to use.")

        try:
            # Step 1: Generate client key
            progress_callback.emit(10)
            subprocess.run(
                ['openssl', 'genrsa', '-out', key_path, '2048'],
                check=True, capture_output=True, text=True
            )
            self.command_output.append(f"Generated key at {key_path}")

            # Step 2: Generate CSR
            progress_callback.emit(20)
            subprocess.run(
                [
                    'openssl', 'req', '-new', '-key', key_path, '-out', csr_path,
                    '-subj', f"/CN={username}/O=users"
                ],
                check=True, capture_output=True, text=True
            )
            self.command_output.append(f"Generated CSR at {csr_path}")

            # Step 3: Create Kubernetes CSR YAML
            progress_callback.emit(30)
            with open(csr_path, 'rb') as csr_file:
                csr_data = csr_file.read()
            csr_base64 = base64.b64encode(csr_data).decode('utf-8')

            csr_yaml = {
                "apiVersion": "certificates.k8s.io/v1",
                "kind": "CertificateSigningRequest",
                "metadata": {
                    "name": f"{username}-csr"
                },
                "spec": {
                    "request": csr_base64,
                    "signerName": "kubernetes.io/kube-apiserver-client",
                    "usages": [
                        "client auth"
                    ]
                }
            }

            with open(csr_yaml_path, 'w') as yaml_file:
                yaml.dump(csr_yaml, yaml_file)
            self.command_output.append(f"Created CSR YAML at {csr_yaml_path}")

            # Step 4: Apply CSR using the appropriate kubeconfig
            progress_callback.emit(40)
            subprocess.run(
                ['kubectl', 'apply', '-f', csr_yaml_path, '--kubeconfig', kubeconfig_to_use],
                check=True, capture_output=True, text=True
            )
            self.command_output.append(f"Applied CSR '{username}-csr' to Kubernetes.")

            # Step 5: Approve CSR using the appropriate kubeconfig
            progress_callback.emit(50)
            subprocess.run(
                ['kubectl', 'certificate', 'approve', f"{username}-csr", '--kubeconfig', kubeconfig_to_use],
                check=True, capture_output=True, text=True
            )
            self.command_output.append(f"Approved CSR '{username}-csr'.")

            # Step 6: Fetch Signed Certificate using the appropriate kubeconfig
            progress_callback.emit(60)
            result = subprocess.run(
                [
                    'kubectl', 'get', 'csr', f"{username}-csr",
                    '-o', 'jsonpath={.status.certificate}',
                    '--kubeconfig', kubeconfig_to_use
                ],
                check=True, capture_output=True, text=True
            )
            if not result.stdout:
                raise Exception("No certificate found in CSR status.")
            cert_base64 = result.stdout
            cert_data = base64.b64decode(cert_base64)
            with open(cert_path, 'wb') as cert_file:
                cert_file.write(cert_data)
            self.command_output.append(f"Fetched and wrote certificate to {cert_path}")

            # Step 7: Generate Kubeconfig
            progress_callback.emit(70)
            current_context = self.get_current_context()
            if not current_context:
                raise Exception("Failed to retrieve current Kubernetes context.")
            
            current_cluster = self.get_cluster_name(current_context)
            current_user = self.get_user_name(current_context)
            current_server = self.get_server_url(current_context)

            # Build kubeconfig
            kubeconfig = {
                "apiVersion": "v1",
                "clusters": [
                    {
                        "cluster": {
                            "certificate-authority-data": self.get_certificate_authority(current_cluster),
                            "server": current_server
                        },
                        "name": current_cluster
                    }
                ],
                "contexts": [
                    {
                        "context": {
                            "cluster": current_cluster,
                            "user": username
                        },
                        "name": f"{username}@{current_cluster}"
                    }
                ],
                "current-context": f"{username}@{current_cluster}",
                "kind": "Config",
                "users": [
                    {
                        "name": username,
                        "user": {
                            "client-certificate-data": self.read_file_as_base64(cert_path),
                            "client-key-data": self.read_file_as_base64(key_path)
                        }
                    }
                ]
            }

            with open(kubeconfig_path, 'w') as kc_file:
                yaml.dump(kubeconfig, kc_file)
            self.command_output.append(f"Generated kubeconfig for user '{username}' at {kubeconfig_path}")

            progress_callback.emit(80)

            # Step 8: Clean up CSR resource using the appropriate kubeconfig
            subprocess.run(
                ['kubectl', 'delete', 'csr', f"{username}-csr", '--kubeconfig', kubeconfig_to_use],
                check=True, capture_output=True, text=True
            )
            self.command_output.append(f"Deleted CSR '{username}-csr' from Kubernetes.")

            progress_callback.emit(90)

            # Return the path to the kubeconfig
            return kubeconfig_path

        except subprocess.CalledProcessError as e:
            self.command_output.append(f"Subprocess error: {e.stderr}")
            raise Exception(f"Subprocess error: {e.stderr}")
        except Exception as e:
            self.command_output.append(f"Unexpected error: {e}")
            raise e



    def on_create_user_result(self, kubeconfig_path):
        """
        Handle the result of the create_user function by prompting the user to save the kubeconfig file.
        """
        # Prompt the user to select where to save the kubeconfig
        save_path, _ = QFileDialog.getSaveFileName(
            self, "Save Kubeconfig", f"{os.path.expanduser('~')}/kubeconfig-{self.current_username}.yaml",
            "YAML Files (*.yaml);;All Files (*)"
        )

        if save_path:
            try:
                shutil.copy(kubeconfig_path, save_path)
                self.command_output.append(f"Kubeconfig saved to {save_path}")
                # Optionally, you can open the file or perform other actions
            except Exception as e:
                self.command_output.append(f"Failed to save kubeconfig: {e}")
        else:
            self.command_output.append("Kubeconfig save canceled.")

    def on_create_user_finished(self):
        """
        Re-enable the execute button after the create_user operation is finished.
        """
        self.user_execute_button.setEnabled(True)

    def on_error(self, error_tuple):
        """
        Handle errors from worker threads.
        """
        if len(error_tuple) == 2:
            returncode, stderr = error_tuple
            self.command_output.append(f"Error (Return Code: {returncode}):\n{stderr}")
        elif len(error_tuple) == 3:
            exctype, value, traceback_str = error_tuple
            self.command_output.append(f"Error: {value}\n{traceback_str}")
        else:
            self.command_output.append("An unknown error occurred.")
            
    def get_cluster_name(self, context_name):
        """
        Retrieves the cluster name from the specified context by manually parsing the kubeconfig file.
        """
        try:
            kubeconfig_to_use = self.get_current_kubeconfig()
            if not kubeconfig_to_use or not os.path.exists(kubeconfig_to_use):
                self.command_output.append("No valid kubeconfig available.")
                raise Exception("No valid kubeconfig available.")

            with open(kubeconfig_to_use, 'r') as f:
                kubeconfig = yaml.safe_load(f)

            contexts = kubeconfig.get('contexts', [])
            clusters = kubeconfig.get('clusters', [])

            self.command_output.append(f"Number of contexts found: {len(contexts)}")

            # Find the specified context
            target_context = next((ctx for ctx in contexts if ctx['name'] == context_name), None)
            if not target_context:
                self.command_output.append(f"Context '{context_name}' not found in kubeconfig.")
                raise Exception(f"Context '{context_name}' not found in kubeconfig.")

            cluster_name = target_context['context']['cluster']
            self.command_output.append(f"Cluster name: {cluster_name}")
            return cluster_name

        except yaml.YAMLError as e:
            self.command_output.append(f"YAMLError: {e}")
            raise Exception(f"Failed to parse kubeconfig YAML: {e}")
        except Exception as e:
            self.command_output.append(f"Exception: {e}")
            raise Exception(f"Failed to get cluster name: {e}")





    def get_current_context(self):
        """
        Retrieves the current Kubernetes context.
        """
        try:
            kubeconfig_to_use = self.get_current_kubeconfig()
            if not kubeconfig_to_use:
                self.command_output.append("No valid kubeconfig available.")
                raise Exception("No valid kubeconfig available.")

            config.load_kube_config(config_file=kubeconfig_to_use)
            contexts, active_context = config.list_kube_config_contexts()
            self.command_output.append(f"Number of contexts found: {len(contexts)}")

            if not contexts:
                self.command_output.append("No contexts found in kubeconfig.")
                raise Exception("No contexts found in kubeconfig.")

            if active_context:
                active_context_name = active_context['name']
                self.command_output.append(f"Active context: {active_context_name}")
                return active_context_name
            else:
                # If no active context, default to the first one
                default_context = contexts[0]['name']
                self.command_output.append(f"No active context. Defaulting to: {default_context}")
                return default_context

        except config.ConfigException as e:
            self.command_output.append(f"ConfigException: {e}")
            raise Exception(f"Failed to get current Kubernetes context: {e}")
        except Exception as e:
            self.command_output.append(f"Exception: {e}")
            raise Exception(f"Failed to get current Kubernetes context: {e}")



    def get_user_name(self, context_name):
        """
        Retrieves the user name from the specified context.
        """
        try:
            kubeconfig_to_use = self.get_current_kubeconfig()
            if not kubeconfig_to_use:
                raise Exception("No valid kubeconfig available.")

            # Load the kubeconfig using the proper method
            config.load_kube_config(config_file=kubeconfig_to_use)

            # Get all contexts and the active context
            contexts, active_context = config.list_kube_config_contexts()

            self.command_output.append(f"Number of contexts found: {len(contexts)}")

            # Find the specified context
            target_context = next((ctx for ctx in contexts if ctx['name'] == context_name), None)
            if not target_context:
                self.command_output.append(f"Context '{context_name}' not found in kubeconfig.")
                raise Exception(f"Context '{context_name}' not found in kubeconfig.")

            user_name = target_context['context']['user']
            self.command_output.append(f"User name retrieved: {user_name}")
            return user_name

        except config.ConfigException as e:
            self.command_output.append(f"ConfigException: {e}")
            raise Exception(f"Failed to get user name: {e}")
        except Exception as e:
            self.command_output.append(f"Exception: {e}")
            raise Exception(f"Failed to get user name: {e}")




    

    def get_server_url(self, context_name):
        """
        Retrieves the server URL from the specified context.
        """
        try:
            kubeconfig_to_use = self.get_current_kubeconfig()
            if not kubeconfig_to_use:
                self.command_output.append("No valid kubeconfig available.")
                raise Exception("No valid kubeconfig available.")

            # Load the kubeconfig file
            with open(kubeconfig_to_use, 'r') as f:
                kubeconfig = yaml.safe_load(f)

            # Find the specified context in the kubeconfig
            target_context = next(
                (ctx for ctx in kubeconfig['contexts'] if ctx['name'] == context_name), 
                None
            )
            if not target_context:
                self.command_output.append(f"Context '{context_name}' not found in kubeconfig.")
                raise Exception(f"Context '{context_name}' not found in kubeconfig.")

            cluster_name = target_context['context']['cluster']
            self.command_output.append(f"Cluster name: {cluster_name}")

            # Find the cluster information in the kubeconfig
            target_cluster = next(
                (cl for cl in kubeconfig['clusters'] if cl['name'] == cluster_name),
                None
            )
            if not target_cluster:
                self.command_output.append(f"Cluster '{cluster_name}' not found in kubeconfig.")
                raise Exception(f"Cluster '{cluster_name}' not found in kubeconfig.")

            server_url = target_cluster['cluster']['server']
            self.command_output.append(f"Server URL retrieved: {server_url}")
            return server_url

        except yaml.YAMLError as e:
            self.command_output.append(f"YAMLError: {e}")
            raise Exception(f"Failed to parse kubeconfig YAML: {e}")
        except Exception as e:
            self.command_output.append(f"Exception: {e}")
            raise Exception(f"Failed to get server URL: {e}")





    def get_certificate_authority(self, cluster_name):
        """
        Retrieves the certificate authority data from the specified cluster.
        Generates a new CA certificate and key if necessary.
        """
        try:
            kubeconfig_to_use = self.get_current_kubeconfig()
            if not kubeconfig_to_use:
                self.command_output.append("No valid kubeconfig available.")
                raise Exception("No valid kubeconfig available.")

            # Load the kubeconfig file
            with open(kubeconfig_to_use, 'r') as f:
                kubeconfig = yaml.safe_load(f)

            # Find the specified cluster in the kubeconfig
            target_cluster = next(
                (cl for cl in kubeconfig['clusters'] if cl['name'] == cluster_name),
                None
            )
            if not target_cluster:
                self.command_output.append(f"Cluster '{cluster_name}' not found in kubeconfig.")
                raise Exception(f"Cluster '{cluster_name}' not found in kubeconfig.")

            # Check for 'certificate-authority-data'
            if 'certificate-authority-data' in target_cluster['cluster']:
                self.command_output.append("Certificate authority data found in cluster configuration.")
                return target_cluster['cluster']['certificate-authority-data']
            else:
                # If 'certificate-authority-data' is not present, read from 'certificate-authority' file
                ca_path = target_cluster['cluster'].get('certificate-authority')
                if ca_path and os.path.exists(ca_path):
                    with open(ca_path, 'rb') as ca_file:
                        ca_data = ca_file.read()
                    self.command_output.append("Read certificate authority data from file.")
                    return base64.b64encode(ca_data).decode('utf-8')
                else:
                    # Generate a new CA certificate and key if none exist
                    ca_cert_path = os.path.join(tempfile.gettempdir(), f"{cluster_name}_ca.crt")
                    ca_key_path = os.path.join(tempfile.gettempdir(), f"{cluster_name}_ca.key")
                    self.command_output.append("No certificate authority data found. Generating new CA.")

                    # Generate the CA certificate and key
                    ca_cert_path, ca_key_path = self.generate_ca_certificate(ca_cert_path, ca_key_path)

                    # Read the generated CA certificate and encode it in base64
                    with open(ca_cert_path, 'rb') as ca_file:
                        ca_data = ca_file.read()

                    return base64.b64encode(ca_data).decode('utf-8')

        except yaml.YAMLError as e:
            self.command_output.append(f"YAMLError: {e}")
            raise Exception(f"Failed to parse kubeconfig YAML: {e}")
        except Exception as e:
            self.command_output.append(f"Exception: {e}")
            raise Exception(f"Failed to get certificate authority: {e}")

        
    def generate_ca_certificate(self, ca_cert_path, ca_key_path):
        """
        Generates a CA certificate and key.
        """
        try:
            self.command_output.append(f"Generating new CA certificate and key.")

            # Generate CA Key
            subprocess.run(
                ['openssl', 'genrsa', '-out', ca_key_path, '4096'],
                check=True, capture_output=True, text=True
            )

            # Generate CA Certificate
            subprocess.run(
                [
                    'openssl', 'req', '-x509', '-new', '-nodes', '-key', ca_key_path, '-sha256', '-days', '3650',
                    '-out', ca_cert_path, '-subj', "/CN=Kubernetes-CA"
                ],
                check=True, capture_output=True, text=True
            )

            self.command_output.append(f"Generated CA certificate at {ca_cert_path} and key at {ca_key_path}.")
            return ca_cert_path, ca_key_path

        except subprocess.CalledProcessError as e:
            self.command_output.append(f"Error generating CA certificate: {e.stderr}")
            raise Exception(f"Failed to generate CA certificate: {e.stderr}")
        except Exception as e:
            self.command_output.append(f"Unexpected error generating CA certificate: {e}")
            raise e




    def create_role(self):
        """Create a cluster role with full access and bind it to a specified user."""
        # Prompt for role name
        role_name, ok = QInputDialog.getText(self, 'Create Role', 'Enter new role name:')
        if not ok or not role_name.strip():
            self.command_output.append("Role creation canceled or invalid role name.")
            return
        role_name = role_name.strip()

        # Prompt for user name to bind the role
        user_name, ok = QInputDialog.getText(self, 'Bind User', 'Enter user name to bind to role:')
        if not ok or not user_name.strip():
            self.command_output.append("Role binding canceled or invalid user name.")
            return
        user_name = user_name.strip()

        # Start the worker to create and bind the role
        worker = Worker(self._create_and_bind_role, role_name, user_name)
        worker.signals.result.connect(self.on_role_creation_result)
        worker.signals.error.connect(self.on_error)
        worker.signals.finished.connect(self.on_role_creation_finished)

        self.user_execute_button.setEnabled(False)
        self.command_output.append(f"Creating role '{role_name}' and binding it to user '{user_name}'...")
        self.threadpool.start(worker)
        
        
    def _create_and_bind_role(self, role_name, user_name, progress_callback):
        """Function to create a cluster role with all access and bind it to a specified user."""
        temp_dir = tempfile.mkdtemp()
        cluster_role_yaml_path = os.path.join(temp_dir, f"{role_name}-clusterrole.yaml")
        role_binding_yaml_path = os.path.join(temp_dir, f"{role_name}-binding.yaml")

        kubeconfig_to_use = self.get_current_kubeconfig()
        if not kubeconfig_to_use:
            raise Exception("Failed to determine a valid kubeconfig to use.")

        try:
            # Step 1: Create a ClusterRole with full access
            cluster_role = {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRole",
                "metadata": {
                    "name": role_name
                },
                "rules": [
                    {
                        "apiGroups": ["*"],
                        "resources": ["*"],
                        "verbs": ["*"]
                    }
                ]
            }
            with open(cluster_role_yaml_path, 'w') as yaml_file:
                yaml.dump(cluster_role, yaml_file)
            self.command_output.append(f"Generated ClusterRole YAML at {cluster_role_yaml_path}")

            # Step 2: Apply the ClusterRole
            progress_callback.emit(50)
            subprocess.run(
                ['kubectl', 'apply', '-f', cluster_role_yaml_path, '--kubeconfig', kubeconfig_to_use],
                check=True, capture_output=True, text=True
            )
            self.command_output.append(f"Applied ClusterRole '{role_name}' to Kubernetes.")

            # Step 3: Create a ClusterRoleBinding
            role_binding = {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRoleBinding",
                "metadata": {
                    "name": f"{role_name}-binding"
                },
                "subjects": [
                    {
                        "kind": "User",
                        "name": user_name,
                        "apiGroup": "rbac.authorization.k8s.io"
                    }
                ],
                "roleRef": {
                    "kind": "ClusterRole",
                    "name": role_name,
                    "apiGroup": "rbac.authorization.k8s.io"
                }
            }
            with open(role_binding_yaml_path, 'w') as yaml_file:
                yaml.dump(role_binding, yaml_file)
            self.command_output.append(f"Generated ClusterRoleBinding YAML at {role_binding_yaml_path}")

            # Step 4: Apply the ClusterRoleBinding
            progress_callback.emit(90)
            subprocess.run(
                ['kubectl', 'apply', '-f', role_binding_yaml_path, '--kubeconfig', kubeconfig_to_use],
                check=True, capture_output=True, text=True
            )
            self.command_output.append(f"Bound role '{role_name}' to user '{user_name}'.")

            # Clean up temporary files
            shutil.rmtree(temp_dir)

            return f"Successfully created and bound ClusterRole '{role_name}' to user '{user_name}'."

        except subprocess.CalledProcessError as e:
            self.command_output.append(f"Subprocess error: {e.stderr}")
            raise Exception(f"Subprocess error: {e.stderr}")
        except Exception as e:
            self.command_output.append(f"Unexpected error: {e}")
            raise e
        
        
    
    def on_role_creation_result(self, result):
        """Handle the result of the role creation and binding function."""
        self.command_output.append(result)

    def on_role_creation_finished(self):
        """Re-enable the execute button after the role creation and binding operation is finished."""
        self.user_execute_button.setEnabled(True)
        
        
    # Create Service Account  
    def create_service_account(self):
        """Create a ServiceAccount with limited permissions within the default namespace."""
        # Prompt for ServiceAccount name
        service_account_name, ok = QInputDialog.getText(self, 'Create ServiceAccount', 'Enter ServiceAccount name:')
        if not ok or not service_account_name.strip():
            self.command_output.append("ServiceAccount creation canceled or invalid name.")
            return

        service_account_name = service_account_name.strip()

        # Prompt for Role name
        role_name, ok = QInputDialog.getText(self, 'Role Name', 'Enter role name for the ServiceAccount:')
        if not ok or not role_name.strip():
            self.command_output.append("Role creation canceled or invalid name.")
            return

        role_name = role_name.strip()

        # Prompt for namespace (default set to 'default')
        namespace, ok = QInputDialog.getText(self, 'Namespace', 'Enter namespace (default is "default"):', text="default")
        if not ok or not namespace.strip():
            self.command_output.append("Namespace selection canceled.")
            return

        namespace = namespace.strip()

        # Start the worker to create the ServiceAccount
        worker = Worker(self._create_service_account, service_account_name, role_name, namespace)
        worker.signals.result.connect(self.on_create_service_account_result)
        worker.signals.error.connect(self.on_error)
        worker.signals.finished.connect(self.on_create_service_account_finished)

        self.user_execute_button.setEnabled(False)
        self.command_output.append(f"Starting creation of ServiceAccount '{service_account_name}'...")
        self.threadpool.start(worker)

    def _create_service_account(self, service_account_name, role_name, namespace, progress_callback):
        """
        Create a ServiceAccount with a role in the specified namespace and generate a kubeconfig file for it.
        """
        temp_dir = tempfile.mkdtemp()
        sa_yaml_path = os.path.join(temp_dir, f"{service_account_name}-sa.yaml")
        role_yaml_path = os.path.join(temp_dir, f"{role_name}-role.yaml")
        role_binding_yaml_path = os.path.join(temp_dir, f"{role_name}-rolebinding.yaml")
        kubeconfig_path = os.path.join(temp_dir, f"{service_account_name}-kubeconfig.yaml")

        kubeconfig_to_use = self.get_current_kubeconfig()
        if not kubeconfig_to_use:
            self.command_output.append("Failed to determine a valid kubeconfig to use.")
            return

        def generate_unique_name(base_name):
            """Generate a unique name if the base name already exists."""
            return f"{base_name}-{''.join(random.choices(string.ascii_lowercase + string.digits, k=5))}"

        try:
            # Initialize Kubernetes API client
            config.load_kube_config(config_file=kubeconfig_to_use)
            v1_api = client.CoreV1Api()
            rbac_api = client.RbacAuthorizationV1Api()

            # Check if ServiceAccount already exists and create a unique name if needed
            try:
                v1_api.read_namespaced_service_account(name=service_account_name, namespace=namespace)
                original_service_account_name = service_account_name  # Keep track of the original name
                service_account_name = generate_unique_name(service_account_name)
                self.command_output.append(f"ServiceAccount '{original_service_account_name}' exists. Using new name '{service_account_name}'.")
            except ApiException as e:
                if e.status != 404:
                    raise

            # Step 1: Create ServiceAccount YAML and apply it
            service_account_yaml = {
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                "metadata": {
                    "name": service_account_name,
                    "namespace": namespace
                }
            }
            with open(sa_yaml_path, 'w') as yaml_file:
                yaml.dump(service_account_yaml, yaml_file)

            subprocess.run(
                ['kubectl', 'apply', '-f', sa_yaml_path, '--kubeconfig', kubeconfig_to_use],
                check=True, capture_output=True, text=True
            )
            self.command_output.append(f"Applied ServiceAccount '{service_account_name}' to namespace '{namespace}'.")
            progress_callback.emit(10)

            # Check if the secret already exists and create a unique name if needed
            secret_name = f"{service_account_name}-token"
            try:
                v1_api.read_namespaced_secret(name=secret_name, namespace=namespace)
                original_secret_name = secret_name  # Keep track of the original name
                secret_name = generate_unique_name(secret_name)
                self.command_output.append(f"Secret '{original_secret_name}' exists. Using new name '{secret_name}'.")
            except ApiException as e:
                if e.status != 404:
                    raise

            # Step 2: Create a secret of type service-account-token associated with the ServiceAccount
            secret_yaml = {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {
                    "name": secret_name,
                    "namespace": namespace,
                    "annotations": {
                        "kubernetes.io/service-account.name": service_account_name
                    }
                },
                "type": "kubernetes.io/service-account-token"
            }

            secret_yaml_path = os.path.join(temp_dir, f"{secret_name}-secret.yaml")
            with open(secret_yaml_path, 'w') as yaml_file:
                yaml.dump(secret_yaml, yaml_file)

            subprocess.run(
                ['kubectl', 'apply', '-f', secret_yaml_path, '--kubeconfig', kubeconfig_to_use],
                check=True, capture_output=True, text=True
            )
            self.command_output.append(f"Created token secret '{secret_name}' for ServiceAccount '{service_account_name}'.")

            # Check if Role already exists and create a unique name if needed
            try:
                rbac_api.read_namespaced_role(name=role_name, namespace=namespace)
                original_role_name = role_name  # Keep track of the original name
                role_name = generate_unique_name(role_name)
                self.command_output.append(f"Role '{original_role_name}' exists. Using new name '{role_name}'.")
            except ApiException as e:
                if e.status != 404:
                    raise

            # Step 3: Create Role YAML and apply it
            role_yaml = {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "Role",
                "metadata": {
                    "namespace": namespace,
                    "name": role_name
                },
                "rules": [
                    {
                        "apiGroups": [""],
                        "resources": ["pods", "services", "configmaps"],
                        "verbs": ["get", "list", "watch"]
                    }
                ]
            }
            with open(role_yaml_path, 'w') as yaml_file:
                yaml.dump(role_yaml, yaml_file)

            subprocess.run(
                ['kubectl', 'apply', '-f', role_yaml_path, '--kubeconfig', kubeconfig_to_use],
                check=True, capture_output=True, text=True
            )
            self.command_output.append(f"Applied Role '{role_name}' to namespace '{namespace}'.")
            progress_callback.emit(30)

            # Step 4: Create RoleBinding YAML and apply it
            role_binding_name = f"{service_account_name}-rolebinding"
            try:
                rbac_api.read_namespaced_role_binding(name=role_binding_name, namespace=namespace)
                original_role_binding_name = role_binding_name  # Keep track of the original name
                role_binding_name = generate_unique_name(role_binding_name)
                self.command_output.append(f"RoleBinding '{original_role_binding_name}' exists. Using new name '{role_binding_name}'.")
            except ApiException as e:
                if e.status != 404:
                    raise

            role_binding_yaml = {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "RoleBinding",
                "metadata": {
                    "name": role_binding_name,
                    "namespace": namespace
                },
                "subjects": [
                    {
                        "kind": "ServiceAccount",
                        "name": service_account_name,
                        "namespace": namespace
                    }
                ],
                "roleRef": {
                    "kind": "Role",
                    "name": role_name,
                    "apiGroup": "rbac.authorization.k8s.io"
                }
            }
            with open(role_binding_yaml_path, 'w') as yaml_file:
                yaml.dump(role_binding_yaml, yaml_file)

            subprocess.run(
                ['kubectl', 'apply', '-f', role_binding_yaml_path, '--kubeconfig', kubeconfig_to_use],
                check=True, capture_output=True, text=True
            )
            self.command_output.append(f"Bound Role '{role_name}' to ServiceAccount '{service_account_name}'.")
            progress_callback.emit(50)

            # Step 5: Retrieve the token associated with the secret
            secret_data = v1_api.read_namespaced_secret(name=secret_name, namespace=namespace)
            token_base64 = secret_data.data['token']
            token = base64.b64decode(token_base64).decode('utf-8')

            # Step 6: Generate kubeconfig for external access
            current_cluster = self.get_cluster_name(self.get_current_context())
            current_server = self.get_server_url(self.get_current_context())
            kubeconfig = {
                "apiVersion": "v1",
                "kind": "Config",
                "clusters": [
                    {
                        "cluster": {
                            "certificate-authority-data": self.get_certificate_authority(current_cluster),
                            "server": current_server
                        },
                        "name": current_cluster
                    }
                ],
                "contexts": [
                    {
                        "context": {
                            "cluster": current_cluster,
                            "user": service_account_name,
                            "namespace": namespace
                        },
                        "name": f"{service_account_name}@{current_cluster}"
                    }
                ],
                "current-context": f"{service_account_name}@{current_cluster}",
                "users": [
                    {
                        "name": service_account_name,
                        "user": {
                            "token": token
                        }
                    }
                ]
            }

            with open(kubeconfig_path, 'w') as kc_file:
                yaml.dump(kubeconfig, kc_file)
            self.command_output.append(f"Generated kubeconfig for ServiceAccount '{service_account_name}' at {kubeconfig_path}")
            progress_callback.emit(80)

            # Return the kubeconfig path for saving
            return kubeconfig_path

        except ApiException as e:
            error_message = f"API error: {e.status} {e.reason} - {e.body}"
            self.command_output.append(error_message)
        except subprocess.CalledProcessError as e:
            self.command_output.append(f"Subprocess error: {e.stderr}")
        except Exception as e:
            self.command_output.append(f"Unexpected error: {e}")


    @pyqtSlot(str)
    def _clean_up_temp_dir(self, temp_dir):
        try:
            shutil.rmtree(temp_dir)
            self.command_output.append(f"Cleaned up temporary directory {temp_dir}.")
        except Exception as cleanup_error:
            self.command_output.append(f"Failed to clean up temporary directory: {cleanup_error}")

    def on_create_service_account_result(self, kubeconfig_path):
        """
        Handle the result of the create_service_account function by prompting the user to save the kubeconfig file.
        """
        # Check if kubeconfig_path is valid
        if kubeconfig_path is None:
            self.command_output.append("Failed to generate kubeconfig. Please check for any errors.")
            return

        # Extract the temporary directory from the kubeconfig path
        temp_dir = os.path.dirname(kubeconfig_path)

        # Prompt the user to select where to save the kubeconfig
        save_path, _ = QFileDialog.getSaveFileName(
            self, "Save Kubeconfig", f"{os.path.expanduser('~')}/kubeconfig-{os.path.basename(kubeconfig_path)}",
            "YAML Files (*.yaml);;All Files (*)"
        )

        if save_path:
            try:
                shutil.copy(kubeconfig_path, save_path)
                self.command_output.append(f"Kubeconfig saved to {save_path}")
            except Exception as e:
                self.command_output.append(f"Failed to save kubeconfig: {e}")
        else:
            self.command_output.append("Kubeconfig save canceled.")

        # Clean up the temporary directory after saving or canceling
        self._clean_up_temp_dir(temp_dir)


    def on_create_service_account_finished(self):
        """Re-enable the execute button after the role creation and binding operation is finished."""
        self.user_execute_button.setEnabled(True)

    







    

        
    
        
        
   


            
            
    # ###########    Management Actions    ########################################

    def execute_management_action(self):
        """Execute the selected management action using a worker thread."""
        selected_action = self.action_selector.currentText()
        if selected_action == "Select Action":
            self.command_output.append("Please select a valid action.")
            return

        if selected_action == "Configure Ingress":
            self.configure_ingress()
        elif selected_action == "Configure Volume":
            self.create_volume()
        elif selected_action == "Configure ConfigMap or Secret":
            self.create_configmap_or_secret()
        elif selected_action == "Configure Data Backup":
            self.configure_data_backup()
        elif selected_action == "Configure Namespace":
            self.configure_namespace()


    def configure_ingress(self):
        """Display a dialog to choose Ingress actions (Install, Upgrade, Uninstall)."""
        # Ask user to choose the action for ingress
        action_options = ["Install", "Upgrade", "Uninstall"]
        action, ok = QInputDialog.getItem(self, "Configure Ingress", "Select Action:", action_options, 0, False)

        if not ok or action not in action_options:
            self.command_output.append("No valid action selected for ingress configuration.")
            return

        # Ask for the release name
        release_name, ok = QInputDialog.getText(self, 'Release Name', 'Enter Release Name:')
        if not ok or not release_name:
            self.command_output.append("No release name provided.")
            return

        # Disable execute button during operation
        self.execute_button.setEnabled(False)

        # Execute action based on user selection
        if action == "Install":
            worker = Worker(self.install_ingress, release_name)
        elif action == "Upgrade":
            worker = Worker(self.upgrade_ingress, release_name)
        elif action == "Uninstall":
            worker = Worker(self.uninstall_ingress, release_name)
        else:
            self.command_output.append("Invalid action selected.")
            self.execute_button.setEnabled(True)
            return

        worker.signals.result.connect(self.on_action_result)
        worker.signals.error.connect(self.on_error)
        worker.signals.finished.connect(self.on_action_finished)

        self.threadpool.start(worker)

    def generate_insecure_kubeconfig(self):
        """Generate a temporary kubeconfig with SSL verification disabled."""
        try:
            with open(self.kubeconfig_path, 'r') as f:
                kubeconfig = yaml.safe_load(f)
                if not kubeconfig:
                    raise Exception("Original kubeconfig is empty.")

            # Deep copy to avoid modifying the original kubeconfig
            insecure_kubeconfig = deepcopy(kubeconfig)

            current_context_name = self.context_selector.currentText()
            if not current_context_name or current_context_name == "Select Kubernetes Context":
                self.command_output.append("No valid context selected.")
                return None
            self.command_output.append(f"Current context: {current_context_name}")

            context = next((ctx for ctx in insecure_kubeconfig.get('contexts', []) if ctx['name'] == current_context_name), None)
            if not context:
                self.command_output.append("Selected context not found in kubeconfig.")
                return None

            cluster_name = context['context']['cluster']
            self.command_output.append(f"Cluster name: {cluster_name}")
            cluster = next((cl for cl in insecure_kubeconfig.get('clusters', []) if cl['name'] == cluster_name), None)
            if not cluster:
                self.command_output.append("Associated cluster not found in kubeconfig.")
                return None

            # Disable SSL verification
            cluster['cluster']['insecure-skip-tls-verify'] = True
            # Optionally, remove 'certificate-authority' and 'certificate-authority-data' if present
            cluster['cluster'].pop('certificate-authority', None)
            cluster['cluster'].pop('certificate-authority-data', None)

            # Validate the modified kubeconfig
            contexts = insecure_kubeconfig.get('contexts', [])
            clusters = insecure_kubeconfig.get('clusters', [])
            users = insecure_kubeconfig.get('users', [])
            if not contexts or not clusters or not users:
                self.command_output.append("Insecure kubeconfig is missing contexts, clusters, or users.")
                return None

            # Create a temporary file to store the insecure kubeconfig in text mode
            temp_kubeconfig = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".kubeconfig")
            yaml.dump(insecure_kubeconfig, temp_kubeconfig)
            temp_kubeconfig.close()

            self.command_output.append(f"Generated temporary insecure kubeconfig at {temp_kubeconfig.name}")
            self.temp_kubeconfig = temp_kubeconfig.name  # Store the path
            return temp_kubeconfig.name

        except Exception as e:
            self.command_output.append(f"Error generating insecure kubeconfig: {e}")
            return None


    def check_existing_resources(self, kubeconfig_to_use):
        """Check if ingress-nginx ClusterRole, ClusterRoleBinding, IngressClass, and ValidatingWebhookConfiguration already exist."""
        resources_exist = {}
        try:
            # Check ClusterRole
            cmd_role = [
                'kubectl', 'get', 'clusterrole', 'ingress-nginx',
                '--kubeconfig', kubeconfig_to_use
            ]
            result_role = subprocess.run(cmd_role, capture_output=True, text=True)
            resources_exist['ClusterRole'] = (result_role.returncode == 0)
            
            # Check ClusterRoleBinding
            cmd_binding = [
                'kubectl', 'get', 'clusterrolebinding', 'ingress-nginx',
                '--kubeconfig', kubeconfig_to_use
            ]
            result_binding = subprocess.run(cmd_binding, capture_output=True, text=True)
            resources_exist['ClusterRoleBinding'] = (result_binding.returncode == 0)
            
            # Check IngressClass
            cmd_ingressclass = [
                'kubectl', 'get', 'ingressclass', 'nginx',
                '--kubeconfig', kubeconfig_to_use
            ]
            result_ingressclass = subprocess.run(cmd_ingressclass, capture_output=True, text=True)
            resources_exist['IngressClass'] = (result_ingressclass.returncode == 0)
            
            # Check ValidatingWebhookConfiguration
            cmd_vwc = [
                'kubectl', 'get', 'validatingwebhookconfiguration', 'ingress-nginx-admission',
                '--kubeconfig', kubeconfig_to_use
            ]
            result_vwc = subprocess.run(cmd_vwc, capture_output=True, text=True)
            resources_exist['ValidatingWebhookConfiguration'] = (result_vwc.returncode == 0)
            
            return resources_exist
        except Exception as e:
            self.command_output.append(f"Error checking existing resources: {e}")
            return resources_exist

    def delete_clusterrole(self, kubeconfig_to_use):
        """Delete the existing ingress-nginx ClusterRole."""
        try:
            delete_cmd = [
                'kubectl', 'delete', 'clusterrole', 'ingress-nginx',
                '--kubeconfig', kubeconfig_to_use
            ]
            delete_result = subprocess.run(delete_cmd, capture_output=True, text=True)
            if delete_result.returncode == 0:
                self.command_output.append("Deleted existing ClusterRole 'ingress-nginx'.")
                return True
            else:
                self.command_output.append(f"Error deleting ClusterRole: {delete_result.stderr}")
                return False
        except Exception as e:
            self.command_output.append(f"Error deleting ClusterRole: {e}")
            return False

    def delete_clusterrolebinding(self, kubeconfig_to_use):
        """Delete the existing ingress-nginx ClusterRoleBinding."""
        try:
            delete_cmd = [
                'kubectl', 'delete', 'clusterrolebinding', 'ingress-nginx',
                '--kubeconfig', kubeconfig_to_use
            ]
            delete_result = subprocess.run(delete_cmd, capture_output=True, text=True)
            if delete_result.returncode == 0:
                self.command_output.append("Deleted existing ClusterRoleBinding 'ingress-nginx'.")
                return True
            else:
                self.command_output.append(f"Error deleting ClusterRoleBinding: {delete_result.stderr}")
                return False
        except Exception as e:
            self.command_output.append(f"Error deleting ClusterRoleBinding: {e}")
            return False

    def delete_ingressclass(self, kubeconfig_to_use):
        """Delete the existing ingress-nginx IngressClass."""
        try:
            delete_cmd = [
                'kubectl', 'delete', 'ingressclass', 'nginx',
                '--kubeconfig', kubeconfig_to_use
            ]
            delete_result = subprocess.run(delete_cmd, capture_output=True, text=True)
            if delete_result.returncode == 0:
                self.command_output.append("Deleted existing IngressClass 'nginx'.")
                return True
            else:
                self.command_output.append(f"Error deleting IngressClass: {delete_result.stderr}")
                return False
        except Exception as e:
            self.command_output.append(f"Error deleting IngressClass: {e}")
            return False

    def delete_validatingwebhookconfiguration(self, kubeconfig_to_use):
        """Delete the existing ingress-nginx-admission ValidatingWebhookConfiguration."""
        try:
            delete_cmd = [
                'kubectl', 'delete', 'validatingwebhookconfiguration', 'ingress-nginx-admission',
                '--kubeconfig', kubeconfig_to_use
            ]
            delete_result = subprocess.run(delete_cmd, capture_output=True, text=True)
            if delete_result.returncode == 0:
                self.command_output.append("Deleted existing ValidatingWebhookConfiguration 'ingress-nginx-admission'.")
                return True
            else:
                self.command_output.append(f"Error deleting ValidatingWebhookConfiguration: {delete_result.stderr}")
                return False
        except Exception as e:
            self.command_output.append(f"Error deleting ValidatingWebhookConfiguration: {e}")
            return False

    def clean_up_temp_kubeconfig(self):
        """Remove the temporary kubeconfig if it exists."""
        if self.temp_kubeconfig and os.path.exists(self.temp_kubeconfig):
            try:
                os.remove(self.temp_kubeconfig)
                self.command_output.append(f"Removed temporary kubeconfig: {self.temp_kubeconfig}")
                self.temp_kubeconfig = None
            except Exception as e:
                self.command_output.append(f"Error removing temporary kubeconfig: {e}")

    def install_ingress(self, release_name, progress_callback):
        """Install ingress-nginx using Helm."""
        try:
            # Determine which kubeconfig to use
            if not self.ssl_verification:
                temp_kubeconfig = self.generate_insecure_kubeconfig()
                if not temp_kubeconfig:
                    self.command_output.append("Failed to generate insecure kubeconfig.")
                    return
                kubeconfig_to_use = temp_kubeconfig
            else:
                kubeconfig_to_use = self.kubeconfig_path

            # Get the selected namespace
            selected_namespace = self.namespace_selector.currentText()
            if not selected_namespace:
                self.command_output.append("No namespace selected.")
                self.clean_up_temp_kubeconfig()
                return

            # Check for existing resources
            existing_resources = self.check_existing_resources(kubeconfig_to_use)

            # Handle ClusterRole
            if existing_resources.get('ClusterRole', False):
                reply = QMessageBox.question(
                    self, 'Resource Exists',
                    "ClusterRole 'ingress-nginx' already exists. Do you want to delete it and proceed with installation?",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No
                )
                if reply == QMessageBox.Yes:
                    if not self.delete_clusterrole(kubeconfig_to_use):
                        self.command_output.append("Failed to delete existing ClusterRole. Installation aborted.")
                        self.clean_up_temp_kubeconfig()
                        return
                else:
                    self.command_output.append("Installation aborted by the user.")
                    self.clean_up_temp_kubeconfig()
                    return

            # Handle ClusterRoleBinding
            if existing_resources.get('ClusterRoleBinding', False):
                reply = QMessageBox.question(
                    self, 'Resource Exists',
                    "ClusterRoleBinding 'ingress-nginx' already exists. Do you want to delete it and proceed with installation?",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No
                )
                if reply == QMessageBox.Yes:
                    if not self.delete_clusterrolebinding(kubeconfig_to_use):
                        self.command_output.append("Failed to delete existing ClusterRoleBinding. Installation aborted.")
                        self.clean_up_temp_kubeconfig()
                        return
                else:
                    self.command_output.append("Installation aborted by the user.")
                    self.clean_up_temp_kubeconfig()
                    return

            # Handle IngressClass
            if existing_resources.get('IngressClass', False):
                reply = QMessageBox.question(
                    self, 'Resource Exists',
                    "IngressClass 'nginx' already exists. Do you want to delete it and proceed with installation?",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No
                )
                if reply == QMessageBox.Yes:
                    if not self.delete_ingressclass(kubeconfig_to_use):
                        self.command_output.append("Failed to delete existing IngressClass. Installation aborted.")
                        self.clean_up_temp_kubeconfig()
                        return
                else:
                    self.command_output.append("Installation aborted by the user.")
                    self.clean_up_temp_kubeconfig()
                    return

            # Handle ValidatingWebhookConfiguration
            if existing_resources.get('ValidatingWebhookConfiguration', False):
                reply = QMessageBox.question(
                    self, 'Resource Exists',
                    "ValidatingWebhookConfiguration 'ingress-nginx-admission' already exists. Do you want to delete it and proceed with installation?",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No
                )
                if reply == QMessageBox.Yes:
                    if not self.delete_validatingwebhookconfiguration(kubeconfig_to_use):
                        self.command_output.append("Failed to delete existing ValidatingWebhookConfiguration. Installation aborted.")
                        self.clean_up_temp_kubeconfig()
                        return
                else:
                    self.command_output.append("Installation aborted by the user.")
                    self.clean_up_temp_kubeconfig()
                    return

            # Define Helm command parameters
            helm_command = [
                'helm', 'install', release_name, 'ingress-nginx/ingress-nginx',
                '--kube-context', self.context_selector.currentText(),
                '--kubeconfig', kubeconfig_to_use,
                '--namespace', selected_namespace,
                '--create-namespace'  # Create namespace if it doesn't exist
            ]

            # Execute the Helm command via subprocess
            result = subprocess.run(helm_command, capture_output=True, text=True)
            if result.returncode != 0:
                # Raise CalledProcessError with stderr
                raise subprocess.CalledProcessError(result.returncode, helm_command, output=result.stdout, stderr=result.stderr)
            self.command_output.append(f"Successfully installed ingress-nginx with release name: {release_name}")
            self.command_output.append(result.stdout)

        except subprocess.CalledProcessError as e:
            self.command_output.append(f"Error installing ingress-nginx: {e.stderr}")
        except Exception as e:
            self.command_output.append(f"Unexpected error during installation: {e}")
        finally:
            # Clean up the temporary kubeconfig if it was used
            self.clean_up_temp_kubeconfig()

    def upgrade_ingress(self, release_name, progress_callback):
        """Upgrade ingress-nginx using Helm."""
        try:
            # Determine which kubeconfig to use
            if not self.ssl_verification:
                temp_kubeconfig = self.generate_insecure_kubeconfig()
                if not temp_kubeconfig:
                    self.command_output.append("Failed to generate insecure kubeconfig.")
                    return
                kubeconfig_to_use = temp_kubeconfig
            else:
                kubeconfig_to_use = self.kubeconfig_path

            # Get the selected namespace
            selected_namespace = self.namespace_selector.currentText()
            if not selected_namespace:
                self.command_output.append("No namespace selected.")
                self.clean_up_temp_kubeconfig()
                return

            # Define Helm command parameters
            helm_command = [
                'helm', 'upgrade', release_name, 'ingress-nginx/ingress-nginx',
                '--kube-context', self.context_selector.currentText(),
                '--kubeconfig', kubeconfig_to_use,
                '--namespace', selected_namespace
            ]

            # Execute the Helm command via subprocess
            result = subprocess.run(helm_command, capture_output=True, text=True)
            if result.returncode != 0:
                raise subprocess.CalledProcessError(result.returncode, helm_command, output=result.stdout, stderr=result.stderr)
            self.command_output.append(f"Ingress-nginx '{release_name}' upgraded successfully.")
            self.command_output.append(result.stdout)

        except subprocess.CalledProcessError as e:
            self.command_output.append(f"Error upgrading ingress-nginx: {e.stderr}")
        except Exception as e:
            self.command_output.append(f"Unexpected error during upgrade: {e}")
        finally:
            # Clean up the temporary kubeconfig if it was used
            self.clean_up_temp_kubeconfig()

    def uninstall_ingress(self, release_name, progress_callback):
        """Uninstall ingress-nginx using Helm."""
        try:
            # Determine which kubeconfig to use
            if not self.ssl_verification:
                temp_kubeconfig = self.generate_insecure_kubeconfig()
                if not temp_kubeconfig:
                    self.command_output.append("Failed to generate insecure kubeconfig.")
                    return
                kubeconfig_to_use = temp_kubeconfig
            else:
                kubeconfig_to_use = self.kubeconfig_path

            # Get the selected namespace
            selected_namespace = self.namespace_selector.currentText()
            if not selected_namespace:
                self.command_output.append("No namespace selected.")
                self.clean_up_temp_kubeconfig()
                return

            # Define Helm command parameters
            helm_command = [
                'helm', 'uninstall', release_name,
                '--kube-context', self.context_selector.currentText(),
                '--kubeconfig', kubeconfig_to_use,
                '--namespace', selected_namespace
            ]

            # Execute the Helm command via subprocess
            result = subprocess.run(helm_command, capture_output=True, text=True)
            if result.returncode != 0:
                raise subprocess.CalledProcessError(result.returncode, helm_command, output=result.stdout, stderr=result.stderr)
            self.command_output.append(f"Ingress-nginx '{release_name}' uninstalled successfully.")
            self.command_output.append(result.stdout)

        except subprocess.CalledProcessError as e:
            self.command_output.append(f"Error uninstalling ingress-nginx: {e.stderr}")
        except Exception as e:
            self.command_output.append(f"Unexpected error during uninstallation: {e}")
        finally:
            # Clean up the temporary kubeconfig if it was used
            self.clean_up_temp_kubeconfig()

    def on_action_result(self, result):
        """Handle the result of an action (install, upgrade, uninstall)."""
        self.command_output.append(result)

    def on_action_finished(self):
        """Re-enable execute button after action is finished."""
        self.execute_button.setEnabled(True)

    def get_current_kubeconfig(self):
        """Determine which kubeconfig to use based on SSL verification."""
        if not self.ssl_verification:
            if self.temp_kubeconfig and os.path.exists(self.temp_kubeconfig):
                self.command_output.append(f"Using temporary insecure kubeconfig: {self.temp_kubeconfig}")
                return self.temp_kubeconfig
            else:
                temp_kubeconfig = self.generate_insecure_kubeconfig()
                if temp_kubeconfig and os.path.exists(temp_kubeconfig):
                    self.command_output.append(f"Using newly generated insecure kubeconfig: {temp_kubeconfig}")
                    return temp_kubeconfig
                else:
                    self.command_output.append("Failed to generate insecure kubeconfig.")
                    return None
        else:
            if os.path.exists(self.kubeconfig_path):
                self.command_output.append(f"Using default kubeconfig: {self.kubeconfig_path}")
                return self.kubeconfig_path
            else:
                self.command_output.append(f"Default kubeconfig not found: {self.kubeconfig_path}")
                return None


    # Volume Management
    def create_volume(self):
        """Create a Persistent Volume and Persistent Volume Claim within the selected namespace."""
        # Prompt for volume name
        volume_name, ok = QInputDialog.getText(self, 'Create Volume', 'Enter volume name:')
        if not ok or not volume_name.strip():
            self.command_output.append("Volume creation canceled or invalid name.")
            return

        volume_name = volume_name.strip()

        # Get the current selected namespace from the dropdown
        namespace = self.namespace_selector.currentText()
        if not namespace.strip():
            self.command_output.append("Invalid namespace selected.")
            return

        # Start the worker to create the Volume
        worker = Worker(self._create_volume, volume_name, namespace)
        worker.signals.result.connect(self.on_create_volume_result)
        worker.signals.error.connect(self.on_error)
        worker.signals.finished.connect(self.on_create_volume_finished)

        self.user_execute_button.setEnabled(False)
        self.command_output.append(f"Starting creation of Volume '{volume_name}' in namespace '{namespace}'...")
        self.threadpool.start(worker)
        
    def _create_volume(self, volume_name, namespace, progress_callback):
        """Create a Persistent Volume and Persistent Volume Claim with 10Gi and RWM access."""
        temp_dir = tempfile.mkdtemp()
        pv_yaml_path = os.path.join(temp_dir, f"{volume_name}-pv.yaml")
        pvc_yaml_path = os.path.join(temp_dir, f"{volume_name}-pvc.yaml")

        # Define PV and PVC YAML configurations
        pv_yaml = {
            "apiVersion": "v1",
            "kind": "PersistentVolume",
            "metadata": {
                "name": volume_name
            },
            "spec": {
                "capacity": {
                    "storage": "10Gi"
                },
                "accessModes": [
                    "ReadWriteMany"
                ],
                "persistentVolumeReclaimPolicy": "Retain",
                "hostPath": {
                    "path": f"/mnt/data/{volume_name}"  # Use a path in your environment
                }
            }
        }

        pvc_yaml = {
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": {
                "name": f"{volume_name}-claim",
                "namespace": namespace
            },
            "spec": {
                "accessModes": [
                    "ReadWriteMany"
                ],
                "resources": {
                    "requests": {
                        "storage": "10Gi"
                    }
                },
                "volumeName": volume_name  # Ensure PVC is bound to PV
            }
        }

        try:
            # Write PV YAML to file
            with open(pv_yaml_path, 'w') as yaml_file:
                yaml.dump(pv_yaml, yaml_file)

            # Write PVC YAML to file
            with open(pvc_yaml_path, 'w') as yaml_file:
                yaml.dump(pvc_yaml, yaml_file)

            kubeconfig_to_use = self.get_current_kubeconfig()
            if not kubeconfig_to_use:
                self.command_output.append("Failed to determine a valid kubeconfig to use.")
                return

            # Apply PV
            subprocess.run(
                ['kubectl', 'apply', '-f', pv_yaml_path, '--kubeconfig', kubeconfig_to_use],
                check=True, capture_output=True, text=True
            )
            self.command_output.append(f"PersistentVolume '{volume_name}' created.")
            progress_callback.emit(50)

            # Apply PVC
            subprocess.run(
                ['kubectl', 'apply', '-f', pvc_yaml_path, '--kubeconfig', kubeconfig_to_use],
                check=True, capture_output=True, text=True
            )
            self.command_output.append(f"PersistentVolumeClaim '{volume_name}-claim' created in namespace '{namespace}'.")
            progress_callback.emit(80)

            # Wait for the PVC to bind
            self.wait_for_pvc_binding(volume_name, namespace, kubeconfig_to_use)

        except subprocess.CalledProcessError as e:
            self.command_output.append(f"Subprocess error: {e.stderr}")
        except Exception as e:
            self.command_output.append(f"Unexpected error: {e}")
        finally:
            # Cleanup temporary directory
            self._clean_up_temp_dir(temp_dir)
            
            
    def on_create_volume_result(self, result):
        """Handle the result of volume creation (optional if there's a return value)."""
        self.command_output.append("Volume creation completed.")

    def on_create_volume_finished(self):
        """Re-enable the execute button after volume creation is finished."""
        self.user_execute_button.setEnabled(True)
        self.command_output.append("Volume creation process finished.")


 # ConfigMap or Secret
    def create_configmap_or_secret(self):
        """Prompt user for details and create a ConfigMap or Secret."""
        # Prompt for the type of resource to create (ConfigMap or Secret)
        resource_type, ok = QInputDialog.getItem(
            self, "Select Resource", "Create ConfigMap or Secret:", ["ConfigMap", "Secret"], 0, False
        )
        if not ok or not resource_type.strip():
            self.command_output.append("Resource creation canceled.")
            return

        # Prompt for the resource name
        resource_name, ok = QInputDialog.getText(self, f'Create {resource_type}', f'Enter {resource_type} name:')
        if not ok or not resource_name.strip():
            self.command_output.append(f"{resource_type} creation canceled or invalid name.")
            return
        resource_name = resource_name.strip()

        # Use the selected namespace from the namespace_selector dropdown
        namespace = self.namespace_selector.currentText()
        if not namespace:
            self.command_output.append("No namespace selected. Please select a namespace before creating the resource.")
            return

        # Prompt for key-value pairs to add
        data = {}
        while True:
            key, ok = QInputDialog.getText(self, f'Add Data to {resource_type}', 'Enter key (or leave blank to finish):')
            if not ok or not key.strip():
                break

            value, ok = QInputDialog.getText(self, f'Add Data to {resource_type}', f'Enter value for key "{key}":')
            if not ok or not value.strip():
                continue

            data[key.strip()] = value.strip()

        if not data:
            self.command_output.append(f"No data provided for {resource_type}. Creation canceled.")
            return

        # Start the worker to create the ConfigMap or Secret
        worker = Worker(self._create_configmap_or_secret, resource_type, resource_name, namespace, data)
        worker.signals.result.connect(self.on_create_resource_result)
        worker.signals.error.connect(self.on_error)
        worker.signals.finished.connect(self.on_create_resource_finished)

        self.user_execute_button.setEnabled(False)
        self.command_output.append(f"Starting creation of {resource_type} '{resource_name}' in namespace '{namespace}'...")
        self.threadpool.start(worker)



    def _create_configmap_or_secret(self, resource_type, resource_name, namespace, data, progress_callback):
        """Create a ConfigMap or Secret with the specified data."""
        temp_dir = tempfile.mkdtemp()
        resource_yaml_path = os.path.join(temp_dir, f"{resource_name}-{resource_type.lower()}.yaml")

        # Generate YAML structure
        if resource_type == "ConfigMap":
            resource_yaml = {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {
                    "name": resource_name,
                    "namespace": namespace
                },
                "data": data  # Add the key-value pairs directly to 'data'
            }
        elif resource_type == "Secret":
            # Encode data values to base64 as required for secrets
            data_b64 = {k: base64.b64encode(v.encode()).decode() for k, v in data.items()}
            resource_yaml = {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {
                    "name": resource_name,
                    "namespace": namespace
                },
                "data": data_b64  # Add base64-encoded key-value pairs to 'data'
            }

        try:
            # Write resource YAML to file
            with open(resource_yaml_path, 'w') as yaml_file:
                yaml.dump(resource_yaml, yaml_file)

            kubeconfig_to_use = self.get_current_kubeconfig()
            if not kubeconfig_to_use:
                self.command_output.append("Failed to determine a valid kubeconfig to use.")
                return

            # Apply resource using kubectl
            subprocess.run(
                ['kubectl', 'apply', '-f', resource_yaml_path, '--kubeconfig', kubeconfig_to_use],
                check=True, capture_output=True, text=True
            )
            self.command_output.append(f"{resource_type} '{resource_name}' created in namespace '{namespace}'.")
            progress_callback.emit(100)

        except subprocess.CalledProcessError as e:
            self.command_output.append(f"Subprocess error: {e.stderr}")
        except Exception as e:
            self.command_output.append(f"Unexpected error: {e}")
        finally:
            # Cleanup temporary directory
            self._clean_up_temp_dir(temp_dir)
            
            
    def on_create_resource_result(self, result):
        """Handle the result of resource creation (optional if there's a return value)."""
        self.command_output.append("Resource creation completed.")

    def on_create_resource_finished(self):
        """Re-enable the execute button after resource creation is finished."""
        self.user_execute_button.setEnabled(True)
        self.command_output.append("Resource creation process finished.")


    # Backup Data Etcd

    def configure_data_backup(self):
        """Handle backup and restore for etcd data."""
        # Ask user to choose Backup or Restore action
        action_options = ["Backup etcd", "Restore etcd"]
        action, ok = QInputDialog.getItem(self, "Configure Data Backup", "Select Action:", action_options, 0, False)

        if not ok or action not in action_options:
            self.command_output.append("No valid action selected for data backup.")
            return

        # Execute backup or restore based on selection
        if action == "Backup etcd":
            self.backup_etcd()
        elif action == "Restore etcd":
            self.restore_etcd()

    def backup_etcd(self):
        """Backup etcd data and save it to the local machine."""
        # Define file path to save backup on the local machine
        save_path, _ = QFileDialog.getSaveFileName(
            self, "Save etcd Backup", f"{os.path.expanduser('~')}/etcd-backup.db",
            "DB Files (*.db);;All Files (*)"
        )

        if not save_path:
            self.command_output.append("Backup canceled by the user.")
            return

        self.command_output.append(f"Starting etcd backup to {save_path}...")

        # Start worker to perform backup and pass progress_callback
        worker = Worker(self._backup_etcd, save_path)
        worker.signals.result.connect(self.on_create_resource_result)
        worker.signals.error.connect(self.on_error)
        worker.signals.finished.connect(self.on_create_resource_finished)

        self.threadpool.start(worker)





    def _backup_etcd(self, save_path, progress_callback):
        """
        Back up the etcd database dynamically based on the running etcd pod in the kube-system namespace.
        """
        try:
            progress_callback.emit(10)  # Emit initial progress

            # Retrieve the current kubeconfig
            kubeconfig_to_use = self.get_current_kubeconfig()
            if not kubeconfig_to_use:
                raise Exception("No valid kubeconfig available.")

            progress_callback.emit(30)  # Emit progress for finding the etcd pod

            # Command to find the etcd pod name
            find_pod_command = [
                'kubectl', 'get', 'pods', '-n', 'kube-system',
                '--kubeconfig', kubeconfig_to_use,
                '--insecure-skip-tls-verify',
                '-o', 'jsonpath={.items[?(@.metadata.name contains "etcd")].metadata.name}'
            ]

            # Execute the command to find the etcd pod
            pod_result = subprocess.run(find_pod_command, capture_output=True, text=True)
            etcd_pod_names = pod_result.stdout.strip().split()

            # Identify the specific etcd pod
            etcd_pod_name = next((name for name in etcd_pod_names if "etcd" in name), None)

            if not etcd_pod_name:
                raise Exception("No etcd pod found in the kube-system namespace.")

            self.command_output.append(f"Detected etcd pod: {etcd_pod_name}")
            progress_callback.emit(40)  # Emit progress for executing the backup

            # Define the backup path inside the pod
            pod_backup_path = "/tmp/etcd-backup.db"

            # Command to execute the etcd snapshot
            backup_command = [
                'kubectl', 'exec', '-n', 'kube-system', etcd_pod_name,
                '--kubeconfig', kubeconfig_to_use,
                '--insecure-skip-tls-verify',
                '--', 'sh', '-c',
                f'ETCDCTL_API=3 etcdctl snapshot save {pod_backup_path} '
                f'--cacert=/etc/kubernetes/pki/etcd/ca.crt '
                f'--cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt '
                f'--key=/etc/kubernetes/pki/etcd/healthcheck-client.key'
            ]

            # Execute the backup command inside the pod
            backup_process = subprocess.run(backup_command, check=True, capture_output=True, text=True)
            self.command_output.append("Backup successful inside the pod.")
            progress_callback.emit(50)  # Emit progress for copying the backup

            # Define the chunk size (1 MB)
            chunk_size = 1024 * 1024  # 1 MB chunks

            # Open the local file in binary write mode
            with open(save_path, 'wb') as backup_file:
                offset = 0
                total_bytes_written = 0  # To track the total bytes written

                while True:
                    # Command to read a chunk of the backup file from the pod
                    read_chunk_command = [
                        'kubectl', 'exec', '-n', 'kube-system', etcd_pod_name,
                        '--kubeconfig', kubeconfig_to_use,
                        '--insecure-skip-tls-verify',
                        '--', 'sh', '-c',
                        f"dd if={pod_backup_path} bs={chunk_size} skip={offset} count=1 2>/dev/null"
                    ]

                    # Execute the command and read the chunk as bytes
                    chunk_result = subprocess.run(read_chunk_command, capture_output=True)
                    chunk_data = chunk_result.stdout  # This is bytes

                    # Debug: Log the size of the chunk read
                    chunk_size_read = len(chunk_data)
                    print(f"Read chunk {offset}: {chunk_size_read} bytes")
                    self.command_output.append(f"Read chunk {offset}: {chunk_size_read} bytes")

                    # If no data is returned, the backup is complete
                    if not chunk_data:
                        break

                    # Write the chunk directly as binary data
                    backup_file.write(chunk_data)
                    total_bytes_written += chunk_size_read

                    # Debug: Log the total bytes written so far
                    print(f"Total bytes written: {total_bytes_written}")
                    self.command_output.append(f"Total bytes written: {total_bytes_written} bytes")

                    # Update offset for the next chunk
                    offset += 1

            # Debug: Check the size of the local backup file
            local_backup_size = os.path.getsize(save_path)
            print(f"Local backup size: {local_backup_size} bytes")
            self.command_output.append(f"Local backup size: {local_backup_size} bytes")

            # Optional: Compare the sizes if you have an alternative method to get the pod backup size
            # For simplicity, we'll assume the transfer was successful if data was written

            self.command_output.append(f"Backup copied to {save_path} successfully.")
            progress_callback.emit(100)  # Emit completion progress

        except subprocess.CalledProcessError as e:
            error_message = f"Backup failed: {e.stderr}"
            self.command_output.append(error_message)
            print(error_message)
            raise Exception(error_message)
        except Exception as e:
            error_message = f"Backup process error: {str(e)}"
            self.command_output.append(error_message)
            print(error_message)
            raise Exception(error_message)











    def restore_etcd(self):
        """Restore etcd data from a backup file on the local machine."""
        # Open file dialog to select backup file for restore
        backup_file, _ = QFileDialog.getOpenFileName(
            self, "Select etcd Backup File", os.path.expanduser('~'), "DB Files (*.db);;All Files (*)"
        )

        if not backup_file:
            self.command_output.append("Restore canceled by the user.")
            return

        self.command_output.append(f"Starting etcd restore from {backup_file}...")

        # Start worker to perform restore
        worker = Worker(self._restore_etcd, backup_file)
        worker.signals.result.connect(self.on_create_resource_result)
        worker.signals.error.connect(self.on_error)
        worker.signals.finished.connect(self.on_create_resource_finished)

        self.threadpool.start(worker)

    def _restore_etcd(self, backup_file, progress_callback):
        """Perform the restoration of etcd from a backup file."""
        kubeconfig_to_use = self.get_current_kubeconfig()
        try:
            # Copy backup file from local machine to cluster
            copy_command = [
                'kubectl', 'cp', backup_file, 'kube-system/etcd-master:/tmp/etcd-backup.db',
                '--kubeconfig', kubeconfig_to_use
            ]
            subprocess.run(copy_command, check=True, capture_output=True, text=True)

            # Command to restore etcd data
            restore_command = [
                'kubectl', 'exec', '-n', 'kube-system', 'etcd-master', '--',
                'sh', '-c', f"ETCDCTL_API=3 etcdctl snapshot restore /tmp/etcd-backup.db --data-dir /var/lib/etcd --cacert=/etc/kubernetes/pki/etcd/ca.crt --cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt --key=/etc/kubernetes/pki/etcd/healthcheck-client.key"
            ]
            subprocess.run(restore_command, check=True, capture_output=True, text=True)

            self.command_output.append("etcd data restored successfully.")

        except subprocess.CalledProcessError as e:
            raise Exception(f"Restore failed: {e.stderr}")

    def on_create_resource_result(self, result):
        """Handle the result of resource creation (optional if there's a return value)."""
        self.command_output.append("Resource creation completed.")

    def on_create_resource_finished(self):
        """Re-enable the execute button after resource creation is finished."""
        self.execute_button.setEnabled(True)  # Ensure the correct button is re-enabled
        self.command_output.append("Resource creation process finished.")
        
        
    
    def configure_namespace(self):
        """Display a dialog to choose namespace actions (Create, Delete)."""
        # Define namespace actions
        namespace_actions = ["Create Namespace", "Delete Namespace"]
        action, ok = QInputDialog.getItem(self, "Configure Namespace", "Select Action:", namespace_actions, 0, False)

        if not ok or action not in namespace_actions:
            self.command_output.append("No valid action selected for namespace configuration.")
            return

        # Call appropriate method based on user selection
        if action == "Create Namespace":
            self.create_namespace()
        elif action == "Delete Namespace":
            self.delete_namespace()
            
        
    def create_namespace(self):
        """Create a new namespace in the cluster."""
        # Prompt for namespace name
        namespace_name, ok = QInputDialog.getText(self, 'Create Namespace', 'Enter new namespace name:')
        if not ok or not namespace_name.strip():
            self.command_output.append("Namespace creation canceled or invalid name.")
            return

        namespace_name = namespace_name.strip()

        # Start the worker to create the namespace
        worker = Worker(self._create_namespace, namespace_name)
        worker.signals.result.connect(self.on_create_namespace_result)
        worker.signals.error.connect(self.on_error)
        worker.signals.finished.connect(self.on_create_namespace_finished)

        self.execute_button.setEnabled(False)
        self.command_output.append(f"Starting creation of namespace '{namespace_name}'...")
        self.threadpool.start(worker)

    def _create_namespace(self, namespace_name, progress_callback):
        """Function to create a new namespace."""
        try:
            kubeconfig_to_use = self.get_current_kubeconfig()
            if not kubeconfig_to_use:
                raise Exception("No valid kubeconfig available.")

            # Use kubectl to create namespace
            subprocess.run(
                ['kubectl', 'create', 'namespace', namespace_name, '--kubeconfig', kubeconfig_to_use],
                check=True, capture_output=True, text=True
            )
            self.command_output.append(f"Namespace '{namespace_name}' created successfully.")
            progress_callback.emit(100)

        except subprocess.CalledProcessError as e:
            raise Exception(f"Error creating namespace: {e.stderr}")

    def on_create_namespace_result(self, result):
        """Handle the result of the namespace creation."""
        self.command_output.append(result)

    def on_create_namespace_finished(self):
        """Re-enable the execute button after namespace creation is finished."""
        self.execute_button.setEnabled(True)


    def delete_namespace(self):
        """Delete a namespace from the cluster."""
        # Prompt for namespace name
        namespace_name, ok = QInputDialog.getText(self, 'Delete Namespace', 'Enter namespace name to delete:')
        if not ok or not namespace_name.strip():
            self.command_output.append("Namespace deletion canceled or invalid name.")
            return

        namespace_name = namespace_name.strip()

        # Start the worker to delete the namespace
        worker = Worker(self._delete_namespace, namespace_name)
        worker.signals.result.connect(self.on_delete_namespace_result)
        worker.signals.error.connect(self.on_error)
        worker.signals.finished.connect(self.on_delete_namespace_finished)

        self.execute_button.setEnabled(False)
        self.command_output.append(f"Starting deletion of namespace '{namespace_name}'...")
        self.threadpool.start(worker)

    def _delete_namespace(self, namespace_name, progress_callback):
        """Function to delete a namespace."""
        try:
            kubeconfig_to_use = self.get_current_kubeconfig()
            if not kubeconfig_to_use:
                raise Exception("No valid kubeconfig available.")

            # Use kubectl to delete namespace
            subprocess.run(
                ['kubectl', 'delete', 'namespace', namespace_name, '--kubeconfig', kubeconfig_to_use],
                check=True, capture_output=True, text=True
            )
            self.command_output.append(f"Namespace '{namespace_name}' deleted successfully.")
            progress_callback.emit(100)

        except subprocess.CalledProcessError as e:
            raise Exception(f"Error deleting namespace: {e.stderr}")

    def on_delete_namespace_result(self, result):
        """Handle the result of the namespace deletion."""
        self.command_output.append(result)

    def on_delete_namespace_finished(self):
        """Re-enable the execute button after namespace deletion is finished."""
        self.execute_button.setEnabled(True)


