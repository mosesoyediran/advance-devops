import json
import logging
import os
import re
import smtplib
import subprocess
import threading
import time
from datetime import datetime
from email.mime.text import MIMEText

import plotly.graph_objects as go
import plotly.io as pio
from plotly.subplots import make_subplots
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import TerraformLexer
from PyQt5 import QtCore
from PyQt5.QtCore import (QObject, QRunnable, Qt, QThreadPool, pyqtSignal,
                          pyqtSlot)
from PyQt5.QtGui import (QColor, QFont, QSyntaxHighlighter, QTextCharFormat,
                         QTextCursor)
from PyQt5.QtWebEngineWidgets import \
    QWebEngineView  # Ensure PyQtWebEngine is installed
from PyQt5.QtWidgets import (QComboBox, QFileDialog, QGridLayout, QGroupBox,
                             QHBoxLayout, QInputDialog, QLabel, QLineEdit,
                             QListWidget, QListWidgetItem, QMessageBox,
                             QPlainTextEdit, QPushButton, QSizePolicy,
                             QSplitter, QTabWidget, QTextEdit, QVBoxLayout,
                             QWidget)
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError


# Worker Signals for Threading
class WorkerSignals(QObject):
    log_signal = pyqtSignal(str)
    finished = pyqtSignal(list)
    error = pyqtSignal(str)
    
# Worker Signals for Threading


class ProjectLoader(QRunnable):
    """
    Worker thread for loading Terraform projects.
    """
    def __init__(self):
        super().__init__()
        self.signals = WorkerSignals()

    def run(self):
        try:
            project_dir = "terraform_projects"
            if not os.path.exists(project_dir):
                os.makedirs(project_dir)
            projects = [f for f in os.listdir(project_dir) if os.path.isdir(os.path.join(project_dir, f))]
            self.signals.finished.emit(projects)  # Emit the list of projects
        except Exception as e:
            self.signals.error.emit(str(e)) 

class WorkspaceLoader(QRunnable):
    """
    Worker thread for loading Terraform workspaces.
    """
    def __init__(self, project_path):
        super().__init__()
        self.project_path = project_path
        self.signals = WorkerSignals()

    def run(self):
        try:
            # Initialize Terraform if not initialized
            init_command = ['terraform', 'init', '-no-color']
            subprocess.run(init_command, cwd=self.project_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)

            # List workspaces
            list_command = ['terraform', 'workspace', 'list', '-no-color']
            result = subprocess.run(list_command, cwd=self.project_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
            workspaces = [ws.strip('* ').strip() for ws in result.stdout.strip().split('\n') if ws]
            self.signals.finished.emit(workspaces)  # Emit the list of workspaces
        except subprocess.CalledProcessError as e:
            error_message = e.stderr.strip() if e.stderr else "Unknown error during workspace listing."
            self.signals.error.emit(error_message)  # Emit the error message
        except Exception as e:
            self.signals.error.emit(str(e))         # Emit the error message
            
            
class MetricsDataProcessor(QRunnable):
    """
    Worker thread for processing metrics data.
    """
    def __init__(self, data):
        super().__init__()
        self.data = data
        self.signals = WorkerSignals()
    
    def run(self):
        try:
            # Simulate data processing or fetching
            # In real scenarios, replace this with actual data fetching logic
            processed_data = self.process_data(self.data)
            self.signals.finished.emit(processed_data)
        except Exception as e:
            self.signals.error.emit(str(e))
    
    def process_data(self, data):
        # Placeholder for data processing logic
        # For example, filtering, aggregating, etc.
        return data



# Syntax Highlighter for Terraform Configuration
class TerraformHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.lexer = TerraformLexer()
        self.formatter = HtmlFormatter()
        self.highlighting_rules = []

        # Define formatting for different token types
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor("#569CD6"))
        keyword_format.setFontWeight(QFont.Bold)

        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#D69D85"))

        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("#6A9955"))
        comment_format.setFontItalic(True)

        # Add rules (simplified for demonstration)
        self.highlighting_rules.append((r'\b(provider|resource|variable|output)\b', keyword_format))
        self.highlighting_rules.append((r'\".*\"', string_format))
        self.highlighting_rules.append((r'#.*', comment_format))

    def highlightBlock(self, text):
        for pattern, fmt in self.highlighting_rules:
            expression = QtCore.QRegExp(pattern)
            index = expression.indexIn(text)
            while index >= 0:
                length = expression.matchedLength()
                self.setFormat(index, length, fmt)
                index = expression.indexIn(text, index + length)
        self.setCurrentBlockState(0)


# Plotly Canvas Widget
class PlotlyCanvas(QWebEngineView):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(300)

    def plot_metrics(self, data):
        """
        Plot metrics data using Plotly and display it in the QWebEngineView.
        
        :param data: List of dictionaries with 'timestamp', 'cpu', 'memory' keys.
        """
        if not data:
            self.setHtml("<h3>No metrics data available.</h3>")
            return

        # Extract data for plotting
        timestamps = [entry['timestamp'] for entry in data]
        cpu = [entry['cpu'] for entry in data]
        memory = [entry['memory'] for entry in data]

        # Create subplots with secondary y-axis for memory
        fig = make_subplots(specs=[[{"secondary_y": True}]])

        # Add CPU usage trace
        fig.add_trace(
            go.Scatter(x=timestamps, y=cpu, mode='lines+markers', name="CPU Usage (m)"),
            secondary_y=False,
        )

        # Add Memory usage trace
        fig.add_trace(
            go.Scatter(x=timestamps, y=memory, mode='lines+markers', name="Memory Usage (Mi)"),
            secondary_y=True,
        )

        # Update layout
        fig.update_layout(
            title_text="Terraform Infrastructure Metrics",
            template="plotly_dark"
        )
        fig.update_xaxes(title_text="Timestamp")
        fig.update_yaxes(title_text="CPU Usage (m)", secondary_y=False)
        fig.update_yaxes(title_text="Memory Usage (Mi)", secondary_y=True)

        # Render the plot as HTML and display in QWebEngineView
        html = pio.to_html(fig, include_plotlyjs='cdn', full_html=False)
        self.setHtml(html)


# Interactive Configuration Editor with Syntax Highlighting
class TerraformEditor(QPlainTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        # Replace "Courier" with more common monospace fonts
        font = QFont("Consolas", 10)  # Use Consolas if available
        if not font.exactMatch():
            font.setFamily("Monaco")  # Fallback to Monaco (on macOS)
            if not font.exactMatch():
                font.setFamily("Monospace")  # Generic monospace
        self.setFont(font)
        self.highlighter = TerraformHighlighter(self.document())
        self.textChanged.connect(self.highlight_syntax)

    def highlight_syntax(self):
        # Syntax highlighting is handled by the QSyntaxHighlighter
        pass


# Main TerraformTab Class
class TerraformTab(QWidget):
    def __init__(self, auth_manager, main_tab_widget):
        super().__init__()
        self.auth_manager = auth_manager
        self.main_tab_widget = main_tab_widget
        self.current_user = None  # To be set upon authentication
        self.initUI()

    def initUI(self):
        # Main layout with Splitter for two columns
        main_layout = QHBoxLayout(self)
        splitter = QSplitter(Qt.Horizontal)

        # Left Column
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        
        # Add the Back to System Button
        back_button = QPushButton("Back to System")
        back_button.clicked.connect(self.go_back_to_system)
        back_button.setFixedSize(120, 30)
        left_layout.addWidget(back_button)

        # Project & Workspace Management Group
        management_group = QGroupBox("Project & Workspace Management")
        management_layout = QVBoxLayout()

        # Project and Workspace Dropdowns Layout
        selection_layout = QHBoxLayout()
        self.project_option = QComboBox(self)
        self.project_option.setToolTip("Select Terraform Project")

        # **Define loading_label here before calling load_projects**
        self.loading_label = QLabel("Loading...", self)
        self.loading_label.setAlignment(Qt.AlignCenter)
        self.loading_label.setStyleSheet("color: blue; font-weight: bold;")
        self.loading_label.hide()  # Initially hidden
        left_layout.addWidget(self.loading_label)  # Add to the layout

        # Now, load projects (which may show the loading_label)
        self.load_projects()

        self.project_option.currentTextChanged.connect(self.load_workspaces)  # Load workspaces on project change

        self.workspace_option = QComboBox(self)
        self.workspace_option.setToolTip("Select Terraform Workspace")
        self.load_workspaces()  # Load initial workspaces

        selection_layout.addWidget(QLabel("Project:"))
        selection_layout.addWidget(self.project_option)
        selection_layout.addWidget(QLabel("Workspace:"))
        selection_layout.addWidget(self.workspace_option)

        # Management Actions Dropdown
        self.management_actions = QComboBox(self)
        self.management_actions.addItems(["Add Project", "Delete Project", "Add Workspace", "Delete Workspace"])

        # Execute Button to Trigger Action
        self.execute_action_button = QPushButton("Execute Action")
        self.execute_action_button.clicked.connect(self.handle_management_action)  # Trigger action on button click

        management_layout.addLayout(selection_layout)
        management_layout.addWidget(QLabel("Actions:"))
        management_layout.addWidget(self.management_actions)
        management_layout.addWidget(self.execute_action_button)  # Add the execute button

        management_group.setLayout(management_layout)
        left_layout.addWidget(management_group)


        ############################
        # Provider Selection Group
        ############################

        # Provider Selection Group
        provider_group = QGroupBox("Select Provider")
        provider_layout = QVBoxLayout()

        # Dropdown for selecting provider (EKS or EC2)
        self.provider_option = QComboBox(self)
        self.provider_option.addItems(["Select Provider", "EC2", "EKS", "k8s", "AKS", "GKE", "VMS", "Linode"])
        self.provider_option.currentTextChanged.connect(self.on_provider_selection)

        # Add the dropdown to the provider layout
        provider_layout.addWidget(QLabel("Provider:"))
        provider_layout.addWidget(self.provider_option)

        # Add the execute button for running commands
        self.execute_button = QPushButton("Execute")
        self.execute_button.clicked.connect(self.execute_terraform)

        # Add the execute button to the provider layout
        provider_layout.addWidget(self.execute_button)

        # Add provider group to the main layout
        provider_group.setLayout(provider_layout)
        left_layout.addWidget(provider_group)

        # Terraform Command Execution Group
        command_group = QGroupBox("Terraform Commands")
        command_layout = QGridLayout()

        self.init_button = QPushButton("terraform init")
        self.init_button.clicked.connect(lambda: self.run_terraform_command('init -no-color'))
        self.plan_button = QPushButton("terraform plan")
        self.plan_button.clicked.connect(lambda: self.run_terraform_command('plan -no-color -lock=false'))
        self.apply_button = QPushButton("terraform apply")
        self.apply_button.clicked.connect(lambda: self.run_terraform_command('apply -no-color -auto-approve -lock=false'))
        self.destroy_button = QPushButton("terraform destroy")
        self.destroy_button.clicked.connect(lambda: self.run_terraform_command('destroy -no-color -auto-approve -lock=false'))
        self.show_button = QPushButton("terraform show")
        self.show_button.clicked.connect(lambda: self.run_terraform_command('show -no-color terraform.tfstate'))
        self.validate_button = QPushButton("terraform validate")
        self.validate_button.clicked.connect(lambda: self.run_terraform_command('validate -no-color'))
        self.upgrade_button = QPushButton("terraform upgrade")
        self.upgrade_button.clicked.connect(lambda: self.run_terraform_command('upgrade -no-color'))
        self.refresh_button = QPushButton("terraform refresh")
        self.refresh_button.clicked.connect(lambda: self.run_terraform_command('refresh -no-color'))

        command_layout.addWidget(self.init_button, 0, 0)
        command_layout.addWidget(self.plan_button, 0, 1)
        command_layout.addWidget(self.apply_button, 1, 0)
        command_layout.addWidget(self.destroy_button, 1, 1)
        command_layout.addWidget(self.show_button, 2, 0)
        command_layout.addWidget(self.validate_button, 2, 1)
        command_layout.addWidget(self.upgrade_button, 3, 0)
        command_layout.addWidget(self.refresh_button, 3, 1)

        command_group.setLayout(command_layout)
        left_layout.addWidget(command_group)

        # # Extra Variables Group
        # vars_group = QGroupBox("Extra Variables")
        # vars_layout = QVBoxLayout()
        # self.extra_vars_input = QLineEdit(self)
        # self.extra_vars_input.setPlaceholderText("{\"var1\": \"value1\"}")
        # self.extra_vars_input.setToolTip("Provide extra variables for Terraform commands in JSON format.")
        # vars_layout.addWidget(QLabel("Extra Vars (JSON):"))
        # vars_layout.addWidget(self.extra_vars_input)
        # vars_group.setLayout(vars_layout)
        # left_layout.addWidget(vars_group)

        # Custom Scripts Execution Group
        scripts_group = QGroupBox("Custom Scripts")
        scripts_layout = QGridLayout()

        self.pre_script_input = QLineEdit(self)
        self.pre_script_input.setPlaceholderText("Path to Pre-Command Script")
        self.pre_script_input.setToolTip("Specify a script to run before executing Terraform commands.")
        self.browse_pre_script_button = QPushButton("Browse")
        self.browse_pre_script_button.clicked.connect(lambda: self.browse_script(self.pre_script_input))

        self.post_script_input = QLineEdit(self)
        self.post_script_input.setPlaceholderText("Path to Post-Command Script")
        self.post_script_input.setToolTip("Specify a script to run after executing Terraform commands.")
        self.browse_post_script_button = QPushButton("Browse")
        self.browse_post_script_button.clicked.connect(lambda: self.browse_script(self.post_script_input))

        scripts_layout.addWidget(QLabel("Pre-Command Script:"), 0, 0)
        scripts_layout.addWidget(self.pre_script_input, 0, 1)
        scripts_layout.addWidget(self.browse_pre_script_button, 0, 2)
        scripts_layout.addWidget(QLabel("Post-Command Script:"), 1, 0)
        scripts_layout.addWidget(self.post_script_input, 1, 1)
        scripts_layout.addWidget(self.browse_post_script_button, 1, 2)

        scripts_group.setLayout(scripts_layout)
        left_layout.addWidget(scripts_group)

        # Interactive Configuration Editor Group
        editor_group = QGroupBox("Configuration Editor")
        editor_layout = QVBoxLayout()
        self.config_editor = TerraformEditor(self)
        self.load_config_button = QPushButton("Load Configuration")
        self.load_config_button.clicked.connect(self.load_configuration)
        self.save_config_button = QPushButton("Save Configuration")
        self.save_config_button.clicked.connect(self.save_configuration)
        editor_buttons_layout = QHBoxLayout()
        editor_buttons_layout.addWidget(self.load_config_button)
        editor_buttons_layout.addWidget(self.save_config_button)
        editor_layout.addWidget(self.config_editor)
        editor_layout.addLayout(editor_buttons_layout)
        editor_group.setLayout(editor_layout)
        left_layout.addWidget(editor_group)
        
        
        

        # Loading Indicator
        # Already defined above and added to layout

        # Add Spacer to Left Column
        left_layout.addStretch()

        splitter.addWidget(left_widget)

        # Right Column with Tabs
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)

        tabs = QTabWidget()
        tabs.setTabPosition(QTabWidget.West)
        tabs.setTabShape(QTabWidget.Rounded)

        # Tab 1: Output & Logs
        output_tab = QWidget()
        output_layout = QVBoxLayout()
        self.output_area = QTextEdit(self)
        self.output_area.setReadOnly(True)
        self.output_area.setToolTip("Displays Terraform command outputs and logs.")
        output_layout.addWidget(self.output_area)
        output_tab.setLayout(output_layout)
        tabs.addTab(output_tab, "Output & Logs")

        # Tab 2: Metrics Visualization
        metrics_tab = QWidget()
        metrics_layout = QVBoxLayout()
        self.metrics_canvas = PlotlyCanvas(self)
        metrics_layout.addWidget(self.metrics_canvas)
        metrics_tab.setLayout(metrics_layout)
        tabs.addTab(metrics_tab, "Metrics Visualization")
        

        # Tab 3: Configuration Editor
        config_tab = QWidget()
        config_layout = QVBoxLayout()
        config_layout.addWidget(self.config_editor)
        config_buttons_layout = QHBoxLayout()
        config_buttons_layout.addWidget(self.load_config_button)
        config_buttons_layout.addWidget(self.save_config_button)
        config_layout.addLayout(config_buttons_layout)
        config_tab.setLayout(config_layout)
        tabs.addTab(config_tab, "Configuration Editor")

        # Tab 4: Notifications & Audit Trails
        notifications_tab = QWidget()
        notifications_layout = QVBoxLayout()

        # Notification Settings Group
        notification_group = QGroupBox("Notification Settings")
        notification_group_layout = QGridLayout()

        self.email_input = QLineEdit(self)
        self.email_input.setPlaceholderText("Enter Email for Notifications")
        self.email_input.setToolTip("Provide an email address to receive notifications.")
        notification_group_layout.addWidget(QLabel("Email:"), 0, 0)
        notification_group_layout.addWidget(self.email_input, 0, 1)

        self.slack_token_input = QLineEdit(self)
        self.slack_token_input.setPlaceholderText("Enter Slack Token for Notifications")
        self.slack_token_input.setToolTip("Provide your Slack Bot Token for sending notifications.")
        notification_group_layout.addWidget(QLabel("Slack Token:"), 1, 0)
        notification_group_layout.addWidget(self.slack_token_input, 1, 1)

        self.slack_channel_input = QLineEdit(self)
        self.slack_channel_input.setPlaceholderText("Enter Slack Channel ID")
        self.slack_channel_input.setToolTip("Provide the Slack Channel ID where notifications will be sent.")
        notification_group_layout.addWidget(QLabel("Slack Channel ID:"), 2, 0)
        notification_group_layout.addWidget(self.slack_channel_input, 2, 1)

        self.save_notifications_button = QPushButton("Save Notification Settings")
        self.save_notifications_button.clicked.connect(self.save_notification_settings)
        self.save_notifications_button.setToolTip("Save your notification preferences.")
        notification_group_layout.addWidget(self.save_notifications_button, 3, 0, 1, 2)

        notification_group.setLayout(notification_group_layout)
        notifications_layout.addWidget(notification_group)

        # Audit Trails Group
        audit_group = QGroupBox("Audit Trails")
        audit_layout = QVBoxLayout()
        self.view_audit_button = QPushButton("View Audit Logs")
        self.view_audit_button.clicked.connect(self.view_audit_logs)
        audit_layout.addWidget(self.view_audit_button)
        audit_group.setLayout(audit_layout)
        notifications_layout.addWidget(audit_group)

        notifications_tab.setLayout(notifications_layout)
        tabs.addTab(notifications_tab, "Notifications & Audit Trails")

        # Tab 5: Rollback
        rollback_tab = QWidget()
        rollback_layout = QVBoxLayout()
        self.rollback_button = QPushButton("Rollback to Previous State")
        self.rollback_button.clicked.connect(self.rollback_state)
        self.rollback_button.setToolTip("Revert Terraform state to the previous version.")
        rollback_layout.addWidget(self.rollback_button)
        rollback_tab.setLayout(rollback_layout)
        tabs.addTab(rollback_tab, "Rollback")

        right_layout.addWidget(tabs)
        right_widget.setLayout(right_layout)

        splitter.addWidget(right_widget)

        # Set splitter sizes
        splitter.setSizes([400, 600])

        main_layout.addWidget(splitter)
        self.setLayout(main_layout)

        # Initialize Logging
        self.setup_logging()

        # Initialize Notification Settings
        self.load_notification_settings()

        
        # Initialize Thread Pool
        self.threadpool = QThreadPool()

        

    def go_back_to_system(self):
        """
        Switch back to the System tab.
        """
        # Delayed import to avoid circular import issues
        from system_tab import SystemTab

        for i in reversed(range(self.main_tab_widget.count())):
            self.main_tab_widget.removeTab(i)
        system_tab = SystemTab(self.auth_manager, self.main_tab_widget)
        self.main_tab_widget.addTab(system_tab, "System")
        self.main_tab_widget.setCurrentWidget(system_tab)
        
        
        
    ######################
    # Provider Management
    ######################
        
    def on_provider_selection(self, provider):
        """Handle provider selection and load the corresponding .tf file and move terraform.tfvars."""
        if provider == "EC2":
            self.load_tf_file("ec2.tf", "terraform_ec2.tfvars")
        elif provider == "EKS":
            self.load_tf_file("eks.tf", "terraform_eks.tfvars")
        elif provider == "k8s":
            self.load_tf_file("k8s.tf", "terraform_k8s.tfvars")
        elif provider == "AKS":
            self.load_tf_file("aks.tf", "terraform_aks.tfvars")
        elif provider == "GKE":
            self.load_tf_file("gke.tf", "terraform_gke.tfvars")
        elif provider == "vms":
            self.load_tf_file("vms.tf", "terraform_vms.tfvars")
        elif provider == "linode":
            self.load_tf_file("linode.tf", "terraform_linode.tfvars")
        else:
            self.clear_configuration_editor()
    def load_tf_file(self, filename, tfvars_filename):
        """Load the selected .tf file into the main.tf of the project and move terraform.tfvars."""
        selected_project = self.project_option.currentText()  # Assuming project is selected
        if not selected_project:
            QMessageBox.warning(self, "Warning", "Please select a project first.")
            return

        # Locate the directory where the .tf files (ec2.tf or eks.tf) and tfvars files are located
        tf_dir = os.path.join(os.getcwd(), "terraform")  # Assuming 'terraform' is the folder where ec2.tf and eks.tf are located
        tf_path = os.path.join(tf_dir, filename)  # Full path to the selected .tf file
        tfvars_path = os.path.join(tf_dir, tfvars_filename)  # Full path to the corresponding .tfvars file

        # Define the main.tf and terraform.tfvars paths in the project directory
        project_path = os.path.join("terraform_projects", selected_project)
        main_tf_path = os.path.join(project_path, "main.tf")
        project_tfvars_path = os.path.join(project_path, "terraform.tfvars")

        try:
            # Copy the content from ec2.tf or eks.tf to main.tf
            with open(tf_path, 'r') as tf_file:
                tf_content = tf_file.read()
            with open(main_tf_path, 'w') as main_tf_file:
                main_tf_file.write(tf_content)

            self.log_message(f"Loaded {filename} into main.tf")

            # Directly copy the terraform.tfvars file
            with open(tfvars_path, 'r') as tfvars_file:
                tfvars_content = tfvars_file.read()
            with open(project_tfvars_path, 'w') as project_tfvars_file:
                project_tfvars_file.write(tfvars_content)

            self.log_message(f"Copied {tfvars_filename} to project as terraform.tfvars")

            # Extract variables from the .tf file and display them in the editor
            variables = self.extract_variables(tf_content)
            self.display_variables_in_editor(variables)

        except FileNotFoundError as e:
            self.log_message(f"Error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to load {filename}: {e}")
        except Exception as e:
            self.log_message(f"Error loading {filename}: {e}")
            QMessageBox.critical(self, "Error", f"Failed to load {filename}: {e}")

    
    
    def extract_variables(self, tf_content):
        """Extract variable declarations from the .tf content."""
        variables = []
        for line in tf_content.splitlines():
            if line.strip().startswith("variable"):
                var_name = line.split()[1].replace('"', '')
                variables.append(var_name)
        return variables

    def display_variables_in_editor(self, variables):
        """Display variables in the configuration editor."""
        self.config_editor.clear()
        for var in variables:
            self.config_editor.appendPlainText(f'variable "{var}" {{}}')

    def execute_terraform(self):
        """Run the Terraform commands based on the selected provider."""
        selected_provider = self.provider_option.currentText()
        if selected_provider == "Select Provider":
            QMessageBox.warning(self, "Warning", "Please select a valid provider.")
            return




        
        
    
        
    


    ######################
    # Project Management
    ######################

    def load_projects(self):
        """Load existing Terraform projects asynchronously."""
        self.loading_label.show()
        self.project_option.setEnabled(False)

        project_loader = ProjectLoader()
        project_loader.signals.finished.connect(self.on_projects_loaded)
        project_loader.signals.error.connect(self.on_projects_error)
        # Start the worker
        self.threadpool = QThreadPool()
        self.threadpool.start(project_loader)
        
        
    def on_projects_loaded(self, projects):
        """Handle the loaded projects."""
        self.project_option.setEnabled(True)
        self.loading_label.hide()
        self.project_option.clear()
        self.project_option.addItems(projects)
        self.log_message(f"Loaded {len(projects)} project(s).")
        
    def on_projects_error(self, error_message):
        """Handle errors during project loading."""
        self.project_option.setEnabled(True)
        self.loading_label.hide()
        self.log_message(f"Error loading projects: {error_message}")
        QMessageBox.critical(self, "Error", f"Failed to load projects: {error_message}")

    
        
        
     ######################
    # Workspace Management
    ######################

    def load_workspaces(self):
        """Load Terraform workspaces asynchronously for the selected project."""
        self.loading_label.show()
        self.workspace_option.setEnabled(False)
        selected_project = self.project_option.currentText()
        if not selected_project:
            self.loading_label.hide()
            self.workspace_option.setEnabled(True)
            return
        project_path = f"terraform_projects/{selected_project}"
        workspace_loader = WorkspaceLoader(project_path)
        workspace_loader.signals.finished.connect(self.on_workspaces_loaded)
        workspace_loader.signals.error.connect(self.on_workspaces_error)

        # Start the worker
        self.threadpool = QThreadPool()
        self.threadpool.start(workspace_loader)

    def on_workspaces_loaded(self, workspaces):
        """Handle the loaded workspaces."""
        self.workspace_option.setEnabled(True)
        self.loading_label.hide()
        self.workspace_option.clear()
        self.workspace_option.addItems(workspaces)
        self.log_message(f"Loaded {len(workspaces)} workspace(s).")

    def on_workspaces_error(self, error_message):
        """Handle errors during workspace loading."""
        self.workspace_option.setEnabled(True)
        self.loading_label.hide()
        self.log_message(f"Error loading workspaces: {error_message}")
        QMessageBox.critical(self, "Error", f"Failed to load workspaces: {error_message}")


   ######################
    # Other Methods...
    ###################### 
    def handle_management_action(self):
        """Handle management actions based on selected option."""
        selected_action = self.management_actions.currentText()
        if selected_action == "Add Project":
            self.add_project()
        elif selected_action == "Delete Project":
            self.delete_project()
        elif selected_action == "Add Workspace":
            self.add_workspace()
        elif selected_action == "Delete Workspace":
            self.delete_workspace()

    def add_project(self):
        """Add a new Terraform project."""
        project_name, ok = QInputDialog.getText(self, "Add Project", "Enter project name:")
        if ok and project_name:
            project_path = f"terraform_projects/{project_name}"
            try:
                os.makedirs(project_path, exist_ok=False)
                # Initialize a basic Terraform configuration file
                main_tf_path = os.path.join(project_path, "main.tf")
                with open(main_tf_path, 'w') as f:
                    f.write('provider "local" {}\n')
                self.load_projects()
                self.log_message(f"Project '{project_name}' added successfully.")
                logging.info(f"Added project '{project_name}'.")
            except FileExistsError:
                self.log_message(f"Project '{project_name}' already exists.")
                QMessageBox.warning(self, "Warning", f"Project '{project_name}' already exists.")
                logging.warning(f"Attempted to add existing project '{project_name}'.")
            except Exception as e:
                self.log_message(f"Failed to add project: {e}")
                logging.error(f"Failed to add project '{project_name}': {e}")

    def delete_project(self):
        """Delete the selected Terraform project."""
        selected_project = self.project_option.currentText()
        if not selected_project:
            self.log_message("No project selected to delete.")
            QMessageBox.warning(self, "Warning", "No project selected to delete.")
            return
        reply = QMessageBox.question(
            self, 'Confirm Delete',
            f"Are you sure you want to delete project '{selected_project}' and all its contents?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            project_path = f"terraform_projects/{selected_project}"
            try:
                import shutil
                shutil.rmtree(project_path)
                self.load_projects()
                self.log_message(f"Project '{selected_project}' deleted successfully.")
                logging.info(f"Deleted project '{selected_project}'.")
            except Exception as e:
                self.log_message(f"Failed to delete project: {e}")
                logging.error(f"Failed to delete project '{selected_project}': {e}")

    

    def add_workspace(self):
        """Add a new Terraform workspace."""
        selected_project = self.project_option.currentText()
        if not selected_project:
            self.log_message("Please select a project first.")
            QMessageBox.warning(self, "Warning", "Please select a project first.")
            return
        workspace_name, ok = QInputDialog.getText(self, "Add Workspace", "Enter workspace name:")
        if ok and workspace_name:
            project_path = f"terraform_projects/{selected_project}"
            try:
                create_command = ['terraform', 'workspace', 'new', workspace_name]
                subprocess.run(create_command, cwd=project_path, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.load_workspaces()
                self.log_message(f"Workspace '{workspace_name}' added successfully.")
                logging.info(f"Added workspace '{workspace_name}' in project '{selected_project}'.")
            except subprocess.CalledProcessError as e:
                self.log_message(f"Failed to add workspace: {e.stderr}")
                logging.error(f"Failed to add workspace '{workspace_name}' in project '{selected_project}': {e.stderr}")
            except Exception as e:
                self.log_message(f"Error adding workspace: {e}")
                logging.error(f"Error adding workspace '{workspace_name}' in project '{selected_project}': {e}")

    def delete_workspace(self):
        """Delete the selected Terraform workspace."""
        selected_project = self.project_option.currentText()
        selected_workspace = self.workspace_option.currentText()
        if not selected_project or not selected_workspace:
            self.log_message("Please select a project and workspace first.")
            QMessageBox.warning(self, "Warning", "Please select a project and workspace first.")
            return
        reply = QMessageBox.question(
            self, 'Confirm Delete',
            f"Are you sure you want to delete workspace '{selected_workspace}'?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            project_path = f"terraform_projects/{selected_project}"
            try:
                delete_command = ['terraform', 'workspace', 'delete', selected_workspace]
                subprocess.run(delete_command, cwd=project_path, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.load_workspaces()
                self.log_message(f"Workspace '{selected_workspace}' deleted successfully.")
                logging.info(f"Deleted workspace '{selected_workspace}' from project '{selected_project}'.")
            except subprocess.CalledProcessError as e:
                self.log_message(f"Failed to delete workspace: {e.stderr}")
                logging.error(f"Failed to delete workspace '{selected_workspace}' from project '{selected_project}': {e.stderr}")
            except Exception as e:
                self.log_message(f"Error deleting workspace: {e}")
                logging.error(f"Error deleting workspace '{selected_workspace}' from project '{selected_project}': {e}")

    ######################
    # Terraform Command Execution
    ######################

    def run_terraform_command(self, command):
        """Run Terraform commands in a separate thread."""
        selected_project = self.project_option.currentText()
        selected_workspace = self.workspace_option.currentText()
        if not selected_project or not selected_workspace:
            self.log_message("Please select a project and workspace first.")
            QMessageBox.warning(self, "Warning", "Please select a project and workspace first.")
            return
        project_path = f"terraform_projects/{selected_project}"
        cmd = ['terraform'] + command.split()

        # Retrieve extra variables
        # extra_vars = self.extra_vars_input.text().strip()
        # if extra_vars:
        #     try:
        #         extra_vars_json = json.loads(extra_vars)
        #         # Convert JSON to Terraform variable flags
        #         for key, value in extra_vars_json.items():
        #             cmd.append(f"-var")
        #             cmd.append(f"{key}={value}")
        #     except json.JSONDecodeError as e:
        #         self.log_message(f"Invalid JSON for extra variables: {e}")
        #         QMessageBox.warning(self, "Warning", f"Invalid JSON for extra variables: {e}")
        #         return

        thread = threading.Thread(target=self.execute_command, args=(cmd, project_path), daemon=True)
        thread.start()

    def execute_command(self, cmd, cwd):
        """Execute a Terraform command and stream output."""
        self.log_message(f"Executing: {' '.join(cmd)} in {cwd}")
        # Execute Pre-Command Script if defined
        pre_script = self.pre_script_input.text().strip()
        if pre_script:
            if os.path.exists(pre_script):
                self.log_message(f"Running pre-command script: {pre_script}")
                try:
                    subprocess.run([pre_script], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    self.log_message("Pre-command script executed successfully.")
                    logging.info(f"Executed pre-command script '{pre_script}'.")
                except subprocess.CalledProcessError as e:
                    self.log_message(f"Pre-command script failed: {e.stderr.decode().strip()}")
                    logging.error(f"Pre-command script '{pre_script}' failed: {e.stderr.decode().strip()}")
                    self.send_notification(f"Pre-command script failed: {e.stderr.decode().strip()}")
                    return
            else:
                self.log_message(f"Pre-command script not found: {pre_script}")
                logging.warning(f"Pre-command script not found: {pre_script}")

        process = subprocess.Popen(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        try:
            for line in process.stdout:
                self.log_message(line.strip())
                # Highlight errors
                if any(keyword in line.lower() for keyword in ["error", "failed"]):
                    self.highlight_error(line.strip())
            process.stdout.close()
            return_code = process.wait()
            if return_code == 0:
                self.log_message(f"Command '{' '.join(cmd)}' executed successfully.")
                self.send_notification(f"Terraform Command Success: {' '.join(cmd)}")
                logging.info(f"Executed command '{' '.join(cmd)}' in '{cwd}' successfully.")
            else:
                self.log_message(f"Command '{' '.join(cmd)}' failed with return code {return_code}.")
                self.send_notification(f"Terraform Command Failed: {' '.join(cmd)}")
                logging.error(f"Command '{' '.join(cmd)}' in '{cwd}' failed with return code {return_code}.")
        except Exception as e:
            self.log_message(f"Error executing command: {e}")
            self.send_notification(f"Terraform Command Error: {' '.join(cmd)} - {e}")
            logging.error(f"Error executing command '{' '.join(cmd)}' in '{cwd}': {e}")

        # Execute Post-Command Script if defined
        post_script = self.post_script_input.text().strip()
        if post_script:
            if os.path.exists(post_script):
                self.log_message(f"Running post-command script: {post_script}")
                try:
                    subprocess.run([post_script], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    self.log_message("Post-command script executed successfully.")
                    logging.info(f"Executed post-command script '{post_script}'.")
                except subprocess.CalledProcessError as e:
                    self.log_message(f"Post-command script failed: {e.stderr.decode().strip()}")
                    logging.error(f"Post-command script '{post_script}' failed: {e.stderr.decode().strip()}")
                    self.send_notification(f"Post-command script failed: {e.stderr.decode().strip()}")
            else:
                self.log_message(f"Post-command script not found: {post_script}")
                logging.warning(f"Post-command script not found: {post_script}")

    ######################
    # Extra Variables
    ######################
    # Already handled via self.extra_vars_input
    ######################
    # Scheduled Tasks Management
    ######################

    def schedule_command(self):
        """Schedule a Terraform command to run at a specified time."""
        command = self.schedule_command_option.currentText()
        project = self.schedule_project_option.currentText()
        workspace = self.schedule_workspace_option.currentText()
        scheduled_time = self.schedule_time_input.text().strip()
        extra_vars = self.extra_vars_input.text().strip()

        if not command or not project or not workspace or not scheduled_time:
            self.log_message("Please provide command, project, workspace, and scheduled time.")
            QMessageBox.warning(self, "Warning", "Please provide command, project, workspace, and scheduled time.")
            return

        # Validate datetime format
        try:
            scheduled_datetime = datetime.strptime(scheduled_time, "%Y-%m-%d %H:%M")
            if scheduled_datetime < datetime.now():
                self.log_message("Scheduled time must be in the future.")
                QMessageBox.warning(self, "Warning", "Scheduled time must be in the future.")
                return
        except ValueError:
            self.log_message("Invalid datetime format. Please use YYYY-MM-DD HH:MM.")
            QMessageBox.warning(self, "Warning", "Invalid datetime format. Please use YYYY-MM-DD HH:MM.")
            return

        # Add to scheduled tasks list
        schedule_item = QListWidgetItem(f"Command: {command}, Project: {project}, Workspace: {workspace}, Time: {scheduled_time}, Extra Vars: {extra_vars}")
        self.scheduled_tasks_list.addItem(schedule_item)
        self.log_message(f"Scheduled command '{command}' to run at {scheduled_time}.")
        logging.info(f"Scheduled command '{command}' for project '{project}', workspace '{workspace}' at {scheduled_time} with extra vars: {extra_vars}")

        # Start a thread to wait until the scheduled time and execute the command
        thread = threading.Thread(target=self.run_scheduled_command, args=(command, project, workspace, extra_vars, scheduled_datetime), daemon=True)
        thread.start()

    

    

    ######################
    # Interactive Configuration Editor
    ######################

    def load_configuration(self):
        """Load a Terraform configuration file into the editor."""
        selected_project = self.project_option.currentText()
        if not selected_project:
            self.log_message("Please select a project first.")
            QMessageBox.warning(self, "Warning", "Please select a project first.")
            return
        project_path = f"terraform_projects/{selected_project}"
        config_path, _ = QFileDialog.getOpenFileName(self, "Open Terraform Configuration", project_path, "Terraform Files (*.tf *.tfvars)")
        if config_path:
            try:
                with open(config_path, 'r') as f:
                    content = f.read()
                self.config_editor.setPlainText(content)
                self.current_config_path = config_path
                self.log_message(f"Loaded configuration file: {config_path}")
                logging.info(f"Loaded configuration file '{config_path}' for project '{selected_project}'.")
            except Exception as e:
                self.log_message(f"Failed to load configuration: {e}")
                logging.error(f"Failed to load configuration file '{config_path}' for project '{selected_project}': {e}")

    def save_configuration(self):
        """Save the edited Terraform configuration file."""
        if not hasattr(self, 'current_config_path') or not self.current_config_path:
            self.log_message("No configuration file loaded to save.")
            QMessageBox.warning(self, "Warning", "No configuration file loaded to save.")
            return
        try:
            content = self.config_editor.toPlainText()
            with open(self.current_config_path, 'w') as f:
                f.write(content)
            self.log_message(f"Configuration file '{self.current_config_path}' saved successfully.")
            logging.info(f"Saved configuration file '{self.current_config_path}'.")
        except Exception as e:
            self.log_message(f"Failed to save configuration: {e}")
            logging.error(f"Failed to save configuration file '{self.current_config_path}': {e}")

    ######################
    # Rollback Capability
    ######################

    def rollback_state(self):
        """Rollback Terraform state to the previous version."""
        selected_project = self.project_option.currentText()
        selected_workspace = self.workspace_option.currentText()
        if not selected_project or not selected_workspace:
            self.log_message("Please select a project and workspace first.")
            QMessageBox.warning(self, "Warning", "Please select a project and workspace first.")
            return
        project_path = f"terraform_projects/{selected_project}"
        try:
            # Fetch previous state (Placeholder: Implement actual state backup and rollback logic)
            # For demonstration, we'll assume there's a backup state file named 'terraform.tfstate.backup'
            backup_state = os.path.join(project_path, "terraform.tfstate.backup")
            current_state = os.path.join(project_path, "terraform.tfstate")
            if os.path.exists(backup_state):
                subprocess.run(['cp', backup_state, current_state], check=True)
                self.log_message(f"Rolled back state for project '{selected_project}', workspace '{selected_workspace}'.")
                self.send_notification(f"Terraform State Rolled Back for Project '{selected_project}', Workspace '{selected_workspace}'.")
                logging.info(f"Rolled back state for project '{selected_project}', workspace '{selected_workspace}'.")
            else:
                self.log_message("No backup state file found. Cannot rollback.")
                QMessageBox.warning(self, "Warning", "No backup state file found. Cannot rollback.")
                logging.warning(f"No backup state file found for project '{selected_project}', workspace '{selected_workspace}'.")
        except subprocess.CalledProcessError as e:
            self.log_message(f"Failed to rollback state: {e.stderr}")
            logging.error(f"Failed to rollback state for project '{selected_project}', workspace '{selected_workspace}': {e.stderr}")
        except Exception as e:
            self.log_message(f"Error during rollback: {e}")
            logging.error(f"Error during rollback for project '{selected_project}', workspace '{selected_workspace}': {e}")

    ######################
    # Notification Settings
    ######################

    def save_notification_settings(self):
        """Save notification settings for Email and Slack."""
        email = self.email_input.text().strip()
        slack_token = self.slack_token_input.text().strip()
        slack_channel = self.slack_channel_input.text().strip()

        settings = {
            "email": email,
            "slack_token": slack_token,
            "slack_channel": slack_channel
        }

        try:
            with open("settings.json", "w") as f:
                json.dump(settings, f)
            self.log_message("Notification settings saved successfully.")
            QMessageBox.information(self, "Success", "Notification settings saved successfully.")
            logging.info("Notification settings saved.")
        except Exception as e:
            self.log_message(f"Failed to save notification settings: {e}")
            QMessageBox.critical(self, "Error", f"Failed to save notification settings: {e}")
            logging.error(f"Failed to save notification settings: {e}")

    def load_notification_settings(self):
        """Load notification settings from file."""
        try:
            if os.path.exists("settings.json"):
                with open("settings.json", "r") as f:
                    settings = json.load(f)
                self.email_input.setText(settings.get("email", ""))
                self.slack_token_input.setText(settings.get("slack_token", ""))
                self.slack_channel_input.setText(settings.get("slack_channel", ""))
                self.log_message("Notification settings loaded successfully.")
                logging.info("Notification settings loaded.")
        except Exception as e:
            #self.log_message(f"Failed to load notification settings: {e}")
            logging.error(f"Failed to load notification settings: {e}")

    ######################
    # Automated Alerts
    ######################

    def send_notification(self, message):
        """Send notifications via Email and Slack based on settings."""
        # Load settings
        try:
            with open("settings.json", "r") as f:
                settings = json.load(f)
            email = settings.get("email", "")
            slack_token = settings.get("slack_token", "")
            slack_channel = settings.get("slack_channel", "")
        except Exception as e:
            #self.log_message(f"Failed to load notification settings: {e}")
            logging.error(f"Failed to load notification settings: {e}")
            return

        # Send Email
        if email:
            try:
                smtp_server = "smtp.gmail.com"  # Example SMTP server
                smtp_port = 587
                smtp_username = os.getenv("SMTP_USERNAME")  # Use environment variables for security
                smtp_password = os.getenv("SMTP_PASSWORD")  # Use environment variables for security
                if not smtp_username or not smtp_password:
                    self.log_message("SMTP credentials not set in environment variables.")
                    logging.warning("SMTP credentials not set in environment variables.")
                else:
                    msg = MIMEText(message)
                    msg['Subject'] = "Terraform Notification"
                    msg['From'] = smtp_username
                    msg['To'] = email

                    server = smtplib.SMTP(smtp_server, smtp_port)
                    server.starttls()
                    server.login(smtp_username, smtp_password)
                    server.send_message(msg)
                    server.quit()
                    self.log_message(f"Email notification sent to {email}.")
                    logging.info(f"Email notification sent to {email}.")
            except Exception as e:
                self.log_message(f"Failed to send email notification: {e}")
                logging.error(f"Failed to send email notification to {email}: {e}")

        # Send Slack Notification
        if slack_token and slack_channel:
            try:
                client = WebClient(token=slack_token)
                response = client.chat_postMessage(
                    channel=slack_channel,
                    text=message
                )
                if response["ok"]:
                    self.log_message(f"Slack notification sent to channel {slack_channel}.")
                    logging.info(f"Slack notification sent to channel {slack_channel}.")
                else:
                    self.log_message(f"Failed to send Slack notification: {response['error']}")
                    logging.error(f"Failed to send Slack notification to channel {slack_channel}: {response['error']}")
            except SlackApiError as e:
                self.log_message(f"Slack API Error: {e.response['error']}")
                logging.error(f"Slack API Error while sending notification: {e.response['error']}")
            except Exception as e:
                self.log_message(f"Failed to send Slack notification: {e}")
                logging.error(f"Failed to send Slack notification: {e}")

    ######################
    # Audit Trails
    ######################

    def setup_logging(self):
        """Setup logging for audit trails."""
        log_dir = "logs"
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        log_file = os.path.join(log_dir, "terraform_audit.log")
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        logging.info("TerraformTab initialized.")
        


    def strip_ansi_codes(self, text):
        """
        Remove ANSI escape sequences from the given text.
        
        :param text: The string containing ANSI escape sequences.
        :return: Cleaned string without ANSI codes.
        """
        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
        return ansi_escape.sub('', text)

    def log_message(self, message):
        """Log messages to the output area and audit trail."""
        
        # Strip ANSI escape codes from the message
        clean_message = self.strip_ansi_codes(message)
        
        # Check if output_area exists before attempting to use it
        if hasattr(self, 'output_area') and self.output_area is not None:
            self.output_area.append(clean_message)
        else:
            # Fallback: print to console or store logs in a buffer until output_area is ready
            print(f"{clean_message}")
        
        # Log to file
        logging.info(clean_message)


    def view_audit_logs(self):
        """Display audit logs."""
        log_file = "logs/terraform_audit.log"
        try:
            with open(log_file, 'r') as f:
                content = f.read()
            # Open a dialog to display logs
            dialog = QMessageBox(self)
            dialog.setWindowTitle("Audit Logs")
            dialog.setText("Displaying Audit Logs:")
            dialog.setDetailedText(content)
            dialog.setStandardButtons(QMessageBox.Ok)
            dialog.exec_()
        except Exception as e:
            self.log_message(f"Failed to load audit logs: {e}")
            logging.error(f"Failed to load audit logs: {e}")

    ######################
    # Rollback Capability
    ######################

    # Already implemented via rollback_state()

    ######################
    # Metrics Visualization
    ######################

    
    def update_metrics_visualization(self, metrics_data):
        """
        Update the Plotly metrics visualization asynchronously.
        
        :param metrics_data: List of dictionaries with 'timestamp', 'cpu', 'memory' keys.
        """
        # Show loading indicator
        self.loading_label.show()
        
        # Disable the metrics tab to prevent multiple updates
        self.metrics_canvas.setEnabled(False)
        
        # Create and start the worker
        worker = MetricsDataProcessor(metrics_data)
        worker.signals.finished.connect(self.on_metrics_processed)
        worker.signals.error.connect(self.on_metrics_error)
        self.threadpool.start(worker)

    def on_metrics_processed(self, processed_data):
        """
        Slot to handle the processed metrics data.
        
        :param processed_data: List of dictionaries with 'timestamp', 'cpu', 'memory' keys.
        """
        self.metrics_canvas.plot_metrics(processed_data)
        
        # Hide loading indicator and re-enable the metrics tab
        self.loading_label.hide()
        self.metrics_canvas.setEnabled(True)
        
        self.log_message("Metrics visualization updated successfully.")

    def on_metrics_error(self, error_message):
        """
        Slot to handle errors during metrics data processing.
        
        :param error_message: Error message string.
        """
        self.loading_label.hide()
        self.metrics_canvas.setEnabled(True)
        self.log_message(f"Error updating metrics visualization: {error_message}")
        QMessageBox.critical(self, "Error", f"Failed to update metrics visualization: {error_message}")

    ######################
    # User Authentication and Authorization
    ######################

    # Placeholder: Implement user roles and permissions
    # Integrate with the main application's authentication system to enforce RBAC.

    ######################
    # Integration with CI/CD Pipelines
    ######################

    # Placeholder: Implement triggers based on CI/CD events
    # This could involve setting up webhook listeners or integrating with CI/CD tools' APIs.

    ######################
    # Helper Methods
    ######################

    # def get_workspace_directories(self, project):
    #     """Retrieve a list of Terraform workspaces for a given project."""
    #     project_path = f"terraform_projects/{project}"
    #     try:
    #         list_command = ['terraform', 'workspace', 'list']
    #         result = subprocess.run(list_command, cwd=project_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    #         if result.returncode != 0:
    #             self.log_message(f"Error listing workspaces: {result.stderr}")
    #             logging.error(f"Error listing workspaces for project '{project}': {result.stderr}")
    #             return []
    #         workspaces = [ws.strip('* ').strip() for ws in result.stdout.strip().split('\n') if ws]
    #         return workspaces
    #     except Exception as e:
    #         self.log_message(f"Failed to retrieve workspaces: {e}")
    #         logging.error(f"Failed to retrieve workspaces for project '{project}': {e}")
    #         return []

    ######################
    # Additional Functionalities
    ######################
    # Implement additional functionalities as needed

    ######################
    # Error Highlighting and Debugging
    ######################

    def highlight_error(self, line):
        """Highlight error lines in the output area."""
        # Simple implementation: append error in red color
        # For a more sophisticated approach, consider using rich text or custom text formats
        error_message = f"<span style='color:red;'><b>{line}</b></span>"
        self.output_area.append(error_message)



