import os
import sys

from PyQt5.QtWidgets import (QComboBox, QFileDialog, QHBoxLayout, QLabel,
                             QLineEdit, QPushButton, QTextEdit, QVBoxLayout,
                             QWidget)

from ansible_tab.ansible_tab import AnsibleTab
from aws.aws_tab import AWSTab
from gitlab_tab.gtlab_tab import GitLabTab
from jenkins_tab.jenkins_tab import JenkinsTab
from k8s.k8s_tab import K8sTab
from ssh.ssh_tab import SSHTab
from terraform.terraform_tab import TerraformTab
from text_editor_dialog import TextEditorDialog


class SystemTab(QWidget):
    def __init__(self, auth_manager, main_tab_widget):
        super().__init__()
        self.auth_manager = auth_manager
        self.main_tab_widget = main_tab_widget
        self.current_service_tab = None  # Placeholder for the current service tab
        self.initUI()

    def initUI(self):
        main_layout = QVBoxLayout()

        # Dropdown for selecting a service
        self.service_dropdown = QComboBox(self)
        self.service_dropdown.addItems(["System", "SSH", "AWS", "K8S", "GITAB", "ANSIBLE", "TERRAFORM", "JENKINS"])  # Add more services as needed
        self.service_dropdown.currentIndexChanged.connect(self.load_service_tab)

        # Add Service Dropdown to the main layout
        main_layout.addWidget(QLabel("Select a Service:"))
        main_layout.addWidget(self.service_dropdown)

        # System-related UI Components
        self.system_info_label = QLabel("System Info: Not fetched yet", self)
        self.system_info_button = QPushButton("Get System Info", self)
        self.system_info_button.clicked.connect(self.get_system_info)

        self.open_dir_button = QPushButton("Open Directory and List Files", self)
        self.open_dir_button.clicked.connect(self.open_directory)
        self.files_text = QTextEdit(self)

        self.command_input = QLineEdit(self)
        self.command_input.setPlaceholderText("Enter a command to run")
        self.run_command_button = QPushButton("Run Command", self)
        self.run_command_button.clicked.connect(self.run_command)
        
        # Add Text Editor Button
        self.text_editor_button = QPushButton("Open Text Editor", self)
        self.text_editor_button.clicked.connect(self.open_text_editor)

        # Layouts for System-related UI
        left_column = QVBoxLayout()
        right_column = QVBoxLayout()

        left_column.addWidget(self.system_info_label)
        left_column.addWidget(self.system_info_button)
        left_column.addWidget(self.open_dir_button)
        left_column.addWidget(self.files_text)
        left_column.addWidget(self.command_input)
        left_column.addWidget(self.run_command_button)
        left_column.addWidget(self.text_editor_button)
        
        

        self.command_output = QTextEdit(self)
        right_column.addWidget(self.command_output)

        # Create the layout for the system-related UI and add it to the main layout
        system_layout = QHBoxLayout()
        system_layout.addLayout(left_column)
        system_layout.addLayout(right_column)
        main_layout.addLayout(system_layout)

        self.setLayout(main_layout)

    def load_service_tab(self):
        """
        Load the selected service's UI into the service layout and update the main tab widget.
        """
        selected_service = self.service_dropdown.currentText()

        # Clear other tabs in the main tab widget except for the selected service
        for i in reversed(range(self.main_tab_widget.count())):
            self.main_tab_widget.removeTab(i)

        # Load the selected service tab
        if selected_service == "System":
            self.main_tab_widget.addTab(self, "System")
            self.main_tab_widget.setCurrentWidget(self)
        elif selected_service == "SSH":
            self.current_service_tab = SSHTab(self.auth_manager, self.main_tab_widget)
            self.main_tab_widget.addTab(self.current_service_tab, "SSH")
            self.main_tab_widget.setCurrentWidget(self.current_service_tab)
        elif selected_service == "AWS":
            self.current_service_tab = AWSTab(self.auth_manager, self.main_tab_widget)
            self.main_tab_widget.addTab(self.current_service_tab, "AWS")
            self.main_tab_widget.setCurrentWidget(self.current_service_tab)
        elif selected_service == "K8S":  # Add the K8s option
            self.current_service_tab = K8sTab(self.auth_manager, self.main_tab_widget)
            self.main_tab_widget.addTab(self.current_service_tab, "K8S")
            self.main_tab_widget.setCurrentWidget(self.current_service_tab)

        elif selected_service == "GITAB":  # Add the GITAB option
            self.current_service_tab = GitLabTab(self.auth_manager, self.main_tab_widget)
            self.main_tab_widget.addTab(self.current_service_tab, "GITAB")
            self.main_tab_widget.setCurrentWidget(self.current_service_tab)
            
        elif selected_service == "ANSIBLE":  # Add the ANSIBLE option
            self.current_service_tab = AnsibleTab(self.auth_manager, self.main_tab_widget)
            self.main_tab_widget.addTab(self.current_service_tab, "ANSIBLE")
            self.main_tab_widget.setCurrentWidget(self.current_service_tab)
            
        elif selected_service == "TERRAFORM":  # Add the TERRAFORM option
            self.current_service_tab = TerraformTab(self.auth_manager, self.main_tab_widget)
            self.main_tab_widget.addTab(self.current_service_tab, "TERRAFORM")
            self.main_tab_widget.setCurrentWidget(self.current_service_tab)
            
        elif selected_service == "JENKINS":  # Add the JENKINS option
            self.current_service_tab = JenkinsTab(self.auth_manager, self.main_tab_widget)
            self.main_tab_widget.addTab(self.current_service_tab, "JENKINS")
            self.main_tab_widget.setCurrentWidget(self.current_service_tab)

    def get_system_info(self):
        system_info = f"OS: {os.name}\nPlatform: {sys.platform}\nVersion: {os.sys.version}\n"
        self.system_info_label.setText(f"System Info:\n{system_info}")

    def open_directory(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select Directory")
        if dir_path:
            files = os.listdir(dir_path)
            self.files_text.setText("\n".join(files))

    def run_command(self):
        command = self.command_input.text()
        if command:
            try:
                result = os.popen(command).read()
                self.command_output.setText(result)
            except Exception as e:
                self.command_output.setText(f"Error: {str(e)}")
                
    def open_text_editor(self):
        """
        Opens the text editor dialog.
        """
        dialog = TextEditorDialog(self)
        dialog.exec_()