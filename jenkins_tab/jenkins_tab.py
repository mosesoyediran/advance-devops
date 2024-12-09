import base64
import json
import os
import threading
import time
from datetime import datetime

import jenkins
import requests
from PyQt5.QtCore import QRunnable, Qt, QThreadPool, pyqtSlot
from PyQt5.QtGui import QTextCursor
from PyQt5.QtWidgets import (QComboBox, QFileDialog, QGridLayout, QGroupBox,
                             QHBoxLayout, QInputDialog, QLabel, QLineEdit,
                             QListWidget, QListWidgetItem, QMessageBox,
                             QPushButton, QRadioButton, QSplitter, QTabWidget,
                             QTextEdit, QVBoxLayout, QWidget)
from requests.auth import HTTPBasicAuth


class BuildWorker(QRunnable):
    def __init__(self, jenkins_server, job_name, log_message_callback):
        super().__init__()
        self.jenkins_server = jenkins_server
        self.job_name = job_name
        self.log_message_callback = log_message_callback

    @pyqtSlot()
    def run(self):
        # Run build process in a separate thread
        try:
            self.log_message_callback(f"Triggering build for job '{self.job_name}'...")

            # Start the build for the selected job
            self.jenkins_server.build_job(self.job_name)
            self.log_message_callback(f"Build started for job '{self.job_name}'.")

            # Wait for a moment to let Jenkins initialize the build
            time.sleep(5)

            # Get the job information to determine the current build number
            job_info = self.jenkins_server.get_job_info(self.job_name)

            # Check for ongoing builds
            if 'lastBuild' in job_info and job_info['lastBuild']:
                build_number = job_info['lastBuild']['number']
                self.log_message_callback(f"Waiting for build #{build_number} to complete...")

                # Monitor the build status
                build_info = None
                while True:
                    time.sleep(2)  # Delay between status checks
                    build_info = self.jenkins_server.get_build_info(self.job_name, build_number)

                    # Check if the build has finished
                    if build_info['building']:
                        self.log_message_callback(f"Build #{build_number} is still in progress...")
                    else:
                        break

                # Display the final build status
                status = build_info['result']
                self.log_message_callback(f"Build #{build_number} for job '{self.job_name}' finished with status: {status}")

                # Fetch and display build logs
                console_output = self.jenkins_server.get_build_console_output(self.job_name, build_number)
                self.log_message_callback(f"Build Logs for job '{self.job_name}' (Build #{build_number}):\n{console_output}")
            else:
                self.log_message_callback(f"No build was found for job '{self.job_name}'. The build might not have been triggered properly.")

        except jenkins.JenkinsException as e:
            self.log_message_callback(f"Failed to trigger build for job '{self.job_name}': {e}")
        except Exception as e:
            self.log_message_callback(f"Unexpected error occurred while triggering build for job '{self.job_name}': {e}")

# Main JenkinsTab Class
class JenkinsTab(QWidget):
    def __init__(self, auth_manager, main_tab_widget):
        super().__init__()
        self.auth_manager = auth_manager
        self.main_tab_widget = main_tab_widget
        self.jenkins_server = None
        self.git_repo = None  # Git repository for version control integration
        self.threadpool = QThreadPool() 
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

        # Jenkins Server Connection Group
        connection_group = QGroupBox("Jenkins Server Connection")
        connection_layout = QGridLayout()

        # Load saved credentials if they exist
        credentials = self.load_credentials()
        self.connected = False  # Track connection status

        if credentials:
            # Display the username from saved credentials
            self.username_label = QLabel(f"Username: {credentials['username']}")
            connection_layout.addWidget(self.username_label, 0, 0)

            # Radio button to enter new details
            self.new_credentials_radio = QRadioButton("Enter New Details")
            self.new_credentials_radio.setChecked(False)
            connection_layout.addWidget(self.new_credentials_radio, 0, 1)

            # Jenkins URL input (hidden initially)
            self.jenkins_url_input = QLineEdit(self)
            self.jenkins_url_input.setPlaceholderText("http://your-jenkins-server:8080")
            self.jenkins_url_input.setToolTip("Enter the URL of your Jenkins server.")
            self.jenkins_url_input.setVisible(False)  # Hidden by default
            connection_layout.addWidget(self.jenkins_url_input, 1, 0, 1, 2)

            # Jenkins Username input (hidden initially)
            self.jenkins_username_input = QLineEdit(self)
            self.jenkins_username_input.setPlaceholderText("Username")
            self.jenkins_username_input.setToolTip("Enter your Jenkins username.")
            self.jenkins_username_input.setVisible(False)  # Hidden by default
            connection_layout.addWidget(self.jenkins_username_input, 2, 0, 1, 2)

            # Jenkins API Token input (hidden initially)
            self.jenkins_api_token_input = QLineEdit(self)
            self.jenkins_api_token_input.setPlaceholderText("API Token")
            self.jenkins_api_token_input.setToolTip("Enter your Jenkins API token.")
            self.jenkins_api_token_input.setEchoMode(QLineEdit.Password)
            self.jenkins_api_token_input.setVisible(False)  # Hidden by default
            connection_layout.addWidget(self.jenkins_api_token_input, 3, 0, 1, 2)

            # Connect radio button to toggle visibility
            self.new_credentials_radio.toggled.connect(self.toggle_new_credentials_input)
        else:
            # No saved credentials, show input fields
            self.jenkins_url_input = QLineEdit(self)
            self.jenkins_url_input.setPlaceholderText("http://your-jenkins-server:8080")
            self.jenkins_url_input.setToolTip("Enter your Jenkins server URL.")
            connection_layout.addWidget(QLabel("Jenkins URL:"), 1, 0)
            connection_layout.addWidget(self.jenkins_url_input, 1, 1)

            self.jenkins_username_input = QLineEdit(self)
            self.jenkins_username_input.setPlaceholderText("Username")
            self.jenkins_username_input.setToolTip("Enter your Jenkins username.")
            connection_layout.addWidget(QLabel("Username:"), 2, 0)
            connection_layout.addWidget(self.jenkins_username_input, 2, 1)

            self.jenkins_api_token_input = QLineEdit(self)
            self.jenkins_api_token_input.setPlaceholderText("API Token")
            self.jenkins_api_token_input.setToolTip("Enter your Jenkins API token.")
            self.jenkins_api_token_input.setEchoMode(QLineEdit.Password)
            connection_layout.addWidget(QLabel("API Token:"), 3, 0)
            connection_layout.addWidget(self.jenkins_api_token_input, 3, 1)

        # Button to connect or disconnect to/from Jenkins
        self.connect_button = QPushButton("Connect")
        self.connect_button.clicked.connect(self.toggle_connection)
        self.connect_button.setToolTip("Click to connect or disconnect from the Jenkins server.")
        connection_layout.addWidget(self.connect_button, 4, 0, 1, 2)

        connection_group.setLayout(connection_layout)
        left_layout.addWidget(connection_group)

        # Job Management Group
        job_group = QGroupBox("Job Management")
        job_layout = QVBoxLayout()

        # Job label and dropdown for listing Jenkins jobs (This will be at the top)
        job_selection_layout = QHBoxLayout()
        self.job_list_label = QLabel("Job:")
        self.job_list_dropdown = QComboBox()
        self.job_list_dropdown.setToolTip("Select a Jenkins job")

        # Add the label and dropdown to the same horizontal layout
        job_selection_layout.addWidget(self.job_list_label)
        job_selection_layout.addWidget(self.job_list_dropdown)

        # Add job selection layout to the main layout
        job_layout.addLayout(job_selection_layout)
        
        # Credential label and dropdown for listing Jenkins credentials
        credential_selection_layout = QHBoxLayout()
        self.credential_list_label = QLabel("Credential:")
        self.credential_list_dropdown = QComboBox()
        self.credential_list_dropdown.setToolTip("Select a Jenkins credential")

        # Add the label and dropdown to the same horizontal layout
        credential_selection_layout.addWidget(self.credential_list_label)
        credential_selection_layout.addWidget(self.credential_list_dropdown)

        # Add credential selection layout to the main layout
        job_layout.addLayout(credential_selection_layout)

        # Dropdown for job actions
        self.job_action_dropdown = QComboBox()
        self.job_action_dropdown.addItem("Refresh Jobs")
        self.job_action_dropdown.addItem("Create Job")
        self.job_action_dropdown.addItem("Delete Job")
        self.job_action_dropdown.addItem("Create Generic Credentials")

        # Execute button
        self.execute_job_button = QPushButton("Execute")
        self.execute_job_button.clicked.connect(self.execute_job_action)

        # Horizontal layout for job actions and execute button
        job_dropdown_layout = QHBoxLayout()
        job_dropdown_layout.addWidget(self.job_action_dropdown)
        job_dropdown_layout.addWidget(self.execute_job_button)

        # Add job action dropdown layout to the main layout (below the job selection)
        job_layout.addLayout(job_dropdown_layout)

        job_group.setLayout(job_layout)
        left_layout.addWidget(job_group)

        # Build Management Group
        # Build Management Group
        build_group = QGroupBox("Build Management")
        build_layout = QVBoxLayout()

        # Dropdown for build actions
        self.build_action_dropdown = QComboBox()
        self.build_action_dropdown.addItem("Trigger Build")
        self.build_action_dropdown.addItem("Stop Build")

        # Execute button
        self.execute_build_button = QPushButton("Execute")
        self.execute_build_button.clicked.connect(self.trigger_build)


        # Layout for dropdown and execute button
        build_dropdown_layout = QHBoxLayout()
        build_dropdown_layout.addWidget(self.build_action_dropdown)
        build_dropdown_layout.addWidget(self.execute_build_button)

        build_layout.addLayout(build_dropdown_layout)

        build_group.setLayout(build_layout)
        left_layout.addWidget(build_group)

        # Scheduled Builds Group
        schedule_group = QGroupBox("Scheduled Builds")
        schedule_layout = QVBoxLayout()

        # Schedule Form
        schedule_form_layout = QGridLayout()

        # Job Selection
        self.schedule_job_option = QComboBox(self)
        self.schedule_job_option.setToolTip("Select the Jenkins job to schedule.")
        schedule_form_layout.addWidget(QLabel("Job:"), 0, 0)
        schedule_form_layout.addWidget(self.schedule_job_option, 0, 1)

        # Scheduled Time
        self.schedule_time_input = QLineEdit(self)
        self.schedule_time_input.setPlaceholderText("YYYY-MM-DD HH:MM")
        self.schedule_time_input.setToolTip("Enter the datetime to trigger the build (e.g., 2024-09-18 14:30).")
        schedule_form_layout.addWidget(QLabel("Scheduled Time:"), 1, 0)
        schedule_form_layout.addWidget(self.schedule_time_input, 1, 1)

        # Schedule Button
        self.schedule_build_button = QPushButton("Schedule Build")
        self.schedule_build_button.clicked.connect(self.schedule_build)
        self.schedule_build_button.setToolTip("Click to schedule the selected Jenkins build.")
        schedule_form_layout.addWidget(self.schedule_build_button, 2, 0, 1, 2)

        schedule_layout.addLayout(schedule_form_layout)


        # Cancel Schedule Button
        self.cancel_schedule_button = QPushButton("Cancel Selected Schedule")
        self.cancel_schedule_button.clicked.connect(self.cancel_schedule)
        self.cancel_schedule_button.setToolTip("Cancel the selected scheduled build.")
        schedule_layout.addWidget(self.cancel_schedule_button)

        schedule_group.setLayout(schedule_layout)
        left_layout.addWidget(schedule_group)

        # Git Integration Group
        git_group = QGroupBox("Version Control Integration")
        git_layout = QVBoxLayout()

        # Dropdown for git actions
        self.git_action_dropdown = QComboBox()
        self.git_action_dropdown.addItem("Clone Repository")
        self.git_action_dropdown.addItem("Commit Changes")
        self.git_action_dropdown.addItem("Push Changes")

        # Execute button
        self.execute_git_button = QPushButton("Execute")
        self.execute_git_button.clicked.connect(self.execute_git_action)

        # Layout for dropdown and execute button
        git_dropdown_layout = QHBoxLayout()
        git_dropdown_layout.addWidget(self.git_action_dropdown)
        git_dropdown_layout.addWidget(self.execute_git_button)

        git_layout.addLayout(git_dropdown_layout)

        # Input field for repository path
        git_layout.addWidget(QLabel("Repository Path:"))
        self.repo_path_input = QLineEdit(self)
        self.repo_path_input.setPlaceholderText("/path/to/git/repo")
        self.repo_path_input.setToolTip("Enter the local path of the Git repository.")
        git_layout.addWidget(self.repo_path_input)

        git_group.setLayout(git_layout)
        left_layout.addWidget(git_group)

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
        self.output_area.setToolTip("Displays Jenkins command outputs and logs.")
        output_layout.addWidget(self.output_area)
        output_tab.setLayout(output_layout)
        tabs.addTab(output_tab, "Output & Logs")

        # Tab 2: Rollback
        rollback_tab = QWidget()
        rollback_layout = QVBoxLayout()
        self.rollback_button = QPushButton("Rollback to Previous Configuration")
        self.rollback_button.clicked.connect(self.rollback_state)
        self.rollback_button.setToolTip("Revert Jenkins job configuration to the previous version.")
        rollback_layout.addWidget(self.rollback_button)
        rollback_tab.setLayout(rollback_layout)
        tabs.addTab(rollback_tab, "Rollback")
        
        
        # Tab 3: Configure Tools
        configure_tab = QWidget()
        configure_layout = QVBoxLayout()

        # Tools GroupBox
        tools_group = QGroupBox("Configure Tools")
        tools_layout = QHBoxLayout()

        # Dropdown for selecting tools
        self.tools_dropdown = QComboBox()
        self.tools_dropdown.setToolTip("Select a tool to configure.")
        # Add available tools to the dropdown (example: Jenkins, Git, Docker)
        self.tools_dropdown.addItems(["Jenkins", "Git", "Docker"])  # Extend the list as needed

        # Dropdown for selecting action (Install/Uninstall)
        self.action_dropdown = QComboBox()
        self.action_dropdown.setToolTip("Select an action to perform on the tool.")
        self.action_dropdown.addItems(["Install", "Uninstall"])

        # Execute button for performing the action
        self.execute_tool_action_button = QPushButton("Execute")
        self.execute_tool_action_button.clicked.connect(self.execute_tool_action)

        # Add dropdowns and button to the layout
        tools_layout.addWidget(QLabel("Tool:"))
        tools_layout.addWidget(self.tools_dropdown)
        tools_layout.addWidget(QLabel("Action:"))
        tools_layout.addWidget(self.action_dropdown)
        tools_layout.addWidget(self.execute_tool_action_button)

        tools_group.setLayout(tools_layout)
        configure_layout.addWidget(tools_group)

        # Plugins GroupBox
        plugins_group = QGroupBox("Manage Plugins")
        plugins_layout = QHBoxLayout()

        # Dropdown for selecting plugins
        self.plugins_dropdown = QComboBox()
        self.plugins_dropdown.setToolTip("Select a plugin to manage.")
        # Add available plugins to the dropdown (example plugins)
        self.plugins_dropdown.addItems(["Plugin1", "Plugin2", "Plugin3"])  # Extend the list as needed

        # Dropdown for selecting action (Install/Uninstall)
        self.plugin_action_dropdown = QComboBox()
        self.plugin_action_dropdown.setToolTip("Select an action to perform on the plugin.")
        self.plugin_action_dropdown.addItems(["Install", "Uninstall"])

        # Execute button for performing the plugin action
        self.execute_plugin_action_button = QPushButton("Execute")
        self.execute_plugin_action_button.clicked.connect(self.execute_plugin_action)

        # Add dropdowns and button to the layout
        plugins_layout.addWidget(QLabel("Plugin:"))
        plugins_layout.addWidget(self.plugins_dropdown)
        plugins_layout.addWidget(QLabel("Action:"))
        plugins_layout.addWidget(self.plugin_action_dropdown)
        plugins_layout.addWidget(self.execute_plugin_action_button)

        plugins_group.setLayout(plugins_layout)
        configure_layout.addWidget(plugins_group)

        configure_tab.setLayout(configure_layout)
        tabs.addTab(configure_tab, "Configure Tools")

        right_layout.addWidget(tabs)
        right_widget.setLayout(right_layout)

        splitter.addWidget(right_widget)

        # Set splitter sizes
        splitter.setSizes([400, 800])

        main_layout.addWidget(splitter)
        self.setLayout(main_layout)
        
        
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

    # Function to handle toggling of new credential inputs
    # Function to handle toggling of new credential inputs
    def toggle_new_credentials_input(self):
        is_new = self.new_credentials_radio.isChecked()
        if is_new:
            # Disconnect if currently connected
            if self.connected:
                self.disconnect_from_jenkins()
            
            # Show input fields for new credentials
            self.jenkins_url_input.setVisible(True)
            self.jenkins_username_input.setVisible(True)
            self.jenkins_api_token_input.setVisible(True)
        else:
            # Hide input fields if toggled back to use saved credentials
            self.jenkins_url_input.setVisible(False)
            self.jenkins_username_input.setVisible(False)
            self.jenkins_api_token_input.setVisible(False)

    # Function to connect or disconnect to/from Jenkins
    def toggle_connection(self):
        if not self.connected:
            # Validate fields only when connecting
            if self.new_credentials_radio.isChecked():
                # Check for empty fields
                if not self.jenkins_url_input.text().strip() or not self.jenkins_username_input.text().strip() or not self.jenkins_api_token_input.text().strip():
                    QMessageBox.warning(self, "Missing Details", "Please fill in all the required fields.")
                    return

                # Use new details for connection
                credentials = {
                    "url": self.jenkins_url_input.text().strip(),
                    "username": self.jenkins_username_input.text().strip(),
                    "api_token": self.jenkins_api_token_input.text().strip()
                }
            else:
                # Use saved credentials
                credentials = self.load_credentials()

            self.connect_to_jenkins(credentials)
        else:
            # Disconnect
            self.disconnect_from_jenkins()

    ######################
    # Jenkins Server Connection
    ######################

    # Function to connect to Jenkins
    def connect_to_jenkins(self, credentials):
        try:
            # Initialize the Jenkins server connection
            self.jenkins_server = jenkins.Jenkins(
                credentials['url'],
                username=credentials['username'],
                password=credentials['api_token']
            )
            
            # Check if the connection is valid
            user = self.jenkins_server.get_whoami()
            version = self.jenkins_server.get_version()
            self.log_message(f"Connected to Jenkins as {user['fullName']} (Version: {version})")
            
            # Update button and connection status
            self.connect_button.setText("Disconnect")
            self.connected = True

            # Automatically refresh the job list after a successful connection
            self.refresh_jobs()
            self.fetch_credentials()

        except jenkins.JenkinsException as e:
            self.log_message(f"Connection failed: {e}")
            QMessageBox.critical(self, "Connection Error", f"Failed to connect to Jenkins: {e}")
        except Exception as e:
            self.log_message(f"Unexpected error occurred: {e}")
            QMessageBox.critical(self, "Error", f"Unexpected error occurred: {e}")


    # Function to disconnect from Jenkins
    def disconnect_from_jenkins(self):
        try:
            # Reset the Jenkins server connection and related attributes
            self.jenkins_server = None
            self.connected = False
            
            # Clear the job list dropdown and other UI elements if necessary
            self.job_list_dropdown.clear()
            
            # Update UI elements to reflect disconnection status
            self.connect_button.setText("Connect")
            
            # Log the disconnection
            self.log_message("Disconnected from Jenkins")

        except Exception as e:
            self.log_message(f"Disconnection failed: {e}")
            QMessageBox.critical(self, "Error", f"Disconnection failed: {e}")

    
    def use_saved_credentials(self):
        credentials = self.load_credentials()
        if credentials:
            self.jenkins_url_input.setText(credentials["url"])
            self.jenkins_username_input.setText(credentials["username"])
            self.jenkins_api_token_input.setText(credentials["api_token"])
            QMessageBox.information(self, "Credentials Loaded", "Loaded saved Jenkins credentials successfully!")
            
    

    
    def save_credentials(self):
        # Prompt user for Jenkins details
        jenkins_url, url_ok = QInputDialog.getText(self, "Jenkins URL", "Enter your Jenkins URL:")
        jenkins_username, user_ok = QInputDialog.getText(self, "Jenkins Username", "Enter your Jenkins username:")
        jenkins_api_token, token_ok = QInputDialog.getText(self, "Jenkins API Token", "Enter your Jenkins API token:")

        # Ensure all inputs are provided
        if not (url_ok and user_ok and token_ok) or not (jenkins_url and jenkins_username and jenkins_api_token):
            QMessageBox.warning(self, "Input Error", "All credentials must be provided.")
            return

        # Save credentials to a JSON file
        credentials = {
            "url": jenkins_url.strip(),
            "username": jenkins_username.strip(),
            "api_token": jenkins_api_token.strip()
        }

        try:
            with open("jenkins_credentials.json", "w") as cred_file:
                json.dump(credentials, cred_file)
            QMessageBox.information(self, "Saved", "Credentials saved successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Save Error", f"Failed to save credentials: {e}")

    def load_credentials(self):
        # Load credentials from JSON file
        try:
            if os.path.exists("jenkins_credentials.json"):
                with open("jenkins_credentials.json", "r") as cred_file:
                    credentials = json.load(cred_file)
                return credentials
            else:
                QMessageBox.warning(self, "No Credentials", "No saved credentials found. Please save them first.")
                return None
        except Exception as e:
            QMessageBox.critical(self, "Load Error", f"Failed to load credentials: {e}")
            return None

    


    ######################
    # Job Management
    ######################
    
    def fetch_credentials(self):
        try:
            # Construct the Jenkins credentials API endpoint
            url = f"{self.jenkins_server.server}/credentials/store/system/domain/_/api/json?tree=credentials[id,description]"
            
            # Use Jenkins username and token for Basic Authentication
            credentials = self.load_credentials()
            response = requests.get(url, auth=HTTPBasicAuth(credentials['username'], credentials['api_token']))
            
            # Check for a successful response
            response.raise_for_status()
            data = response.json()
            
            # Extract credential IDs
            credentials_list = data.get('credentials', [])
            
            # Populate the dropdown with the credentials
            self.credential_list_dropdown.clear()
            for cred in credentials_list:
                cred_id = cred['id']
                description = cred.get('description', 'No description')
                # Add item with the credential ID as text and set the credential ID as itemData
                self.credential_list_dropdown.addItem(f"{cred_id} - {description}", cred_id)  # Note the second argument is now just `cred_id`.
            
            self.log_message("Credentials loaded successfully.")
        
        except requests.exceptions.RequestException as e:
            self.log_message(f"Failed to load credentials: {e}")
            QMessageBox.critical(self, "Error", f"Failed to load credentials: {e}")





    
    

    # Function to execute the selected job action
    def execute_job_action(self):
        selected_action = self.job_action_dropdown.currentText()
        selected_job = self.job_list_dropdown.currentText()
        
        if selected_action == "Refresh Jobs":
            self.refresh_jobs()
        elif selected_action == "Create Job":
            self.create_job()
        elif selected_action == "Delete Job":
            self.delete_job(selected_job)
        elif selected_action == "Create Generic Credentials":
            self.create_generic_credentials()
            
    # Function to refresh and populate jobs in the dropdown
    def refresh_jobs(self):
        try:
            # Assuming `self.jenkins_server` is a valid Jenkins connection
            jobs = self.jenkins_server.get_all_jobs()  # Fetch all jobs
            self.job_list_dropdown.clear()  # Clear existing items
            for job in jobs:
                job_name = job['name']
                self.job_list_dropdown.addItem(job_name)  # Add each job to dropdown
            self.log_message("Jobs refreshed successfully.")
        except Exception as e:
            self.log_message(f"Failed to refresh jobs: {e}")
            QMessageBox.critical(self, "Error", f"Failed to refresh jobs: {e}")





    def create_job(self):
        # Prompt user for the job name
        job_name, ok_pressed = QInputDialog.getText(self, "Job Name", "Enter the new job name:")

        if not ok_pressed or not job_name.strip():
            # User canceled or entered an empty name
            QMessageBox.warning(self, "Invalid Name", "Please provide a valid job name.")
            return

        # Prompt for job type: Pipeline or Multibranch Pipeline
        job_type, ok_type = QInputDialog.getItem(self, "Job Type", "Choose the job type:", ["Pipeline", "Multibranch Pipeline"], 0, False)

        if not ok_type:
            # User canceled or did not make a selection
            QMessageBox.warning(self, "Invalid Selection", "Please select a valid job type.")
            return

        # Get selected credentials ID from the dropdown
        selected_credentials_index = self.credential_list_dropdown.currentIndex()
        selected_credentials_id = self.credential_list_dropdown.itemData(selected_credentials_index)

        print(f"Selected credential ID: {selected_credentials_id}")  # Debugging log to verify the correct data is retrieved.

        # Check if the selected credentials ID is valid
        if selected_credentials_id is None or selected_credentials_id.strip() == "":
            QMessageBox.warning(self, "Invalid Credential Selection", "Please select a valid credential.")
            return

        # Handle different job types
        if job_type == "Pipeline":
            # Define the workspace directory for the new job
            workspace_dir = os.path.join("/tmp/jenkins_jobs", job_name)

            # Create workspace directory
            try:
                os.makedirs(workspace_dir, exist_ok=True)

                # Generate Jenkinsfile content
                jenkinsfile_content = f"""
    pipeline {{
        agent any
        environment {{
            IMAGE_NAME = 'node-app'
            IMAGE_TAG = 'node-1.0'
            DOCKER_HUB_REPO = 'webdev2123/node-app'  // Replace 'your-docker-username' with your Docker Hub username
        }}
        stages {{
            stage('Checkout Code') {{
                steps {{
                    git branch: 'master', url: 'https://gitlab.com/hwebdev/node-app.git'
                }}
            }}
            stage('Build Docker Image') {{
                steps {{
                    script {{
                        sh 'docker build -t $IMAGE_NAME:$IMAGE_TAG .'
                    }}
                }}
            }}
            stage('Push to Docker Hub') {{
                steps {{
                    script {{
                        withCredentials([usernamePassword(credentialsId: '{selected_credentials_id}', usernameVariable: 'DOCKER_HUB_USERNAME', passwordVariable: 'DOCKER_HUB_PASSWORD')]) {{
                            sh 'echo $DOCKER_HUB_PASSWORD | docker login -u $DOCKER_HUB_USERNAME --password-stdin'
                        }}
                        sh 'docker tag $IMAGE_NAME:$IMAGE_TAG $DOCKER_HUB_REPO:$IMAGE_TAG'
                        sh 'docker push $DOCKER_HUB_REPO:$IMAGE_TAG'
                    }}
                }}
            }}
        }}
    }}
    """

                # Write Jenkinsfile to workspace
                with open(os.path.join(workspace_dir, "Jenkinsfile"), "w") as jenkinsfile:
                    jenkinsfile.write(jenkinsfile_content.strip())

                # Create an empty script.groovy as a placeholder
                with open(os.path.join(workspace_dir, "script.groovy"), "w") as script_file:
                    script_file.write("// Placeholder script file for custom Groovy scripts\n")

            except Exception as e:
                self.log_message(f"Failed to create workspace directory or files for '{job_name}': {e}")
                QMessageBox.critical(self, "Error", f"Failed to create workspace directory or files for '{job_name}': {e}")
                return

            # Pipeline job configuration
            job_config_xml = f"""<?xml version='1.1' encoding='UTF-8'?>
            <flow-definition plugin="workflow-job@2.40">
                <actions/>
                <description>Pipeline for Node.js app with Docker build and push</description>
                <keepDependencies>false</keepDependencies>
                <properties/>
                <definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition" plugin="workflow-cps@2.92">
                    <script>{jenkinsfile_content.strip()}</script>
                    <sandbox>true</sandbox>
                </definition>
                <triggers/>
                <disabled>false</disabled>
            </flow-definition>"""

        elif job_type == "Multibranch Pipeline":
            # Basic example of a Multibranch Pipeline job configuration
            job_config_xml = f"""<org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject plugin="workflow-multibranch@2.26">
            <actions/>
            <description>Multibranch Pipeline for Node.js app</description>
            <properties/>
            <folderViews class="jenkins.branch.MultiBranchProjectViewHolder" plugin="branch-api@2.6.2">
                <owner class="org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject" reference="../../../.."/>
            </folderViews>
            <healthMetrics/>
            <icon class="jenkins.branch.MetadataActionFolderIcon" plugin="branch-api@2.6.2"/>
            <orphanedItemStrategy class="com.cloudbees.hudson.plugins.folder.computed.DefaultOrphanedItemStrategy" plugin="cloudbees-folder@6.15">
                <pruneDeadBranches>true</pruneDeadBranches>
                <daysToKeep>0</daysToKeep>
                <numToKeep>0</numToKeep>
            </orphanedItemStrategy>
            <triggers/>
            <sources class="jenkins.branch.MultiBranchProject$BranchSourceList" plugin="branch-api@2.6.2">
                <data>
                    <jenkins.branch.BranchSource>
                        <source class="jenkins.plugins.git.GitSCMSource" plugin="git@4.7.1">
                            <id>{job_name}-id</id>
                            <remote>https://gitlab.com/hwebdev/node-app.git</remote>
                            <credentialsId>{selected_credentials_id}</credentialsId>
                        </source>
                    </jenkins.branch.BranchSource>
                </data>
            </sources>
            <factory class="org.jenkinsci.plugins.workflow.multibranch.WorkflowBranchProjectFactory" plugin="workflow-multibranch@2.26">
                <owner class="org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject" reference="../../.."/>
            </factory>
        </org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject>"""

        try:
            # Assuming `self.jenkins_server` is a valid Jenkins connection
            if self.jenkins_server.job_exists(job_name):
                QMessageBox.warning(self, "Job Exists", f"A job named '{job_name}' already exists.")
                return

            # Create the new pipeline job with the provided name and XML configuration
            self.jenkins_server.create_job(job_name, job_config_xml)
            self.log_message(f"{job_type} job '{job_name}' created successfully.")
            QMessageBox.information(self, "Job Created", f"{job_type} job '{job_name}' has been created successfully.")

            # Refresh the job list after creating the job
            self.refresh_jobs()
        except Exception as e:
            self.log_message(f"Failed to create {job_type} job '{job_name}': {e}")
            QMessageBox.critical(self, "Error", f"Failed to create {job_type} job '{job_name}': {e}")






    

    def create_generic_credentials(self):
        # Prompt for platform name
        platform_name, ok_platform = QInputDialog.getText(self, "Platform Name", "Enter the platform for which you are creating credentials:")
        if not ok_platform or not platform_name.strip():
            QMessageBox.warning(self, "Invalid Input", "Please provide a valid platform name.")
            return

        # Prompt for username
        username, ok_username = QInputDialog.getText(self, f"{platform_name} Username", f"Enter your {platform_name} username:")
        if not ok_username or not username.strip():
            QMessageBox.warning(self, "Invalid Input", f"Please provide a valid {platform_name} username.")
            return

        # Prompt for password
        password, ok_password = QInputDialog.getText(self, f"{platform_name} Password", f"Enter your {platform_name} password:", QLineEdit.Password)
        if not ok_password or not password.strip():
            QMessageBox.warning(self, "Invalid Input", f"Please provide a valid {platform_name} password.")
            return

        # Prompt for credentials ID
        credentials_id, ok_id = QInputDialog.getText(self, "Credentials ID", "Enter a unique ID for these credentials:")
        if not ok_id or not credentials_id.strip():
            QMessageBox.warning(self, "Invalid Input", "Please provide a valid credentials ID.")
            return

        # Load Jenkins connection credentials
        jenkins_credentials = self.load_credentials()
        if not jenkins_credentials:
            QMessageBox.warning(self, "Missing Jenkins Credentials", "Please ensure that your Jenkins credentials are configured correctly.")
            return

        # Define the credentials XML payload for Jenkins REST API
        credentials_xml = f"""
            <com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
                <scope>GLOBAL</scope>
                <id>{credentials_id}</id>
                <description>{platform_name} Credentials</description>
                <username>{username}</username>
                <password>{password}</password>
            </com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
        """

        try:
            # Construct the Jenkins URL for creating credentials (assuming default path for credentials)
            url = f"{jenkins_credentials['url']}/credentials/store/system/domain/_/createCredentials"

            # Use HTTP Basic Authentication with Jenkins username and token
            auth = HTTPBasicAuth(jenkins_credentials['username'], jenkins_credentials['api_token'])

            # POST request to add credentials
            headers = {"Content-Type": "application/xml"}
            response = requests.post(url, auth=auth, headers=headers, data=credentials_xml)

            # Check if the request was successful
            if response.status_code in [200, 201]:
                self.log_message(f"Credentials for {platform_name} created/updated with ID: {credentials_id}.")
                QMessageBox.information(self, "Success", f"{platform_name} credentials created/updated with ID: {credentials_id}.")
            else:
                self.log_message(f"Failed to create {platform_name} credentials. Status Code: {response.status_code}, Response: {response.text}")
                QMessageBox.critical(self, "Error", f"Failed to create {platform_name} credentials. Status Code: {response.status_code}")

        except Exception as e:
            self.log_message(f"Failed to create {platform_name} credentials: {e}")
            QMessageBox.critical(self, "Error", f"Failed to create {platform_name} credentials: {e}")






    # Function to delete a selected job
    def delete_job(self, job_name):
        try:
            # Assuming `self.jenkins_server` is a valid Jenkins connection
            self.jenkins_server.delete_job(job_name)
            self.log_message(f"Deleted job: {job_name}")
            self.refresh_jobs()  # Refresh job list after deletion
        except Exception as e:
            self.log_message(f"Failed to delete job '{job_name}': {e}")
            QMessageBox.critical(self, "Error", f"Failed to delete job '{job_name}': {e}")

    ######################
    # Build Management
    ######################

    # Function for executing selected action
    def execute_build_action(self):
        selected_action = self.build_action_dropdown.currentText()
        if selected_action == "Trigger Build":
            self.trigger_build()
        elif selected_action == "Stop Build":
            self.stop_build()

    # Define your actions for Trigger and Stop build
    def trigger_build(self):
        # Get the selected job from the dropdown
        job_name = self.job_list_dropdown.currentText()
        
        if not job_name:
            QMessageBox.warning(self, "No Job Selected", "Please select a job to trigger.")
            return

        # Create and run the worker to handle the build process
        worker = BuildWorker(self.jenkins_server, job_name, self.log_message)
        self.threadpool.start(worker)


    def stop_build(self):
        # Logic for stopping a build
        print("Stopping build...")

    ######################
    # Scheduled Builds Management
    ######################

    def schedule_build(self):
        """Schedule a Jenkins build to run at a specified time."""
        job = self.schedule_job_option.currentText()
        scheduled_time = self.schedule_time_input.text().strip()

        if not job or not scheduled_time:
            self.log_message("Please select a job and provide a scheduled time.")
            QMessageBox.warning(self, "Warning", "Please select a job and provide a scheduled time.")
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

        # Add to scheduled builds list
        schedule_item = QListWidgetItem(f"Job: {job}, Time: {scheduled_time}")
        self.scheduled_builds_list.addItem(schedule_item)
        self.log_message(f"Scheduled build for job '{job}' at {scheduled_time}.")

        # Start a thread to wait until the scheduled time and execute the build
        thread = threading.Thread(target=self.run_scheduled_build, args=(job, scheduled_datetime), daemon=True)
        thread.start()

    def run_scheduled_build(self, job, scheduled_datetime):
        """Wait until the scheduled time and trigger the Jenkins build."""
        try:
            wait_seconds = (scheduled_datetime - datetime.now()).total_seconds()
            if wait_seconds > 0:
                self.log_message(f"Scheduled build for job '{job}' will run in {int(wait_seconds)} seconds.")
                time.sleep(wait_seconds)
            self.log_message(f"Executing scheduled build for job '{job}' now.")
            self.jenkins_server.build_job(job)
            self.log_message(f"Scheduled build for job '{job}' triggered successfully.")
            self.fetch_builds(job)
        except Exception as e:
            self.log_message(f"Error executing scheduled build for job '{job}': {e}")

    def cancel_schedule(self):
        """Cancel the selected scheduled build."""
        selected_items = self.scheduled_builds_list.selectedItems()
        if not selected_items:
            self.log_message("No scheduled build selected to cancel.")
            return
        selected_item = selected_items[0]
        index = self.scheduled_builds_list.row(selected_item)
        self.scheduled_builds_list.takeItem(index)
        self.log_message("Selected scheduled build has been canceled.")

    ######################
    # Rollback Capability
    ######################

    def rollback_state(self):
        """Rollback Jenkins job configuration to the previous version."""
        if not self.jenkins_server:
            self.log_message("Not connected to Jenkins server.")
            return
        selected_job = self.jobs_list.currentItem()
        if not selected_job:
            self.log_message("No job selected to rollback.")
            QMessageBox.warning(self, "Warning", "No job selected to rollback.")
            return
        job_name = selected_job.text()
        try:
            self.log_message(f"Rollback feature for job '{job_name}' is not implemented.")
            QMessageBox.information(self, "Info", f"Rollback feature for job '{job_name}' is not implemented.")
        except Exception as e:
            self.log_message(f"Error during rollback: {e}")
            QMessageBox.critical(self, "Error", f"Error during rollback: {e}")
            
    
    
    
    ## Tab 3 Configuration  
    def execute_tool_action(self):
        selected_tool = self.tools_dropdown.currentText()
        selected_action = self.action_dropdown.currentText()
        self.log_message(f"Executing {selected_action} for {selected_tool}...")

        try:
            if selected_action == "Install":
                self.install_tool(selected_tool)
            elif selected_action == "Uninstall":
                self.uninstall_tool(selected_tool)
        except Exception as e:
            self.log_message(f"Failed to execute {selected_action} for {selected_tool}: {e}")
            QMessageBox.critical(self, "Error", f"Failed to execute {selected_action} for {selected_tool}: {e}")

    def execute_plugin_action(self):
        selected_plugin = self.plugins_dropdown.currentText()
        selected_action = self.plugin_action_dropdown.currentText()
        self.log_message(f"Executing {selected_action} for plugin {selected_plugin}...")

        try:
            if selected_action == "Install":
                self.install_plugin(selected_plugin)
            elif selected_action == "Uninstall":
                self.uninstall_plugin(selected_plugin)
        except Exception as e:
            self.log_message(f"Failed to execute {selected_action} for plugin {selected_plugin}: {e}")
            QMessageBox.critical(self, "Error", f"Failed to execute {selected_action} for plugin {selected_plugin}: {e}")

            
    def install_tool(self, tool_name):
        """Install a tool on the Jenkins server by triggering a Jenkins job."""
        try:
            self.log_message(f"Installing {tool_name} via Jenkins API...")

            # Map tools to their Jenkins jobs for installation
            job_mapping = {
                "Jenkins": "Install-Jenkins-Job",
                "Git": "Install-Git-Job",
                "Docker": "Install-Docker-Job"
            }

            # Get the corresponding Jenkins job name
            job_name = job_mapping.get(tool_name)
            if not job_name:
                self.log_message(f"No installation job defined for {tool_name}.")
                QMessageBox.warning(self, "No Job", f"No installation job defined for {tool_name}.")
                return

            # Trigger the Jenkins job to install the tool
            self.jenkins_server.build_job(job_name)
            self.log_message(f"Job '{job_name}' started for installing {tool_name}.")
            QMessageBox.information(self, "Job Started", f"Installation job for {tool_name} started successfully.")

        except jenkins.JenkinsException as e:
            self.log_message(f"Failed to start installation job for {tool_name}: {e}")
            QMessageBox.critical(self, "Error", f"Failed to start installation job for {tool_name}: {e}")

    def uninstall_tool(self, tool_name):
        """Uninstall a tool from the Jenkins server by triggering a Jenkins job."""
        try:
            self.log_message(f"Uninstalling {tool_name} via Jenkins API...")

            # Map tools to their Jenkins jobs for uninstallation
            job_mapping = {
                "Jenkins": "Uninstall-Jenkins-Job",
                "Git": "Uninstall-Git-Job",
                "Docker": "Uninstall-Docker-Job"
            }

            # Get the corresponding Jenkins job name
            job_name = job_mapping.get(tool_name)
            if not job_name:
                self.log_message(f"No uninstallation job defined for {tool_name}.")
                QMessageBox.warning(self, "No Job", f"No uninstallation job defined for {tool_name}.")
                return

            # Trigger the Jenkins job to uninstall the tool
            self.jenkins_server.build_job(job_name)
            self.log_message(f"Job '{job_name}' started for uninstalling {tool_name}.")
            QMessageBox.information(self, "Job Started", f"Uninstallation job for {tool_name} started successfully.")

        except jenkins.JenkinsException as e:
            self.log_message(f"Failed to start uninstallation job for {tool_name}: {e}")
            QMessageBox.critical(self, "Error", f"Failed to start uninstallation job for {tool_name}: {e}")

    
    def install_plugin(self, plugin_name):
        """Install the specified plugin on the Jenkins server."""
        try:
            self.log_message(f"Attempting to install plugin '{plugin_name}' on Jenkins...")

            # Check if the plugin is already installed
            installed_plugins = self.jenkins_server.get_plugins()
            if plugin_name in installed_plugins:
                self.log_message(f"Plugin '{plugin_name}' is already installed.")
                QMessageBox.information(self, "Plugin Already Installed", f"Plugin '{plugin_name}' is already installed.")
                return

            # Install the plugin using the Jenkins API
            self.log_message(f"Installing plugin '{plugin_name}' on Jenkins...")
            self.jenkins_server.install_plugin(plugin_name)

            # Optionally restart Jenkins if needed
            restart_required = QMessageBox.question(
                self,
                "Restart Jenkins",
                f"Plugin '{plugin_name}' installation requires a Jenkins restart. Do you want to restart now?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )

            if restart_required == QMessageBox.Yes:
                self.log_message("Restarting Jenkins to activate the plugin...")
                self.jenkins_server.safe_restart()
                QMessageBox.information(self, "Jenkins Restart", "Jenkins is restarting to activate the plugin.")
            else:
                self.log_message("Jenkins restart deferred. Please restart Jenkins manually to activate the plugin.")

            QMessageBox.information(self, "Success", f"Plugin '{plugin_name}' installation initiated successfully!")

        except jenkins.JenkinsException as e:
            self.log_message(f"Failed to install plugin '{plugin_name}': {e}")
            QMessageBox.critical(self, "Error", f"Failed to install plugin '{plugin_name}': {e}")
        except Exception as e:
            self.log_message(f"Unexpected error occurred while installing plugin '{plugin_name}': {e}")
            QMessageBox.critical(self, "Error", f"Unexpected error occurred while installing plugin '{plugin_name}': {e}")

    def uninstall_plugin(self, plugin_name):
        """Uninstall the specified plugin from the Jenkins server."""
        try:
            self.log_message(f"Attempting to uninstall plugin '{plugin_name}' on Jenkins...")

            # Check if the plugin is installed
            installed_plugins = self.jenkins_server.get_plugins()
            if plugin_name not in installed_plugins:
                self.log_message(f"Plugin '{plugin_name}' is not installed.")
                QMessageBox.information(self, "Plugin Not Found", f"Plugin '{plugin_name}' is not installed.")
                return

            # Uninstall the plugin (by disabling and removing it)
            self.log_message(f"Disabling and uninstalling plugin '{plugin_name}'...")
            self.jenkins_server.disable_plugin(plugin_name)

            # Optionally restart Jenkins if needed
            restart_required = QMessageBox.question(
                self,
                "Restart Jenkins",
                f"Plugin '{plugin_name}' uninstallation requires a Jenkins restart. Do you want to restart now?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )

            if restart_required == QMessageBox.Yes:
                self.log_message("Restarting Jenkins to finalize plugin uninstallation...")
                self.jenkins_server.safe_restart()
                QMessageBox.information(self, "Jenkins Restart", "Jenkins is restarting to finalize the plugin removal.")
            else:
                self.log_message("Jenkins restart deferred. Please restart Jenkins manually to finalize the plugin removal.")

            QMessageBox.information(self, "Success", f"Plugin '{plugin_name}' uninstallation initiated successfully!")

        except jenkins.JenkinsException as e:
            self.log_message(f"Failed to uninstall plugin '{plugin_name}': {e}")
            QMessageBox.critical(self, "Error", f"Failed to uninstall plugin '{plugin_name}': {e}")
        except Exception as e:
            self.log_message(f"Unexpected error occurred while uninstalling plugin '{plugin_name}': {e}")
            QMessageBox.critical(self, "Error", f"Unexpected error occurred while uninstalling plugin '{plugin_name}': {e}")


    


    ######################
    # Version Control Integration
    ######################

    # Function for executing selected git action
    def execute_git_action(self):
        selected_action = self.git_action_dropdown.currentText()
        if selected_action == "Clone Repository":
            self.clone_repository()
        elif selected_action == "Commit Changes":
            self.commit_changes()
        elif selected_action == "Push Changes":
            self.push_changes()

    # Define your actions for Git operations
    def clone_repository(self):
        repo_path = self.repo_path_input.text()
        # Logic for cloning a repository
        print(f"Cloning repository at: {repo_path}")

    def commit_changes(self):
        repo_path = self.repo_path_input.text()
        # Logic for committing changes
        print(f"Committing changes in repository at: {repo_path}")

    def push_changes(self):
        repo_path = self.repo_path_input.text()
        # Logic for pushing changes
        print(f"Pushing changes to repository at: {repo_path}")

        ######################
        # Helper Methods
        ######################

    def log_message(self, message):
            """Log messages to the output area or console."""
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if hasattr(self, 'output_area'):  # Check if output area is available
                self.output_area.append(f"[{timestamp}] {message}")
                self.output_area.moveCursor(QTextCursor.End)
            else:
                print(f"[{timestamp}] {message}")
