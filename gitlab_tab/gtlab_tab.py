import asyncio
import base64
import datetime
import logging
import math
import os
import queue
import re
import shutil
import time
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime
from functools import wraps
from urllib.parse import parse_qs, urlparse

import gitlab
import requests
from PyQt5.QtCore import (Q_ARG, QDate, QDir, QMetaObject, QObject, Qt,
                          QThread, QTimer, QUrl, pyqtSignal, pyqtSlot)
from PyQt5.QtGui import QIcon
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtWidgets import (QAction, QButtonGroup, QCheckBox, QComboBox,
                             QDateEdit, QDialog, QFileDialog, QFormLayout,
                             QGroupBox, QHBoxLayout, QInputDialog, QLabel,
                             QLineEdit, QListWidget, QListWidgetItem, QMenu,
                             QMessageBox, QPushButton, QRadioButton, QSplitter,
                             QTabWidget, QTextEdit, QTreeWidget,
                             QTreeWidgetItem, QVBoxLayout, QWidget)

from gitlab_tab.gitlab_workflow_configurator import GitLabWorkflowConfigurator

# Setting up structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.FileHandler("gitlab_tool.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Retry decorator with exponential backoff
def retry(exceptions, tries=4, delay=3, backoff=2, logger=None):
    def decorator_retry(func):
        @wraps(func)
        def wrapper_retry(*args, **kwargs):
            _tries, _delay = tries, delay
            while _tries > 1:
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    msg = f"{e}, Retrying in {_delay} seconds..."
                    if logger:
                        logger.warning(msg)
                    else:
                        print(msg)
                    time.sleep(_delay)
                    _tries -= 1
                    _delay *= backoff
            return func(*args, **kwargs)
        return wrapper_retry
    return decorator_retry



class GitLabUploaderThread(QThread):
    # Signal to send messages back to the main thread
    update_signal = pyqtSignal(str)

    def __init__(self, gitlab_url, gitlab_token, base_dir, selected_project_name):
        super().__init__()
        self.gitlab_url = gitlab_url
        self.gitlab_token = gitlab_token
        self.base_dir = base_dir
        self.selected_project_name = selected_project_name

    def run(self):
        try:
            # Initialize a new GitLab client with timeout
            self.update_signal.emit(f"Creating GitLab client for {self.gitlab_url}...")
            gitlab_client = gitlab.Gitlab(self.gitlab_url, private_token=self.gitlab_token, timeout=60)
            self.update_signal.emit("Authenticating with GitLab...")
            gitlab_client.auth()
            user = gitlab_client.user
            self.update_signal.emit(f"Authenticated as GitLab user: {user.username}")

            # Define the project path
            project_path = os.path.join(self.base_dir, self.selected_project_name)
            self.update_signal.emit(f"Project path set to: {project_path}")

            if not os.path.exists(project_path):
                self.update_signal.emit(f"Project directory '{project_path}' does not exist.")
                return

            # Use the project name as the GitLab project name
            gitlab_project_name = self.selected_project_name.strip()
            self.update_signal.emit(f"Attempting to create a GitLab project named '{gitlab_project_name}'...")

            # Attempt to create the GitLab project
            try:
                gitlab_project = gitlab_client.projects.create({"name": gitlab_project_name})
                self.update_signal.emit(f"Created new GitLab project '{gitlab_project_name}' successfully.")
            except gitlab.exceptions.GitlabCreateError as e:
                if 'has already been taken' in str(e):
                    # Project already exists, fetch it
                    self.update_signal.emit(f"Project '{gitlab_project_name}' already exists. Fetching existing project...")
                    gitlab_project = gitlab_client.projects.get(f"{gitlab_client.user.username}/{gitlab_project_name}")
                    self.update_signal.emit(f"Fetched existing GitLab project: '{gitlab_project.name}' with ID {gitlab_project.id}")
                else:
                    self.update_signal.emit(f"Error creating GitLab project: {e}")
                    return

            # Ensure branch exists
            branch_name = 'main'
            self.update_signal.emit(f"Ensuring branch '{branch_name}' exists...")
            try:
                gitlab_project.branches.get(branch_name)
                self.update_signal.emit(f"Branch '{branch_name}' already exists.")
            except gitlab.exceptions.GitlabGetError:
                try:
                    gitlab_project.branches.create({'branch': branch_name, 'ref': 'master'})
                    self.update_signal.emit(f"Branch '{branch_name}' created successfully.")
                except gitlab.exceptions.GitlabCreateError as e:
                    if 'already exists' in str(e):
                        self.update_signal.emit(f"Branch '{branch_name}' already exists.")
                    else:
                        self.update_signal.emit(f"Error creating branch '{branch_name}': {e}")
                        return

            # Traverse and upload all files in the project directory
            self.update_signal.emit(f"Starting file upload for project '{self.selected_project_name}'...")
            for root, _, files in os.walk(project_path):
                for file in files:
                    full_path = os.path.join(root, file)
                    repo_path = os.path.relpath(full_path, project_path)  # Path relative to the project folder
                    self.upload_file_with_chunks(full_path, repo_path, branch_name, gitlab_project)

            self.update_signal.emit(f"Successfully uploaded '{self.selected_project_name}' to GitLab project '{gitlab_project_name}'.")
        except Exception as e:
            self.update_signal.emit(f"Error uploading project to GitLab: {e}")

    def upload_file_with_chunks(self, full_path, repo_path, branch_name, gitlab_project, chunk_size=1024 * 1024):
        """Upload a file in chunks to GitLab for a specific project."""
        try:
            file_size = os.path.getsize(full_path)
            total_chunks = math.ceil(file_size / chunk_size)
            self.update_signal.emit(f"Processing file '{repo_path}' of size {file_size} bytes in {total_chunks} chunks.")

            with open(full_path, 'rb') as file_content:
                if file_size > chunk_size:
                    self.update_signal.emit(f"Uploading '{repo_path}' in {total_chunks} chunks...")

                content_parts = []
                for chunk_index in range(total_chunks):
                    chunk = file_content.read(chunk_size)
                    binary_content = base64.b64encode(chunk).decode('utf-8')
                    content_parts.append(binary_content)
                    self.update_signal.emit(f"Uploaded chunk {chunk_index + 1}/{total_chunks} for '{repo_path}'")

                combined_content = ''.join(content_parts)

                try:
                    # Check if file already exists in the GitLab project
                    file_item = gitlab_project.files.get(file_path=repo_path, ref=branch_name)
                    file_item.content = combined_content
                    file_item.encoding = 'base64'
                    file_item.save(branch=branch_name, commit_message=f"Updating {repo_path}")
                    self.update_signal.emit(f"Updated '{repo_path}' in the GitLab project.")
                except gitlab.exceptions.GitlabGetError:
                    # If file doesn't exist, create a new one
                    gitlab_project.files.create({
                        'file_path': repo_path,
                        'branch': branch_name,
                        'content': combined_content,
                        'encoding': 'base64',
                        'commit_message': f"Uploading {repo_path}"
                    })
                    self.update_signal.emit(f"Uploaded '{repo_path}' to the GitLab project.")
        except Exception as e:
            self.update_signal.emit(f"Error uploading file '{repo_path}': {e}")




class GitLabTab(QWidget):
    # Signals for inter-thread communication
    notify_signal = pyqtSignal(str, str)  # title, message
    select_pipeline_signal = pyqtSignal(list)
    pipeline_selected_signal = pyqtSignal(int)

    

    def __init__(self, auth_manager, main_tab_widget):
        super().__init__()
        self.auth_manager = auth_manager
        self.main_tab_widget = main_tab_widget
        self.gitlab_client = None
        self.project = None
        self.script_directory = os.path.dirname(os.path.realpath(__file__))
        self.hardcoded_gitlab_yml_path = os.path.join(self.script_directory, ".gitlab-ci.yml")
        self.executor = ThreadPoolExecutor(max_workers=16)  # Increased for scalability
        self.loop = asyncio.new_event_loop()

        # Caching mechanism
        self.cache = {}

        # Set up the tab widget for multiple tabs
        self.tab_widget = QTabWidget()
        
        # Set base directory for all projects
        self.base_dir = os.path.join(os.path.dirname(self.script_directory), "gitlab_project")

        # Initialize UI
        self.initUI()

        # Connect notification signal to handler
        #self.notify_signal.connect(self.show_notification)

    def initUI(self):
        """Initialize the UI with all features."""
        main_layout = QVBoxLayout()
        
        

        # Create main management widget
        gitlab_management_widget = QWidget()
        gitlab_management_layout = QHBoxLayout()

        # Left Column for Controls
        left_column = QVBoxLayout()
        
        # Add the Back to System Button
        back_button = QPushButton("Back to System")
        back_button.clicked.connect(self.go_back_to_system)
        back_button.setFixedSize(120, 30)
        left_column.addWidget(back_button)

        # Authentication Options #############################
        # Authentication Options #############################
        self.auth_option_group = QButtonGroup(self)
        self.system_token_radio = QRadioButton("Access Key", self)
        self.manual_login_radio = QRadioButton("Manual Login", self)
        self.system_token_radio.setChecked(True)  # Default

        self.auth_option_group.addButton(self.system_token_radio)
        self.auth_option_group.addButton(self.manual_login_radio)

        self.system_token_radio.toggled.connect(self.toggle_auth_method)
        self.manual_login_radio.toggled.connect(self.toggle_auth_method)

        # Group the radio buttons horizontally
        auth_layout = QHBoxLayout()
        auth_layout.addWidget(self.system_token_radio)
        auth_layout.addWidget(self.manual_login_radio)
        left_column.addLayout(auth_layout)  # Add the horizontal layout to the left column

        # Manual Login Form
        self.manual_login_form = QWidget()
        manual_form_layout = QFormLayout()
        self.gitlab_url_input = QLineEdit()
        manual_form_layout.addRow("GitLab URL:", self.gitlab_url_input)
        self.gitlab_token_input = QLineEdit()
        self.gitlab_token_input.setEchoMode(QLineEdit.Password)
        manual_form_layout.addRow("Private Token:", self.gitlab_token_input)
        self.manual_login_form.setLayout(manual_form_layout)
        self.manual_login_form.setVisible(False)
        left_column.addWidget(self.manual_login_form)

        # Connect to GitLab Button
        self.connect_button = QPushButton("Connect to GitLab")
        self.connect_button.setFixedWidth(150)  # Set a smaller fixed width
        self.connect_button.clicked.connect(self.connect_to_gitlab)
        left_column.addWidget(self.connect_button)




        ###########################################################

        ###########################################################

        # Project Management Group
        project_management_group = QGroupBox("Project Management")
        project_management_layout = QFormLayout()  # You can use QVBoxLayout as well if preferred



        # Project Dropdown
        self.project_dropdown = QComboBox(self)
        self.project_dropdown.addItem("Select a project")
        project_management_layout.addRow("Project:", self.project_dropdown)

        # Project Action on_project_selected
        self.project_action_dropdown = QComboBox(self)
        self.project_action_dropdown.addItems([
            "Create New Project",
            "Delete Project",
            "Add Folder/File to Project",
            "Push Project to GitLab",

        ])
        project_management_layout.addRow("Action:", self.project_action_dropdown)

        # Execute Project Action Button
        self.project_action_button = QPushButton("Execute Project Action")
        self.project_action_button.clicked.connect(self.execute_project_action)
        project_management_layout.addWidget(self.project_action_button)

        # Set layout for the group box
        project_management_group.setLayout(project_management_layout)

        # Add the project management group box to the left column
        left_column.addWidget(project_management_group)


        
        ###################################################################
        # Pipeline Management Group Box
        # Pipeline Management Group Box
        pipeline_management_group = QGroupBox("Pipeline Management")
        pipeline_layout = QFormLayout()

        # GitLab Project Dropdown for Pipeline Actions
        self.pipeline_project_dropdown = QComboBox(self)
        self.pipeline_project_dropdown.addItem("Select a GitLab Project")
        self.pipeline_project_dropdown.currentIndexChanged.connect(self.on_gitlab_project_selected)  # Connect if any specific action needed
        pipeline_layout.addRow("GitLab Project:", self.pipeline_project_dropdown)

        # Pipeline Action Dropdown
        self.pipeline_action_dropdown = QComboBox(self)
        self.pipeline_action_dropdown.addItems([
            "Check Jobs",
            "Check Jobs Logs",
            "Trigger Pipeline",
            "View Pipeline Logs",
            "Fetch Repository Insights",
            "Toggle Project Visibility",
            "Delete GitLab Project",
            "Schedule Pipeline",
            "Project Branch Protection",

 
        ])
        pipeline_layout.addRow("Pipeline Actions:", self.pipeline_action_dropdown)
        self.select_pipeline_signal.connect(self.show_pipeline_selection_dialog)
        self.pipeline_selected_signal.connect(self.fetch_and_display_logs)

        # Execute Pipeline Action Button
        self.pipeline_action_button = QPushButton("Execute Pipeline Action")
        self.pipeline_action_button.clicked.connect(self.execute_pipeline_action)
        pipeline_layout.addRow(self.pipeline_action_button)

        # Set layout for pipeline management group
        pipeline_management_group.setLayout(pipeline_layout)
        left_column.addWidget(pipeline_management_group)


        
        ####################################################################
        # Other Management Group Box
        other_management_group = QGroupBox("Other Management")
        other_management_layout = QFormLayout()

        # Dropdown for Other Management Actions
        self.other_management_dropdown = QComboBox(self)
        self.other_management_dropdown.addItems([
            "Configure GitLab Runner",
            "Manage Webhooks",
            "Manage Pipeline Variables",
            "Configure Access Tokens",
        ])
        other_management_layout.addRow("Select Action:", self.other_management_dropdown)

        # Execute Button for Selected Action
        self.other_management_execute_button = QPushButton("Execute")
        self.other_management_execute_button.clicked.connect(self.execute_other_management_action)
        other_management_layout.addRow(self.other_management_execute_button)

        # Set layout for Other Management group
        other_management_group.setLayout(other_management_layout)
        left_column.addWidget(other_management_group)


        
        
        #################################################

        # Theming and Customization
        theme_layout = QHBoxLayout()
        self.theme_label = QLabel("Theme:")
        self.theme_dropdown = QComboBox()
        self.theme_dropdown.addItems(["Dark", "Light", "Solarized", "High Contrast"])
        self.theme_dropdown.currentIndexChanged.connect(self.change_theme)
        theme_layout.addWidget(self.theme_label)
        theme_layout.addWidget(self.theme_dropdown)
        left_column.addLayout(theme_layout)

        # Add left column to management layout
        gitlab_management_layout.addLayout(left_column)
        
        

        # Right Column for Output and Insights
        right_column = QVBoxLayout()

        # Output Text Area
        self.pipelines_output = QTextEdit()
        self.pipelines_output.setReadOnly(True)
        right_column.addWidget(self.pipelines_output)


        # Add right column to management layout
        gitlab_management_layout.addLayout(right_column)

        gitlab_management_widget.setLayout(gitlab_management_layout)

        # Workflow Configurator Tab

        # Add tabs to QTabWidget
        self.tab_widget.addTab(gitlab_management_widget, "GitLab Management")

        # Set main layout
        main_layout.addWidget(self.tab_widget)
        self.setLayout(main_layout)

        # Initialize Logging and Notifications
        self.setup_logging_and_notifications()
        
        self.load_projects_into_dropdown()
        
        self.populate_gitlab_project_dropdown()
        
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


    def setup_logging_and_notifications(self):
        """Set up logging handlers and user notifications."""
        # Logging to file is already set up via basicConfig
        # Additional logging configurations can be added here

        # Desktop Notifications
        #self.notify_signal.connect(self.show_notification)

    def show_notification(self, title, message):
        """Display a desktop notification."""
        QMessageBox.information(self, title, message)

    def toggle_auth_method(self):
        """Toggle visibility of authentication methods."""
        if self.manual_login_radio.isChecked():
            self.manual_login_form.setVisible(True)

        elif self.system_token_radio.isChecked():
            self.manual_login_form.setVisible(False)
        else:
            self.manual_login_form.setVisible(False)





    def exchange_code_for_token(self, code):
        """Exchange authorization code for access token."""
        client_id = os.getenv('GITLAB_OAUTH_CLIENT_ID')
        client_secret = os.getenv('GITLAB_OAUTH_CLIENT_SECRET')
        redirect_uri = 'http://localhost:8080/callback'

        token_url = 'https://gitlab.com/oauth/token'
        data = {
            'client_id': client_id,
            'client_secret': client_secret,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': redirect_uri
        }

        try:
            response = requests.post(token_url, data=data)
            response.raise_for_status()
            access_token = response.json().get('access_token')
            self.gitlab_client = gitlab.Gitlab('https://gitlab.com', private_token=access_token)
            self.gitlab_client.auth()
            self.update_output("Successfully authenticated via OAuth.")
            self.notify_signal.emit("Authentication", "Successfully authenticated via OAuth.")
            self.populate_gitlab_project_dropdown() 
        except requests.exceptions.RequestException as e:
            logger.error(f"OAuth authentication failed: {e}")
            self.update_output(f"OAuth authentication failed: {str(e)}")
            self.notify_signal.emit("Authentication Error", f"OAuth authentication failed: {str(e)}")

    def connect_to_gitlab(self):
        """Connect to GitLab based on selected authentication method."""
        def on_gitlab_connected(future: Future):
            """Callback when GitLab connection is successful."""
            try:
                gitlab_client = future.result()
                self.gitlab_client = gitlab_client
                self.update_output("Successfully connected to GitLab.")
                self.notify_signal.emit("Connection", "Successfully connected to GitLab.")
                self.populate_gitlab_project_dropdown()
            except Exception as e:
                logger.error(f"Error connecting to GitLab: {e}")
                self.update_output(f"Error connecting to GitLab: {str(e)}")
                self.notify_signal.emit("Connection Error", f"Error connecting to GitLab: {str(e)}")

        #self.update_output("Attempting to connect to GitLab...")

        if self.system_token_radio.isChecked():
            gitlab_token = self.get_system_token()
            if not gitlab_token:
                self.update_output("Error: Could not retrieve system token.")
                self.notify_signal.emit("Authentication Error", "Could not retrieve system token.")
                return
            gitlab_url = "https://gitlab.com"
        elif self.manual_login_radio.isChecked():
            gitlab_url = self.gitlab_url_input.text().strip()
            gitlab_token = self.gitlab_token_input.text().strip()
            if not gitlab_token or not gitlab_url:
                self.update_output("Please enter a valid GitLab URL and private token.")
                self.notify_signal.emit("Input Error", "Please enter a valid GitLab URL and private token.")
                return
        else:
            self.update_output("OAuth authentication selected. Please use the OAuth button.")
            self.notify_signal.emit("Authentication", "OAuth authentication selected. Please use the OAuth button.")
            return

        # Submit connection task with retry
        future: Future = self.executor.submit(self.connect_to_gitlab_task, gitlab_url, gitlab_token)
        future.add_done_callback(on_gitlab_connected)
        
    def populate_gitlab_project_dropdown(self):
        """Populate the GitLab dropdown with user's GitLab projects."""
        self.pipeline_project_dropdown.clear()
        self.pipeline_project_dropdown.addItem("Select a GitLab Project")

        def task():
            try:
                self.update_output("Fetching GitLab projects...")
                projects = self.gitlab_client.projects.list(membership=True, all=True, per_page=100, as_list=True)

                for project in projects:
                    self.pipeline_project_dropdown.addItem(project.name, project.id)

                self.update_output(f"Loaded {len(projects)} GitLab project(s) into the GitLab dropdown.")
            except gitlab.exceptions.GitlabGetError as e:
                logger.error(f"GitLab API error: {e}")
                self.update_output(f"GitLab API error: {str(e)}")
            except Exception as e:
                logger.error(f"Error fetching GitLab projects: {e}")
                self.update_output(f"Error fetching GitLab projects: {str(e)}")

        self.executor.submit(task)

    @retry(gitlab.exceptions.GitlabAuthenticationError, tries=4, delay=3, backoff=2, logger=logger)
    def connect_to_gitlab_task(self, gitlab_url, gitlab_token):
        """Task to connect to GitLab with retry mechanism."""
        #self.update_output(f"Creating GitLab client for {gitlab_url}...")
        gitlab_client = gitlab.Gitlab(gitlab_url, private_token=gitlab_token)
        #self.update_output("Authenticating with GitLab...")
        gitlab_client.auth()
        #self.update_output("Authentication successful.")
        return gitlab_client

    def get_system_token(self):
        """Retrieve system access token from environment or file."""
        gitlab_token = os.getenv('GITLAB_PRIVATE_TOKEN')
        if not gitlab_token:
            token_file_path = os.path.expanduser('~/.gitlab_token')
            if os.path.exists(token_file_path):
                with open(token_file_path, 'r') as token_file:
                    gitlab_token = token_file.read().strip()
        if not gitlab_token:
            logger.warning("No GitLab token found in environment or file.")
            self.update_output("No GitLab token found in environment variables or token file.")
        return gitlab_token

    def update_output(self, message):
        """Append messages to the output QTextEdit in the main thread."""
        logger.info(message)
        QMetaObject.invokeMethod(self.pipelines_output, "append",
                                 Qt.QueuedConnection, Q_ARG(str, message))



    def refresh_dropdown(self):
        """Refresh the project dropdown."""

        self.populate_gitlab_project_dropdown() 

    def on_gitlab_project_selected(self):
        """Handle project selection."""
        project_id = self.pipeline_project_dropdown.currentData()
        if project_id:
            try:
                self.project = self.gitlab_client.projects.get(project_id)
                self.update_output(f"Project loaded: {self.project.name}")
                #self.notify_signal.emit("Project Selected", f"Project loaded: {self.project.name}")
                #self.list_pipelines()
                #self.fetch_repository_insights()
            except Exception as e:
                logger.error(f"Error loading project: {e}")
                self.update_output(f"Error loading project: {str(e)}")
                #self.notify_signal.emit("Error", f"Error loading project: {str(e)}")
        else:
            self.update_output("")
            #self.notify_signal.emit("Selection", "No project selected.")

    


    ############################################################################
    
    def load_projects_into_dropdown(self):
        """Loads all projects from the base_dir into the project dropdown."""
        # Clear the current items in the dropdown (except the placeholder)
        self.project_dropdown.clear()
        self.project_dropdown.addItem("Select a project")

        # Check if base_dir exists
        if os.path.exists(self.base_dir):
            # Get a list of all directories in base_dir
            projects = [f.name for f in os.scandir(self.base_dir) if f.is_dir()]

            # Populate the dropdown with project names
            if projects:
                self.project_dropdown.addItems(projects)
                self.update_output(f"Loaded {len(projects)} project(s) into the system project dropdown.")
            else:
                self.update_output("No system projects found in the base directory.")
        else:
            self.update_output(f"Base directory '{self.base_dir}' does not exist.")


    
    def execute_project_action(self):
        """Execute selected project action."""
        selected_function = self.project_action_dropdown.currentText()
        logger.info(f"Selected project function: {selected_function}")
        self.update_output(f"Selected function: {selected_function}")

        # Actions mapping to their corresponding functions
        actions = {
            "Create New Project": self.prompt_project_creation,  
            "Delete Project": self.delete_project,
            "Add Folder/File to Project": self.add_folder_or_file_to_project,
            "Push Project to GitLab": self.upload_project_to_gitlab, 
        }

        if selected_function in ["Delete Project", "Add Folder/File to Project", "Push Project to GitLab"]:
            action = actions[selected_function]
            action()
        else:
            # Get the action based on the selected function
            action = actions.get(selected_function, None)

            if action:
                # Execute the action
                if selected_function == "Create New Project":
                    action()  # Call directly as it contains user input popups
                else:
                    action()  # Use executor for threaded execution
            else:
                self.update_output(f"Invalid function selected: {selected_function}")
                logger.warning(f"Invalid function selected: {selected_function}")

                
    def add_folder_or_file_to_project(self):
        """Add a folder or file to the selected project."""
        selected_project = self.project_dropdown.currentText()

        # Ensure a valid project is selected
        if selected_project == "Select a project":
            self.update_output("No valid project selected to add files or folders.")
            return

        # Determine the project directory path
        project_path = os.path.join(self.base_dir, selected_project)

        # Check if the project path exists
        if not os.path.exists(project_path):
            self.update_output(f"Project directory '{project_path}' does not exist.")
            return

        # Ask user to choose either a file or a folder to add
        file_or_folder, ok = QInputDialog.getItem(
            self, "Select Option", "What do you want to add?", ["File", "Folder"], 0, False
        )

        if not ok:
            self.update_output("Adding file/folder canceled.")
            return

        # Handle adding a file
        if file_or_folder == "File":
            file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Add")
            if not file_path:
                self.update_output("No file selected.")
                return
            
            # Copy file to project directory
            try:
                shutil.copy(file_path, project_path)
                self.update_output(f"File '{os.path.basename(file_path)}' added to project '{selected_project}'.")
            except Exception as e:
                self.update_output(f"Error adding file: {str(e)}")

        # Handle adding a folder
        elif file_or_folder == "Folder":
            folder_path = QFileDialog.getExistingDirectory(self, "Select Folder to Add")
            if not folder_path:
                self.update_output("No folder selected.")
                return
            
            # Copy folder contents to project directory
            try:
                folder_name = os.path.basename(folder_path)
                dest_folder = os.path.join(project_path, folder_name)
                shutil.copytree(folder_path, dest_folder)
                self.update_output(f"Folder '{folder_name}' added to project '{selected_project}'.")
            except Exception as e:
                self.update_output(f"Error adding folder: {str(e)}")



    def prompt_project_creation(self):
        """Prompt user to input project name and select type for creation."""
        # Popup for project name
        project_name, ok_name = QInputDialog.getText(self, "Create New Project", "Enter project name:")
        
        if ok_name and project_name.strip():
            # Get project type
            project_type, ok_type = QInputDialog.getItem(
                self,
                "Select Project Type",
                "Project Type:",
                ["Node", "Python", "Microservice"],
                0,
                False
            )
            if ok_type:
                # Call the create project function with the provided name and type
                self.executor.submit(self.create_new_project, project_name.strip(), project_type)
            else:
                self.update_output("Project creation canceled or type not selected.")
        else:
            self.update_output("Project creation canceled or name is invalid.")
    

    def create_new_project(self, project_name, project_type):
        """Creates a new project based on type and sets up CI files."""
        # Set the project directory within base_dir
        project_dir = os.path.join(self.base_dir, project_name)

        # Create base project directory if it does not exist
        if not os.path.exists(self.base_dir):
            os.makedirs(self.base_dir)

        # Create project-specific directory
        if not os.path.exists(project_dir):
            os.makedirs(project_dir)
        else:
            self.update_output("Project folder already exists.")
            return
        
        # Define file mappings based on project type
        file_mappings = {
            "Node": {
                "ci_template": "node-ci_config.yml",
                "gitlab_template": "node-gitlab-ci.yml"
            },
            "Python": {
                "ci_template": "python-ci_config.yml",
                "gitlab_template": "python_gitlab-ci.yml"
            },
            "Microservice": {
                "ci_template": "micro-service-ci_config.yml",
                "gitlab_template": "micro-service-ci.yml"
            }
        }

        # Get the correct templates based on project type
        if project_type in file_mappings:
            ci_template = file_mappings[project_type]["ci_template"]
            gitlab_template = file_mappings[project_type]["gitlab_template"]
            
            # Define source paths for the templates
            ci_template_src = os.path.join(self.script_directory, ci_template)
            gitlab_template_src = os.path.join(self.script_directory, gitlab_template)
            
            # Define destination paths for the renamed files
            ci_dest = os.path.join(project_dir, "ci_config.yml")
            gitlab_dest = os.path.join(project_dir, ".gitlab-ci.yml")
            
            # Copy and rename the templates to the project directory
            try:
                shutil.copy(ci_template_src, ci_dest)
                shutil.copy(gitlab_template_src, gitlab_dest)
                self.update_output(f"{project_type} project '{project_name}' created successfully with CI files.")
                
                # Optionally, refresh the project dropdown or perform additional steps
            except Exception as e:
                self.update_output(f"An error occurred during project creation: {str(e)}")
        else:
            self.update_output("Invalid project type selected.")



    def delete_project(self):
        """Deletes the selected project from the project dropdown."""
        selected_project = self.project_dropdown.currentText()

        # Ensure a valid project is selected
        if selected_project == "Select a project":
            self.update_output("No valid project selected for deletion.")
            return

        # Confirm deletion
        confirm_msg = f"Are you sure you want to delete the project '{selected_project}'?"
        reply = QMessageBox.question(self, 'Delete Project', confirm_msg, 
                                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            # Determine the full path to the project directory
            project_path = os.path.join(self.base_dir, selected_project)

            # Check if the path exists and is a directory
            if os.path.exists(project_path) and os.path.isdir(project_path):
                try:
                    # Delete the directory and all its contents
                    import shutil
                    shutil.rmtree(project_path)

                    self.update_output(f"Project '{selected_project}' has been deleted.")

                    # Reload the dropdown to reflect the deletion
                    self.load_projects_into_dropdown()
                except Exception as e:
                    self.update_output(f"Failed to delete project '{selected_project}': {e}")
            else:
                self.update_output(f"Project '{selected_project}' not found.")
        else:
            self.update_output("Project deletion canceled.")
            
    
    def upload_project_to_gitlab(self):
        """Upload the selected local project to GitLab."""
        if not self.gitlab_client:
            self.update_output("Not connected to GitLab. Please connect using an access key first.")
            return

        selected_project = self.project_dropdown.currentText()

        if selected_project == "Select a project":
            self.update_output("No valid project selected to upload to GitLab.")
            return

        # Initialize the uploader thread with separate GitLab client parameters
        try:
            gitlab_url = self.gitlab_client.url  # Ensure this attribute exists
            gitlab_token = self.gitlab_client.private_token  # Ensure this attribute exists
        except AttributeError:
            self.update_output("Error: GitLab client does not have 'url' or 'private_token' attributes.")
            logger.error("GitLab client missing 'url' or 'private_token'.")
            return

        # Initialize the uploader thread with separate GitLab client parameters
        self.uploader_thread = GitLabUploaderThread(gitlab_url, gitlab_token, self.base_dir, selected_project)

        # Connect the update_signal to the update_output function
        self.uploader_thread.update_signal.connect(self.update_output)

        # Start the thread
        self.uploader_thread.start()





############################



############################################################
    ## Pipeline Actions Management

    def execute_pipeline_action(self):
        """Execute selected pipeline action."""
        selected_function = self.pipeline_action_dropdown.currentText()
        logger.info(f"Selected pipeline function: {selected_function}")
        self.update_output(f"Selected pipeline action: {selected_function}")

        actions = {
            "Check Jobs": self.check_project_jobs,
            "Check Jobs Logs": self.check_pipeline_logs,
            "Trigger Pipeline": self.trigger_pipeline,
            "View Pipeline Logs": self.view_pipeline_logs,
            "Fetch Repository Insights": self.fetch_repository_insights, 
            "Toggle Project Visibility": self.toggle_project_visibility,
            "Delete GitLab Project": self.delete_gitlab_project,
            "Schedule Pipeline": self.schedule_pipeline_action,
            "Project Branch Protection": self.set_branch_protection

        }

        action = actions.get(selected_function, None)
        if action:
            action() 
        else:
            self.update_output(f"Invalid pipeline action selected: {selected_function}")
            logger.warning(f"Invalid pipeline action selected: {selected_function}")
            
    def check_project_jobs(self):
        """Check and display jobs for the latest pipeline."""
        if not self.project:
            self.update_output("Error: No project loaded. Please select a project first.")
            return

        def task():
            try:
                self.update_output(f"Fetching pipelines for project '{self.project.name}'...")
                # Fetch pipelines sorted by ID in descending order to get the latest
                pipelines = self.project.pipelines.list(order_by='id', sort='desc', per_page=1)

                if not pipelines:
                    self.update_output(f"No pipelines found for project '{self.project.name}'.")
                    return

                latest_pipeline = pipelines[0]
                self.update_output(f"Latest Pipeline ID: {latest_pipeline.id}, Status: {latest_pipeline.status}")

                self.update_output(f"Fetching jobs for Pipeline ID {latest_pipeline.id}...")
                jobs = latest_pipeline.jobs.list()

                if not jobs:
                    self.update_output(f"No jobs found for pipeline ID {latest_pipeline.id}.")
                    return

                for job in jobs:
                    job_info = (
                        f"Job Name: {job.name}\n"
                        f"Job ID: {job.id}\n"
                        f"Pipeline ID: {job.pipeline['id']}\n"
                        f"Stage: {job.stage}\n"
                        f"Status: {job.status}\n"
                        f"Duration: {job.duration if job.duration else 'N/A'} seconds\n"
                        f"Web URL: {job.web_url}\n"
                        "---------------------------\n"
                    )
                    self.update_output(job_info)

            except gitlab.exceptions.GitlabGetError as e:
                logger.error(f"GitLab API error: {e}")
                self.update_output(f"GitLab API error: {str(e)}")
            except Exception as e:
                logger.error(f"Error checking project jobs: {e}")
                self.update_output(f"Error checking project jobs: {str(e)}")

        # Submit the task to the executor for background execution
        future: Future = self.executor.submit(task)
            
            
    def check_pipeline_logs(self):
        """Check and display logs for a specific job in a pipeline."""
        if not self.project:
            self.update_output("Error: No project loaded. Please select a project first.")
            return

        def fetch_pipelines():
            try:
                self.update_output(f"Fetching pipelines for project '{self.project.name}'...")
                pipelines = self.project.pipelines.list(order_by='id', sort='desc', per_page=10, get_all=False)
                self.update_output(f"Fetched {len(pipelines)} pipelines.")

                if not pipelines:
                    self.update_output(f"No pipelines found for project '{self.project.name}'.")
                    return

                pipeline_descriptions = [f"Pipeline ID: {pipeline.id} | Ref: {pipeline.ref} | Status: {pipeline.status}" for pipeline in pipelines]

                # Move the selection dialog to the main thread
                QMetaObject.invokeMethod(
                    self,
                    "prompt_pipeline_selection",
                    Qt.QueuedConnection,
                    Q_ARG(list, pipelines),
                    Q_ARG(list, pipeline_descriptions)
                )

            except gitlab.exceptions.GitlabGetError as e:
                logger.error(f"GitLab API error: {e}")
                self.update_output(f"GitLab API error: {str(e)}")
            except Exception as e:
                logger.error(f"Error fetching pipeline jobs: {e}")
                self.update_output(f"Error fetching pipeline jobs: {str(e)}")

        # Fetch pipelines in the background
        self.executor.submit(fetch_pipelines)

    @pyqtSlot(list, list)
    def prompt_pipeline_selection(self, pipelines, pipeline_descriptions):
        """Prompt the user to select a pipeline on the main thread."""
        selected_pipeline_description, ok = QInputDialog.getItem(
            self,
            "Select Pipeline",
            "Choose a pipeline to view job logs:",
            pipeline_descriptions,
            0,
            False
        )

        if ok and selected_pipeline_description:
            selected_index = pipeline_descriptions.index(selected_pipeline_description)
            selected_pipeline_id = pipelines[selected_index].id

            # Fetch jobs for the selected pipeline
            self.fetch_pipeline_jobs(selected_pipeline_id)
        else:
            self.update_output("Pipeline selection for job log viewing canceled.")

    def fetch_pipeline_jobs(self, pipeline_id):
        """Fetch and prompt the user to select a job from the pipeline."""
        def fetch_jobs():
            try:
                selected_pipeline = self.project.pipelines.get(pipeline_id)
                jobs = selected_pipeline.jobs.list(all=True)

                if not jobs:
                    self.update_output(f"No jobs found for Pipeline ID {pipeline_id}.")
                    return

                # Create job descriptions with name
                job_descriptions = [f"Job Name: {job.name} | Status: {job.status} | Stage: {job.stage}" for job in jobs]

                # Move the job selection to the main thread
                QMetaObject.invokeMethod(
                    self,
                    "prompt_job_selection",
                    Qt.QueuedConnection,
                    Q_ARG(list, jobs),
                    Q_ARG(list, job_descriptions)
                )

            except gitlab.exceptions.GitlabGetError as e:
                logger.error(f"GitLab API error: {e}")
                self.update_output(f"GitLab API error: {str(e)}")
            except Exception as e:
                logger.error(f"Error fetching pipeline jobs: {e}")
                self.update_output(f"Error fetching pipeline jobs: {str(e)}")

        # Fetch jobs in the background
        self.executor.submit(fetch_jobs)

    @pyqtSlot(list, list)
    def prompt_job_selection(self, jobs, job_descriptions):
        """Prompt the user to select a job based on its name on the main thread."""
        selected_job_description, ok = QInputDialog.getItem(
            self,
            "Select Job",
            "Choose a job to view logs:",
            job_descriptions,
            0,
            False
        )

        if ok and selected_job_description:
            selected_job_index = job_descriptions.index(selected_job_description)
            selected_job_id = jobs[selected_job_index].id
            selected_job_name = jobs[selected_job_index].name

            # Fetch and display the logs for the selected job
            self.fetch_and_display_job_logs(selected_job_id, selected_job_name)
        else:
            self.update_output("Job log viewing canceled.")

    def fetch_and_display_job_logs(self, job_id, job_name):
        """Fetch and display logs for the selected job."""
        def fetch_logs():
            try:
                self.update_output(f"Fetching logs for Job '{job_name}' (ID: {job_id})...")

                # Get the job from the project
                job = self.project.jobs.get(job_id)

                # Fetch job trace/log
                job_trace = job.trace()

                # Decode if necessary (assuming UTF-8)
                if isinstance(job_trace, bytes):
                    job_trace = job_trace.decode('utf-8', errors='replace')

                # Filter meaningful logs (e.g., errors, warnings)
                filtered_logs = self.filter_meaningful_logs(job_trace)

                self.update_output(f"\n--- Logs for Job '{job_name}' ---")
                if filtered_logs:
                    self.update_output(filtered_logs)
                else:
                    self.update_output("No meaningful logs found for this job.")
            
            except gitlab.exceptions.GitlabGetError as e:
                logger.error(f"GitLab API error while fetching logs for Job ID {job_id}: {e}")
                self.update_output(f"GitLab API error while fetching logs for Job ID {job_id}: {str(e)}")
            except Exception as e:
                logger.error(f"Error fetching logs for Job ID {job_id}: {e}")
                self.update_output(f"Error fetching logs for Job ID {job_id}: {str(e)}")

        # Fetch logs in the background
        self.executor.submit(fetch_logs)
        
        
    def fetch_and_display_logs(self, pipeline_id):
        """Fetch and display logs for the selected pipeline."""
        def task():
            try:
                pipeline = self.project.pipelines.get(pipeline_id)

                # Fetch jobs for the selected pipeline
                jobs = pipeline.jobs.list(all=True)
                if not jobs:
                    self.update_output(f"No jobs found for Pipeline ID {pipeline.id}.")
                    return

                for job in jobs:
                    job_name = job.name
                    job_id = job.id
                    self.update_output(f"\n--- Logs for Job '{job_name}' (ID: {job_id}) ---")

                    try:
                        # Fetch job trace/log
                        job_trace = job.trace()

                        # Decode if necessary (assuming UTF-8)
                        if isinstance(job_trace, bytes):
                            job_trace = job_trace.decode('utf-8', errors='replace')

                        # Clean ANSI escape sequences and highlight key phrases
                        cleaned_logs = self.clean_ansi_sequences(job_trace)
                        highlighted_logs = self.highlight_key_phrases(cleaned_logs)

                        # Display highlighted logs
                        self.update_output(highlighted_logs)
                        
                    except gitlab.exceptions.GitlabGetError as e:
                        logger.error(f"GitLab API error while fetching logs for Job ID {job_id}: {e}")
                        self.update_output(f"GitLab API error while fetching logs for Job ID {job_id}: {str(e)}")
                    except Exception as e:
                        logger.error(f"Error fetching logs for Job ID {job_id}: {e}")
                        self.update_output(f"Error fetching logs for Job ID {job_id}: {str(e)}")

            except gitlab.exceptions.GitlabGetError as e:
                logger.error(f"GitLab API error: {e}")
                self.update_output(f"GitLab API error: {str(e)}")
            except Exception as e:
                logger.error(f"Error fetching pipeline logs: {e}")
                self.update_output(f"Error fetching pipeline logs: {str(e)}")

        # Submit the log fetching task to the executor
        self.executor.submit(task)
        
    def clean_ansi_sequences(self, logs):
        """Remove ANSI escape sequences for better readability."""
        ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
        return ansi_escape.sub('', logs)

    def highlight_key_phrases(self, logs):
        """Highlight important phrases for better visibility."""
        key_phrases = ['Deploying the project...', 'Job succeeded', 'Job failed']
        highlighted_logs = logs
        
        for phrase in key_phrases:
            highlighted_logs = highlighted_logs.replace(phrase, f"**{phrase}**")
        
        return highlighted_logs

    #########



    def trigger_pipeline(self):
        """Trigger a pipeline for a specific branch."""
        # Get the selected project ID
        project_id = self.pipeline_project_dropdown.currentData()

        if not project_id:
            self.update_output("Error: No project selected. Please select a project first.")
            return

        # Prompt user to select a branch
        branch_name = self.get_branch_name()

        if not branch_name:
            # If no branch is selected or the action is canceled, exit
            self.update_output("No branch selected. Pipeline trigger aborted.")
            return

        try:
            # Fetch the project using the GitLab client
            project = self.gitlab_client.projects.get(project_id)
            
            self.update_output(f"Triggering pipeline for project '{project.name}' on branch '{branch_name}'...")

            # Trigger the pipeline for the specified branch
            pipeline = project.pipelines.create({'ref': branch_name})
            
            self.update_output(f"Pipeline triggered: ID {pipeline.id}, Status: {pipeline.status}")
        except gitlab.exceptions.GitlabGetError as e:
            logger.error(f"GitLab API error: {e}")
            self.update_output(f"GitLab API error: {str(e)}")
        except Exception as e:
            logger.error(f"Error triggering pipeline: {e}")
            self.update_output(f"Error triggering pipeline: {str(e)}")



    def handle_trigger_pipeline(self):
        """Handle the Trigger Pipeline action by selecting a branch and triggering the pipeline."""
        branch_name = self.get_branch_name()

        if branch_name:
            # Submit the pipeline triggering to the background thread
            self.executor.submit(self.trigger_pipeline_task, branch_name)
        else:
            self.update_output("No branch selected. Pipeline trigger aborted.")

            
    def get_branch_name(self):
        """Prompt the user to select a branch when triggering a pipeline."""
        # Get the selected project ID
        project_id = self.pipeline_project_dropdown.currentData()

        if not project_id:
            self.update_output("Error: No project selected. Please select a project first.")
            return None

        try:
            # Fetch the project using the GitLab client
            project = self.gitlab_client.projects.get(project_id)

            # Fetch branches
            branches = project.branches.list()
            branch_names = [branch.name for branch in branches]

            if not branch_names:
                self.update_output(f"No branches found for project '{project.name}'.")
                return None

            # Prompt the user to select a branch using a blocking dialog on the main thread
            branch_name, ok = QInputDialog.getItem(
                self,
                "Select Branch",
                "Choose a branch to trigger the pipeline:",
                branch_names,
                0,
                False
            )

            # Return the selected branch if confirmed, otherwise return None
            return branch_name if ok else None

        except gitlab.exceptions.GitlabGetError as e:
            logger.error(f"GitLab API error: {e}")
            self.update_output(f"GitLab API error: {str(e)}")
        except Exception as e:
            logger.error(f"Error fetching branches: {e}")
            self.update_output(f"Error fetching branches: {str(e)}")

        return None


    

    @pyqtSlot(list)
    def show_pipeline_selection_dialog(self, pipeline_descriptions):
        """Show a dialog for the user to select a pipeline."""
        try:
            logger.info("show_pipeline_selection_dialog called.")

            selected_description, ok = QInputDialog.getItem(
                self,
                "Select Pipeline",
                "Choose a pipeline to view logs:",
                pipeline_descriptions,
                0,
                False
            )

            logger.info(f"QInputDialog returned: selected_description='{selected_description}', ok={ok}")

            if ok and selected_description:
                try:
                    # Find the index of the selected description
                    selected_index = pipeline_descriptions.index(selected_description)
                    # Retrieve the corresponding pipeline ID
                    selected_pipeline_id = self.pipeline_ids[selected_index]
                    logger.info(f"Selected pipeline ID: {selected_pipeline_id}")
                    # Directly call fetch_and_display_logs
                    self.fetch_and_display_logs(selected_pipeline_id)
                except (IndexError, ValueError) as e:
                    self.update_output("Invalid pipeline selection. Please try again.")
                    logger.error(f"Error retrieving pipeline ID: {e}")
            else:
                self.update_output("Pipeline log viewing canceled.")
                logger.info("Pipeline log viewing canceled by user.")

        except Exception as e:
            logger.error(f"Error in show_pipeline_selection_dialog: {e}")
            self.update_output(f"Error in pipeline selection dialog: {str(e)}")




    def view_pipeline_logs(self):
        """View logs of a selected pipeline."""
        if not self.project:
            self.update_output("Error: No project loaded. Please select a project first.")
            return

        def task():
            try:
                self.update_output(f"Fetching pipelines for project '{self.project.name}'...")
                # Fetch the latest 10 pipelines sorted by ID descending
                pipelines = self.project.pipelines.list(order_by='id', sort='desc', per_page=10, get_all=False)
                self.update_output(f"Fetched {len(pipelines)} pipelines.")

                if not pipelines:
                    self.update_output(f"No pipelines found for project '{self.project.name}'.")
                    return

                # Prepare simplified pipeline descriptions based on current stage
                pipeline_descriptions = []
                self.pipeline_ids = []  # Reset the list to store pipeline IDs

                for pipeline in pipelines:
                    # Determine the current stage of the pipeline
                    current_stage, pipeline_status = self.get_pipeline_current_stage(pipeline)

                    # Parse the created_at string into a datetime object
                    try:
                        # Updated format string to include fractional seconds
                        created_at_dt = datetime.strptime(pipeline.created_at, "%Y-%m-%dT%H:%M:%S.%fZ")
                        created_at_str = created_at_dt.strftime('%Y-%m-%d %H:%M')
                    except ValueError as ve:
                        # Handle unexpected date formats
                        logger.error(f"Error parsing date for pipeline ID {pipeline.id}: {ve}")
                        self.update_output(f"Error parsing date for pipeline ID {pipeline.id}: {ve}")
                        created_at_str = pipeline.created_at  # Fallback to original string

                    # Create a simplified description
                    description = f"Stage: {current_stage} | Ref: {pipeline.ref} | Status: {pipeline_status} | Created: {created_at_str}"
                    pipeline_descriptions.append(description)
                    self.pipeline_ids.append(pipeline.id)

                    # Log the simplified description
                    self.update_output(f"Pipeline Description: {description}")
                    logger.info(f"Pipeline Description: {description}")

                # Emit signal to show the selection dialog on the main thread
                QTimer.singleShot(0, lambda: self.show_pipeline_selection_dialog(pipeline_descriptions))

            except gitlab.exceptions.GitlabGetError as e:
                logger.error(f"GitLab API error: {e}")
                self.update_output(f"GitLab API error: {str(e)}")
            except Exception as e:
                logger.error(f"Error fetching pipelines: {e}")
                self.update_output(f"Error fetching pipelines: {str(e)}")

        # Submit the task to the executor for background execution
        self.executor.submit(task)

        
        
    def get_pipeline_current_stage(self, pipeline):
        """
        Determine the current stage of the pipeline based on its jobs.
        Returns a tuple of (current_stage, pipeline_status).
        """
        try:
            jobs = pipeline.jobs.list(all=True, order_by='id', sort='asc')  # Ensure jobs are ordered
            stages = []
            stage_status = {}

            for job in jobs:
                stage = job.stage
                status = job.status

                if stage not in stages:
                    stages.append(stage)

                if stage not in stage_status:
                    stage_status[stage] = []

                stage_status[stage].append(status)

            # Iterate through stages to find the first stage that is not completed
            for stage in stages:
                statuses = stage_status[stage]
                if any(status in ['pending', 'running'] for status in statuses):
                    return (stage, 'Running')
                elif any(status == 'failed' for status in statuses):
                    return (stage, 'Failed')
                elif all(status == 'success' for status in statuses):
                    continue  # Stage completed successfully
                else:
                    continue  # Other statuses

            # If all stages are completed successfully
            return ('Completed', 'Success')

        except Exception as e:
            logger.error(f"Error determining pipeline stage: {e}")
            return ('Unknown', 'Unknown')




    def filter_meaningful_logs(self, logs):
        """Return all logs without filtering."""
        return logs
    
    
    def fetch_repository_insights(self):
        """Fetch and display repository insights for the selected project."""
        if not self.project:
            self.update_output("Error: No project loaded. Please select a project first.")
            return

        def task():
            try:
                self.update_output(f"Fetching repository insights for project '{self.project.name}'...")
                
                # Get all commits for the project
                commits = self.project.commits.list(all=True)
                commit_count = len(commits)
                
                # Collect contributor information
                contributors = {}
                for commit in commits:
                    author_name = commit.author_name
                    contributors[author_name] = contributors.get(author_name, 0) + 1
                
                # Sort contributors by the number of commits
                sorted_contributors = sorted(contributors.items(), key=lambda x: x[1], reverse=True)
                
                # Format insights
                insights = f"Total Commits: {commit_count}\nTop Contributors:\n"
                for name, count in sorted_contributors[:5]:  # Display top 5 contributors
                    insights += f"{name}: {count} commits\n"
                
                # Display insights using update_output
                self.update_output(insights)
                logger.info(f"Repository insights fetched for project '{self.project.name}'.")
            except Exception as e:
                logger.error(f"Error fetching repository insights: {e}")
                self.update_output(f"Error fetching repository insights: {str(e)}")

        # Submit the task to the executor for background execution
        self.executor.submit(task)


    def toggle_project_visibility(self):
        """Toggle the visibility of the selected project between private and public."""
        if not self.project:
            self.update_output("Error: No project loaded. Please select a project first.")
            return

        def task():
            try:
                # Check the current visibility of the project
                current_visibility = self.project.visibility
                logger.info(f"Current project visibility: {current_visibility}")
                self.update_output(f"Current project visibility: {current_visibility}")

                new_visibility = 'public' if current_visibility == 'private' else 'private'
                logger.info(f"Setting new visibility to: {new_visibility}")

                # Display confirmation dialog on the main thread
                self.confirm_and_toggle_visibility(current_visibility, new_visibility)

            except Exception as e:
                logger.error(f"Error toggling project visibility: {e}")
                self.update_output(f"Error toggling project visibility: {str(e)}")

        def confirm_and_toggle_visibility(current_visibility, new_visibility):
            logger.info("Displaying confirmation dialog for visibility change.")

            reply = QMessageBox.question(
                self,
                'Change Project Visibility',
                f'The project is currently {current_visibility}. Do you want to change it to {new_visibility}?',
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )

            if reply == QMessageBox.Yes:
                logger.info("User confirmed visibility change.")
                # Update project visibility
                try:
                    self.project.visibility = new_visibility
                    self.project.save()
                    self.update_output(f"Project visibility changed to {new_visibility}.")
                    logger.info(f"Project visibility changed to {new_visibility} for '{self.project.name}'.")
                except Exception as e:
                    logger.error(f"Error saving project visibility change: {e}")
                    self.update_output(f"Error saving project visibility change: {str(e)}")
            else:
                self.update_output("Visibility change canceled.")
                logger.info("User canceled visibility change.")

        # Use QTimer to ensure the dialog is run on the main thread
        QTimer.singleShot(0, lambda: confirm_and_toggle_visibility(self.project.visibility, 'public' if self.project.visibility == 'private' else 'private'))


    def delete_gitlab_project(self):
        """Delete the selected GitLab project."""
        if not self.project:
            self.update_output("Error: No project loaded. Please select a project first.")
            return

        def confirm_and_delete_project():
            logger.info("Displaying confirmation dialog for project deletion.")

            reply = QMessageBox.question(
                self,
                'Delete Project',
                f'Are you sure you want to delete the project "{self.project.name}"? This action cannot be undone.',
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )

            if reply == QMessageBox.Yes:
                try:
                    project_name = self.project.name  # Store project name for logging
                    # Delete the project
                    self.project.delete()
                    self.update_output(f"Project '{project_name}' deleted successfully.")
                    logger.info(f"Project '{project_name}' deleted successfully.")
                    # Optionally, refresh the project dropdown after deletion
                    self.populate_gitlab_project_dropdown()
                except Exception as e:
                    logger.error(f"Error deleting project: {e}")
                    self.update_output(f"Error deleting project: {str(e)}")
            else:
                self.update_output("Project deletion canceled.")
                logger.info("User canceled project deletion.")

        # Use QTimer to ensure the dialog is run on the main thread
        QTimer.singleShot(0, confirm_and_delete_project)


    def schedule_pipeline_action(self):
        """Prompt for scheduling options for the pipeline."""
        schedule_options = ["Schedule Pipeline", "List Schedules", "Cancel Schedule"]
        selected_action, ok = QInputDialog.getItem(self, "Schedule Pipeline", "Select an action:", schedule_options, 0, False)

        if ok and selected_action:
            if selected_action == "Schedule Pipeline":
                self.create_pipeline_schedule()
            elif selected_action == "List Schedules":
                self.list_pipeline_schedules()
            elif selected_action == "Cancel Schedule":
                self.cancel_pipeline_schedule()
            else:
                self.update_output(f"Invalid schedule action selected: {selected_action}")
        else:
            self.update_output("Pipeline schedule action canceled.")

    

    def create_pipeline_schedule(self):
        """Create a new schedule for the pipeline."""
        try:
            # Fetch all branches in the project
            branches = self.project.branches.list()
            branch_names = [branch.name for branch in branches]

            if not branch_names:
                self.update_output(f"No branches found for project '{self.project.name}'.")
                return
            
            # Prompt for scheduling details
            description, ok_desc = QInputDialog.getText(self, "Schedule Pipeline", "Enter Schedule Description:")
            date_time_str, ok_time = QInputDialog.getText(self, "Schedule Pipeline", "Enter Date & Time (YYYY-MM-DD HH:MM):")
            
            # Create a dropdown for selecting the branch to schedule
            ref, ok_ref = QInputDialog.getItem(self, "Schedule Pipeline", "Select Branch to Schedule:", branch_names, 0, False)

            if ok_desc and ok_time and ok_ref:
                # Convert the provided datetime string to a cron expression
                cron = self.convert_datetime_to_cron(date_time_str)
                if cron:
                    # Create the schedule
                    schedule = self.project.pipelineschedules.create({
                        'description': description,
                        'ref': ref,
                        'cron': cron
                    })
                    self.update_output(f"Pipeline schedule created successfully with ID: {schedule.id}, Cron: {schedule.cron}")
                else:
                    self.update_output("Failed to create pipeline schedule due to invalid datetime format.")
            else:
                self.update_output("Pipeline scheduling canceled or invalid input.")
        except gitlab.exceptions.GitlabCreateError as e:
            self.update_output(f"Error creating pipeline schedule: {e}")
        except Exception as e:
            self.update_output(f"Unexpected error creating pipeline schedule: {e}")

            
    
    def convert_datetime_to_cron(self, date_time_str):
        """Convert datetime string to cron format."""
        from datetime import datetime
        try:
            dt = datetime.strptime(date_time_str, '%Y-%m-%d %H:%M')
            cron = f"{dt.minute} {dt.hour} {dt.day} {dt.month} *"
            return cron
        except ValueError:
            self.update_output("Invalid datetime format. Please use YYYY-MM-DD HH:MM.")
            # Return a default value or handle error appropriately
            return None


    

    def list_pipeline_schedules(self):
        """List all scheduled pipelines for the current project."""
        try:
            schedules = self.project.pipelineschedules.list()
            if schedules:
                self.update_output(f"Listing pipeline schedules for project '{self.project.name}':")
                for schedule in schedules:
                    # Convert cron to a readable datetime format
                    readable_time = self.convert_cron_to_datetime(schedule.cron)
                    self.update_output(f"Schedule ID: {schedule.id}, Description: {schedule.description}, "
                                    f"Cron: {schedule.cron} (Executes on: {readable_time}), "
                                    f"Branch: {schedule.ref}, Active: {schedule.active}")
            else:
                self.update_output(f"No pipeline schedules found for project '{self.project.name}'.")
        except gitlab.exceptions.GitlabGetError as e:
            self.update_output(f"Error listing pipeline schedules: {e}")
        except Exception as e:
            self.update_output(f"Unexpected error listing pipeline schedules: {e}")
            
            
    def convert_cron_to_datetime(self, cron_str):
        """Convert a cron expression to a human-readable datetime format."""
        try:
            # Split the cron string into its components
            minute, hour, day, month, _ = cron_str.split()
            # Construct a readable string
            readable_time = f"{month.zfill(2)}-{day.zfill(2)} {hour.zfill(2)}:{minute.zfill(2)}"
            return readable_time
        except ValueError:
            return "Invalid cron format"


    def cancel_pipeline_schedule(self):
        """Cancel a scheduled pipeline."""
        try:
            schedules = self.project.pipelineschedules.list()

            if schedules:
                # Prompt user to select a schedule to cancel
                schedule_descriptions = [f"{s.description} (ID: {s.id})" for s in schedules]
                selected_schedule, ok = QInputDialog.getItem(self, "Cancel Pipeline Schedule", "Select Schedule to Cancel:", schedule_descriptions, 0, False)

                if ok and selected_schedule:
                    # Extract the schedule ID from the selected item
                    schedule_id = int(selected_schedule.split("(ID: ")[1].strip(")"))
                    
                    # Find the schedule and delete it
                    schedule_to_cancel = self.project.pipelineschedules.get(schedule_id)
                    schedule_to_cancel.delete()
                    self.update_output(f"Pipeline schedule with ID {schedule_id} canceled successfully.")
                else:
                    self.update_output("Pipeline schedule cancellation canceled.")
            else:
                self.update_output(f"No pipeline schedules available to cancel for project '{self.project.name}'.")
        except gitlab.exceptions.GitlabDeleteError as e:
            self.update_output(f"Error canceling pipeline schedule: {e}")
        except Exception as e:
            self.update_output(f"Unexpected error canceling pipeline schedule: {e}")


    def set_branch_protection(self):
        """Set or remove protection on a branch."""
        try:
            # Fetch all branches in the project
            branches = self.project.branches.list()
            branch_names = [branch.name for branch in branches]

            if not branch_names:
                self.update_output(f"No branches found for project '{self.project.name}'.")
                return
            
            # Create a dropdown for selecting the branch
            branch_name, ok_branch = QInputDialog.getItem(self, "Branch Protection", 
                                                        "Select Branch:", branch_names, 0, False)
            
            if ok_branch and branch_name:
                # Ask the user to set or remove protection
                protection_options = ["Protect Branch", "Unprotect Branch"]
                protection_action, ok_action = QInputDialog.getItem(self, "Set Branch Protection", 
                                                                    "Choose Action:", protection_options, 0, False)
                
                if ok_action and protection_action:
                    try:
                        # Check if the branch is already protected
                        existing_protected_branches = self.project.protectedbranches.list()
                        protected_branch_names = [branch.name for branch in existing_protected_branches]

                        if protection_action == "Protect Branch":
                            # Protect the branch if not already protected
                            if branch_name in protected_branch_names:
                                self.update_output(f"Branch '{branch_name}' is already protected.")
                            else:
                                self.project.protectedbranches.create({'name': branch_name})
                                self.update_output(f"Branch '{branch_name}' protected successfully.")
                        elif protection_action == "Unprotect Branch":
                            # Unprotect the branch if it is protected
                            if branch_name in protected_branch_names:
                                protected_branch = self.project.protectedbranches.get(branch_name)
                                protected_branch.delete()
                                self.update_output(f"Branch '{branch_name}' unprotected successfully.")
                            else:
                                self.update_output(f"Branch '{branch_name}' is not currently protected.")
                        else:
                            self.update_output("Invalid protection action selected.")
                    except gitlab.exceptions.GitlabGetError as e:
                        self.update_output(f"Error modifying branch protection: {e}")
                    except Exception as e:
                        self.update_output(f"Unexpected error setting branch protection: {e}")
                else:
                    self.update_output("Branch protection action canceled.")
            else:
                self.update_output("Branch selection canceled or invalid input.")
        except gitlab.exceptions.GitlabGetError as e:
            self.update_output(f"Error fetching branches: {e}")
        except Exception as e:
            self.update_output(f"Unexpected error fetching branches: {e}")









    ######################################################################

    def execute_other_management_action(self):
        """Execute the selected action from the Other Management dropdown."""
        selected_action = self.other_management_dropdown.currentText()
        self.update_output(f"Selected action: {selected_action}")

        actions = {
            "Configure GitLab Runner": self.configure_gitlab_runner,
            "Manage Webhooks": self.manage_webhooks,
            "Manage Pipeline Variables": self.manage_pipeline_variables,
             "Configure Access Tokens": self.configure_access_tokens,
        }

        # Retrieve and execute the function based on the selected action
        action_function = actions.get(selected_action)
        if action_function:
            action_function()
        else:
            self.update_output(f"Invalid action selected: {selected_action}")
            
            
            
    def configure_gitlab_runner(self):
        """Configure GitLab Runner operations based on the type of runner token."""
        # Check if the user is logged in
        if not self.gitlab_client:
            self.update_output("Please connect to GitLab first.")
            return

        # Define the type of runner token options
        token_type_options = ["Self-managed Runner Token", "Group Runner Token"]
        token_type, ok = QInputDialog.getItem(self, "Select Token Type", "Configure Token for:", token_type_options, 0, False)

        if not ok or not token_type:
            self.update_output("Token type selection canceled.")
            return

        # If user selects "Self-managed Runner Token"
        if token_type == "Self-managed Runner Token":
            self.update_output("Configuring self-managed runner for the project...")

            # Define runner actions for self-managed tokens
            action_options = ["Create Runner", "List Runners", "Delete Runner", "List Tokens"]
            action, ok = QInputDialog.getItem(self, "Configure Self-Managed Runner", "Select Runner Action:", action_options, 0, False)
            
            if ok and action:
                if action == "Create Runner":
                    self.create_gitlab_runner()
                elif action == "List Runners":
                    self.list_gitlab_runners()
                elif action == "Delete Runner":
                    self.delete_gitlab_runner()
                elif action == "List Tokens":
                    self.list_runner_tokens()
                else:
                    self.update_output(f"Invalid runner action selected: {action}")
            else:
                self.update_output("Runner action selection canceled.")

        # If user selects "Group Runner Token"
        elif token_type == "Group Runner Token":
            self.update_output("Configuring group runner token...")

            # Define runner actions for group tokens
            group_action_options = ["Create Group Runner", "List Group Runners", "Delete Group Runner", "List Group Tokens"]
            group_action, ok = QInputDialog.getItem(self, "Configure Group Runner", "Select Runner Action:", group_action_options, 0, False)
            
            if ok and group_action:
                if group_action == "Create Group Runner":
                    self.create_group()
                elif group_action == "List Group Runners":
                    self.list_group_runners()
                elif group_action == "Delete Group Runner":
                    self.delete_group_runner()
                elif group_action == "List Group Tokens":
                    self.get_group_registration_token()
                else:
                    self.update_output(f"Invalid group runner action selected: {group_action}")
            else:
                self.update_output("Group runner action selection canceled.")

        else:
            self.update_output("Invalid token type selected.")

    # Self Managed Runner

    def create_gitlab_runner(self):
        """Create a new GitLab Runner."""
        # Ensure a project is loaded
        if not self.project:
            self.update_output("No project loaded. Please select a project first.")
            return

        # Prompt user for runner name and other required details
        runner_name, ok = QInputDialog.getText(self, "Create Runner", "Enter Runner Name:")
        if ok and runner_name:
            try:
                # GitLab runners are generally registered with a token that is specific to a GitLab instance
                registration_token = self.project.runners_token
                
                # Create a runner registration (Note: GitLab expects registration details like token and description)
                runner_details = {
                    'token': registration_token,
                    'description': runner_name,
                    'locked': False,
                    'run_untagged': True,
                    'tag_list': ['ci-runner']
                }
                
                # Register the runner at the instance level
                runner = self.gitlab_client.runners.create(runner_details)
                self.update_output(f"Runner '{runner_name}' created successfully. Registration Token: {registration_token}")

            except gitlab.exceptions.GitlabError as e:
                self.update_output(f"Error creating runner: {e}")
            except Exception as e:
                self.update_output(f"Unexpected error creating runner: {e}")


    def list_gitlab_runners(self):
        """List all self-managed GitLab Runners for the current project."""
        try:
            # Fetch all runners associated with the project
            runners = self.project.runners.list()
            
            # Filter out only self-managed runners
            self_managed_runners = [runner for runner in runners if not runner.is_shared]
            
            if self_managed_runners:
                self.update_output(f"Listing all self-managed runners for the project '{self.project.name}':")
                for runner in self_managed_runners:
                    self.update_output(f"Runner ID: {runner.id}, Name: {runner.description}, Status: {runner.status}, Active: {runner.active}, Online: {runner.online}")
            else:
                self.update_output("No self-managed runners found for the project.")
        except Exception as e:
            self.update_output(f"Error listing self-managed runners: {e}")






    def delete_gitlab_runner(self):
        """Delete a selected GitLab Runner."""
        # Ensure a project is loaded
        if not self.project:
            self.update_output("No project loaded. Please select a project first.")
            return

        try:
            # List all runners for user selection
            runners = self.project.runners.list()
            runner_names = [runner.description for runner in runners]

            if runners:
                runner_name, ok = QInputDialog.getItem(
                    self, "Delete Runner", "Select Runner to Delete:", runner_names, 0, False
                )
                if ok and runner_name:
                    # Find the corresponding runner to delete
                    runner_index = runner_names.index(runner_name)
                    runner_to_delete = runners[runner_index]
                    runner_to_delete.delete()
                    self.update_output(f"Runner '{runner_name}' deleted successfully.")
                else:
                    self.update_output("Runner deletion canceled.")
            else:
                self.update_output("No runners available to delete.")
        except Exception as e:
            self.update_output(f"Error deleting runner: {e}")
            
            
    def list_runner_tokens(self):
        """Display the registration token for the current project."""
        try:
            # Fetch the project to get the registration token
            project_details = self.gitlab_client.projects.get(self.project.id)
            registration_token = project_details.runners_token

            self.update_output(f"Project '{self.project.name}' Registration Token: {registration_token}")
        except Exception as e:
            self.update_output(f"Error fetching project registration token: {e}")


    # Group Runner
    def get_group_registration_token(self):
        """Retrieve and display the group registration token."""
        group_name, ok = QInputDialog.getText(self, "Get Group Token", "Enter Group Name (full path if nested):")
        if ok and group_name:
            try:
                # Fetch the group using the full path
                group = self.gitlab_client.groups.get(group_name)
                # Display the registration token for the group
                registration_token = group.runners_token
                self.update_output(f"Group '{group_name}' Registration Token: {registration_token}")
            except gitlab.exceptions.GitlabGetError as e:
                self.update_output(f"GitLab error fetching group: {e}")
            except Exception as e:
                self.update_output(f"Error retrieving group registration token: {e}")


    
    def create_group(self):
        """Create a new GitLab group."""
        # Prompt for group name
        group_name, ok_name = QInputDialog.getText(self, "Create Group", "Enter Group Name:")
        
        if ok_name and group_name.strip():
            # Create a URL-friendly path from the group name
            group_path = re.sub(r'[^a-zA-Z0-9]+', '-', group_name.strip()).lower()
            
            try:
                # Check if the group already exists
                existing_groups = self.gitlab_client.groups.list(search=group_name.strip())
                if any(group.name == group_name.strip() for group in existing_groups):
                    self.update_output(f"A group named '{group_name.strip()}' already exists.")
                    return
                
                # Create the group
                new_group = self.gitlab_client.groups.create({
                    'name': group_name.strip(),
                    'path': group_path.strip()
                })
                self.update_output(f"Group '{new_group.name}' created successfully with ID: {new_group.id}, Path: {new_group.path}")
            except gitlab.exceptions.GitlabCreateError as e:
                self.update_output(f"Error creating group: {e}")
            except Exception as e:
                self.update_output(f"Unexpected error while creating group: {e}")
        else:
            self.update_output("Group creation canceled or invalid input.")



                
    def list_group_runners(self):
        """List all runners associated with a group."""
        group_name, ok = QInputDialog.getText(self, "List Group Runners", "Enter Group Name (full path if nested):")
        if ok and group_name:
            try:
                # Fetch the group using the full path
                group = self.gitlab_client.groups.get(group_name)
                runners = group.runners.list()
                if runners:
                    self.update_output(f"Listing runners for group '{group_name}':")
                    for runner in runners:
                        self.update_output(f"Runner ID: {runner.id}, Name: {runner.description}, Status: {runner.status}")
                else:
                    self.update_output(f"No runners found for group '{group_name}'.")
            except gitlab.exceptions.GitlabGetError as e:
                self.update_output(f"GitLab error fetching group: {e}")
            except Exception as e:
                self.update_output(f"Error listing group runners: {e}")



                
                
    def delete_group_runner(self):
        """Delete a runner from a group."""
        group_name, ok = QInputDialog.getText(self, "Delete Group Runner", "Enter Group Name (full path if nested):")
        if ok and group_name:
            try:
                # Fetch the group using the full path
                group = self.gitlab_client.groups.get(group_name)
                runners = group.runners.list()
                
                if runners:
                    runner_names = [runner.description for runner in runners]
                    runner_ids = [runner.id for runner in runners]
                    
                    # Prompt the user to select a runner to delete
                    runner_name, ok = QInputDialog.getItem(
                        self, "Delete Group Runner", "Select Runner to Delete:", runner_names, 0, False
                    )
                    
                    if ok and runner_name:
                        # Find the runner ID to delete
                        runner_index = runner_names.index(runner_name)
                        runner_id_to_delete = runner_ids[runner_index]
                        
                        # Delete the runner
                        runner_to_delete = group.runners.get(runner_id_to_delete)
                        runner_to_delete.delete()
                        
                        self.update_output(f"Runner '{runner_name}' deleted successfully from group '{group_name}'.")
                    else:
                        self.update_output("Group runner deletion canceled.")
                else:
                    self.update_output(f"No runners available to delete in group '{group_name}'.")
            except gitlab.exceptions.GitlabGetError as e:
                self.update_output(f"GitLab error fetching group: {e}")
            except Exception as e:
                self.update_output(f"Error deleting group runner: {e}")
                
                
                
    
    def manage_webhooks(self):
        """Manage webhooks for the current project."""
        # Check if a project is loaded
        if not self.project:
            self.update_output("Please load a project first to manage its webhooks.")
            return

        # Define webhook actions
        webhook_actions = ["Create Webhook", "List Webhooks", "Update Webhook", "Delete Webhook"]
        action, ok = QInputDialog.getItem(self, "Manage Webhooks", "Select Webhook Action:", webhook_actions, 0, False)

        if ok and action:
            if action == "Create Webhook":
                self.create_webhook()
            elif action == "List Webhooks":
                self.list_webhooks()
            elif action == "Update Webhook":
                self.update_webhook()
            elif action == "Delete Webhook":
                self.delete_webhook()
            else:
                self.update_output(f"Invalid webhook action selected: {action}")
        else:
            self.update_output("Webhook action selection canceled.")

    def create_webhook(self):
        """Create a new webhook for the project."""
        # Prompt user for webhook details
        webhook_url, ok_url = QInputDialog.getText(self, "Create Webhook", "Enter Webhook URL:")
        
        if ok_url and webhook_url:
            try:
                # Optional: Add a dialog for selecting events for which the webhook will be triggered
                webhook = self.project.hooks.create({
                    'url': webhook_url,
                    'push_events': True,  # Enable webhook for push events as an example
                    'merge_requests_events': True  # Enable for merge requests
                })
                self.update_output(f"Webhook created successfully. ID: {webhook.id}, URL: {webhook.url}")
            except gitlab.exceptions.GitlabCreateError as e:
                self.update_output(f"Error creating webhook: {e}")
            except Exception as e:
                self.update_output(f"Unexpected error creating webhook: {e}")
        else:
            self.update_output("Webhook creation canceled or invalid input.")

    def list_webhooks(self):
        """List all webhooks for the current project."""
        try:
            webhooks = self.project.hooks.list()
            if webhooks:
                self.update_output(f"Listing webhooks for project '{self.project.name}':")
                for hook in webhooks:
                    self.update_output(f"Webhook ID: {hook.id}, URL: {hook.url}, Push Events: {hook.push_events}, Merge Requests Events: {hook.merge_requests_events}")
            else:
                self.update_output(f"No webhooks found for project '{self.project.name}'.")
        except gitlab.exceptions.GitlabGetError as e:
            self.update_output(f"Error listing webhooks: {e}")
        except Exception as e:
            self.update_output(f"Unexpected error listing webhooks: {e}")

    def update_webhook(self):
        """Update an existing webhook."""
        try:
            webhooks = self.project.hooks.list()
            
            if webhooks:
                # Prompt user to select a webhook to update
                webhook_urls = [hook.url for hook in webhooks]
                webhook_url, ok = QInputDialog.getItem(self, "Update Webhook", "Select Webhook to Update:", webhook_urls, 0, False)

                if ok and webhook_url:
                    # Find the selected webhook
                    selected_hook = next(hook for hook in webhooks if hook.url == webhook_url)
                    
                    # Prompt user for new URL or settings
                    new_webhook_url, ok_url = QInputDialog.getText(self, "Update Webhook", "Enter New Webhook URL:", text=selected_hook.url)
                    if ok_url and new_webhook_url:
                        selected_hook.url = new_webhook_url
                        selected_hook.save()
                        self.update_output(f"Webhook updated successfully. New URL: {selected_hook.url}")
                    else:
                        self.update_output("Webhook update canceled or invalid input.")
                else:
                    self.update_output("Webhook update action canceled.")
            else:
                self.update_output(f"No webhooks available to update in project '{self.project.name}'.")
        except gitlab.exceptions.GitlabUpdateError as e:
            self.update_output(f"Error updating webhook: {e}")
        except Exception as e:
            self.update_output(f"Unexpected error updating webhook: {e}")

    def delete_webhook(self):
        """Delete a webhook from the current project."""
        try:
            webhooks = self.project.hooks.list()
            
            if webhooks:
                # Prompt user to select a webhook to delete
                webhook_urls = [hook.url for hook in webhooks]
                webhook_url, ok = QInputDialog.getItem(self, "Delete Webhook", "Select Webhook to Delete:", webhook_urls, 0, False)

                if ok and webhook_url:
                    # Find the selected webhook
                    selected_hook = next(hook for hook in webhooks if hook.url == webhook_url)
                    
                    # Confirm deletion
                    reply = QMessageBox.question(self, 'Delete Webhook', f"Are you sure you want to delete the webhook '{webhook_url}'?",
                                                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
                    
                    if reply == QMessageBox.Yes:
                        selected_hook.delete()
                        self.update_output(f"Webhook '{webhook_url}' deleted successfully.")
                    else:
                        self.update_output("Webhook deletion canceled.")
                else:
                    self.update_output("Webhook deletion action canceled.")
            else:
                self.update_output(f"No webhooks available to delete in project '{self.project.name}'.")
        except gitlab.exceptions.GitlabDeleteError as e:
            self.update_output(f"Error deleting webhook: {e}")
        except Exception as e:
            self.update_output(f"Unexpected error deleting webhook: {e}")




    def manage_pipeline_variables(self):
        """Manage pipeline variables for the current project."""
        action_options = ["Add Variable", "Update Variable", "Delete Variable", "List Variables"]
        action, ok = QInputDialog.getItem(self, "Manage Pipeline Variables", "Select Action:", action_options, 0, False)
        
        # Check if a project is selected
        if not self.project:
            self.update_output("Please select a project first.")
            return
        
        if ok and action:
            if action == "Add Variable":
                self.add_pipeline_variable()
            elif action == "Update Variable":
                self.update_pipeline_variable()
            elif action == "Delete Variable":
                self.delete_pipeline_variable()
            elif action == "List Variables":
                self.list_pipeline_variables()
            else:
                self.update_output(f"Invalid pipeline variable action selected: {action}")
        else:
            self.update_output("Pipeline variable action selection canceled.")

    def add_pipeline_variable(self):
        """Add a new pipeline variable."""
        try:
            key, ok_key = QInputDialog.getText(self, "Add Variable", "Enter Variable Key:")
            value, ok_value = QInputDialog.getText(self, "Add Variable", "Enter Variable Value:")
            variable_type, ok_type = QInputDialog.getItem(self, "Add Variable", "Select Variable Type:", ["env_var", "file"], 0, False)
            
            if ok_key and ok_value and ok_type:
                # Convert the key to uppercase
                key = key.strip().upper()
                
                # Create the pipeline variable
                self.project.variables.create({
                    'key': key,
                    'value': value.strip(),
                    'variable_type': variable_type
                })
                self.update_output(f"Pipeline variable '{key}' added successfully.")
            else:
                self.update_output("Adding pipeline variable canceled or invalid input.")
        except gitlab.exceptions.GitlabCreateError as e:
            self.update_output(f"Error adding pipeline variable: {e}")
        except Exception as e:
            self.update_output(f"Unexpected error adding pipeline variable: {e}")

    def update_pipeline_variable(self):
        """Update an existing pipeline variable."""
        try:
            variables = self.project.variables.list()
            if not variables:
                self.update_output(f"No variables found for project '{self.project.name}'.")
                return

            # List variables for user selection
            variable_keys = [var.key for var in variables]
            selected_var, ok_var = QInputDialog.getItem(self, "Update Variable", "Select Variable to Update:", variable_keys, 0, False)
            
            if ok_var and selected_var:
                # Prompt for new value
                new_value, ok_value = QInputDialog.getText(self, "Update Variable", f"Enter New Value for {selected_var}:")
                
                if ok_value:
                    # Update the variable value
                    variable_to_update = self.project.variables.get(selected_var)
                    variable_to_update.value = new_value.strip()
                    variable_to_update.save()
                    self.update_output(f"Pipeline variable '{selected_var}' updated successfully.")
                else:
                    self.update_output("Updating pipeline variable canceled or invalid input.")
            else:
                self.update_output("Variable selection canceled.")
        except gitlab.exceptions.GitlabGetError as e:
            self.update_output(f"Error updating pipeline variable: {e}")
        except Exception as e:
            self.update_output(f"Unexpected error updating pipeline variable: {e}")

    def delete_pipeline_variable(self):
        """Delete an existing pipeline variable."""
        try:
            variables = self.project.variables.list()
            if not variables:
                self.update_output(f"No variables found for project '{self.project.name}'.")
                return

            # List variables for user selection
            variable_keys = [var.key for var in variables]
            selected_var, ok_var = QInputDialog.getItem(self, "Delete Variable", "Select Variable to Delete:", variable_keys, 0, False)
            
            if ok_var and selected_var:
                # Delete the variable
                variable_to_delete = self.project.variables.get(selected_var)
                variable_to_delete.delete()
                self.update_output(f"Pipeline variable '{selected_var}' deleted successfully.")
            else:
                self.update_output("Variable deletion canceled.")
        except gitlab.exceptions.GitlabGetError as e:
            self.update_output(f"Error deleting pipeline variable: {e}")
        except Exception as e:
            self.update_output(f"Unexpected error deleting pipeline variable: {e}")

    def list_pipeline_variables(self):
        """List all pipeline variables for the current project."""
        try:
            variables = self.project.variables.list()
            if variables:
                self.update_output(f"Listing pipeline variables for project '{self.project.name}':")
                for var in variables:
                    self.update_output(f"Key: {var.key}, Value: {var.value}, Type: {var.variable_type}")
            else:
                self.update_output(f"No pipeline variables found for project '{self.project.name}'.")
        except gitlab.exceptions.GitlabGetError as e:
            self.update_output(f"Error listing pipeline variables: {e}")
        except Exception as e:
            self.update_output(f"Unexpected error listing pipeline variables: {e}")


    def configure_access_tokens(self):
        """Prompt user to select between Project Access Tokens and Pipeline Trigger Tokens."""
        token_type, ok = QInputDialog.getItem(
            self, "Access Token Configuration", "Select Token Type:", 
            ["Project Access Tokens", "Pipeline Trigger Tokens"], 0, False
        )

        if ok and token_type:
            if token_type == "Project Access Tokens":
                self.manage_project_access_tokens()
            elif token_type == "Pipeline Trigger Tokens":
                self.manage_pipeline_trigger_tokens()
        else:
            self.update_output("Access token configuration canceled.")

    # --- Project Access Tokens ---
    def manage_project_access_tokens(self):
        """Manage Project Access Tokens."""
        action, ok = QInputDialog.getItem(
            self, "Manage Project Access Tokens", "Select Action:", 
            ["Generate Token", "List Tokens", "Delete Token"], 0, False
        )
        
        if ok and action:
            if action == "Generate Token":
                self.generate_project_access_token()
            elif action == "List Tokens":
                self.list_project_access_tokens()
            elif action == "Delete Token":
                self.delete_project_access_token()
        else:
            self.update_output("Project access token management canceled.")

    def generate_project_access_token(self):
        """Generate a new Project Access Token."""
        if not self.project:
            self.update_output("Please select a project first.")
            return

        # Custom dialog for access token creation
        dialog = QDialog(self)
        dialog.setWindowTitle("Generate Project Access Token")

        layout = QVBoxLayout()

        # Name input
        layout.addWidget(QLabel("Enter Token Name:"))
        name_edit = QLineEdit()
        layout.addWidget(name_edit)

        # Scopes input as a QListWidget with checkboxes
        layout.addWidget(QLabel("Select Scopes:"))
        scopes_list = QListWidget()
        scopes_list.setSelectionMode(QListWidget.MultiSelection)

        # Available scopes
        available_scopes = ["api", "read_api", "create_runner", "manage_runner", "k8s_proxy", 
                            "read_repository", "write_repository", "read_registry", "write_registry", "ai_features"]

        # Add each scope as a list item
        for scope in available_scopes:
            item = QListWidgetItem(scope)
            item.setCheckState(False)  # Initialize as unchecked
            scopes_list.addItem(item)

        layout.addWidget(scopes_list)

        # Role selection
        layout.addWidget(QLabel("Select Role:"))
        role_combo = QComboBox()
        role_combo.addItems(["guest", "reporter", "developer", "maintainer", "owner"])
        layout.addWidget(role_combo)

        # Visibility checkbox
        visibility_checkbox = QCheckBox("Make Token Visible")
        layout.addWidget(visibility_checkbox)

        # Expiry date
        layout.addWidget(QLabel("Select Expiry Date:"))
        expiry_date_edit = QDateEdit()
        expiry_date_edit.setDate(QDate.currentDate())
        expiry_date_edit.setCalendarPopup(True)
        layout.addWidget(expiry_date_edit)

        # Buttons
        submit_btn = QPushButton("Generate")
        cancel_btn = QPushButton("Cancel")
        layout.addWidget(submit_btn)
        layout.addWidget(cancel_btn)

        dialog.setLayout(layout)

        # Button connections
        submit_btn.clicked.connect(dialog.accept)
        cancel_btn.clicked.connect(dialog.reject)

        # Show dialog
        if dialog.exec_() == QDialog.Accepted:
            name = name_edit.text().strip()
            role = role_combo.currentText()
            visible = visibility_checkbox.isChecked()
            expiry_date = expiry_date_edit.date().toString("yyyy-MM-dd")

            # Collect selected scopes
            selected_scopes = [scopes_list.item(i).text() for i in range(scopes_list.count()) if scopes_list.item(i).checkState()]
            
            if name and selected_scopes and role:
                try:
                    # Create the access token with the selected scopes and role
                    token = self.project.access_tokens.create({
                        'name': name,
                        'scopes': selected_scopes,
                        'role': role,
                        'expires_at': expiry_date,
                        'visible': visible
                    })
                    self.update_output(f"Project access token '{name}' created successfully. Token: {token.token}")
                except gitlab.exceptions.GitlabCreateError as e:
                    self.update_output(f"Error creating project access token: {e}")
                except Exception as e:
                    self.update_output(f"Unexpected error creating project access token: {e}")
            else:
                self.update_output("Token generation canceled or invalid input.")
        else:
            self.update_output("Token generation canceled.")


    def list_project_access_tokens(self):
        """List all Project Access Tokens."""
        if not self.project:
            self.update_output("Please select a project first.")
            return

        try:
            tokens = self.project.access_tokens.list()
            if tokens:
                self.update_output(f"Listing access tokens for project '{self.project.name}':")
                for token in tokens:
                    self.update_output(f"Name: {token.name}, Scopes: {token.scopes}, Created At: {token.created_at}")
            else:
                self.update_output(f"No access tokens found for project '{self.project.name}'.")
        except gitlab.exceptions.GitlabGetError as e:
            self.update_output(f"Error listing project access tokens: {e}")
        except Exception as e:
            self.update_output(f"Unexpected error listing project access tokens: {e}")

    def delete_project_access_token(self):
        """Delete an existing Project Access Token."""
        if not self.project:
            self.update_output("Please select a project first.")
            return

        try:
            tokens = self.project.access_tokens.list()
            if not tokens:
                self.update_output(f"No access tokens found for project '{self.project.name}'.")
                return

            token_names = [token.name for token in tokens]
            selected_token, ok_token = QInputDialog.getItem(
                self, "Delete Access Token", "Select Token to Delete:", token_names, 0, False
            )
            
            if ok_token and selected_token:
                token_to_delete = next((token for token in tokens if token.name == selected_token), None)
                if token_to_delete:
                    token_to_delete.delete()
                    self.update_output(f"Access token '{selected_token}' deleted successfully.")
                else:
                    self.update_output("Error finding token to delete.")
            else:
                self.update_output("Token deletion canceled.")
        except gitlab.exceptions.GitlabGetError as e:
            self.update_output(f"Error deleting project access token: {e}")
        except Exception as e:
            self.update_output(f"Unexpected error deleting project access token: {e}")

    # --- Pipeline Trigger Tokens ---
    def manage_pipeline_trigger_tokens(self):
        """Manage Pipeline Trigger Tokens."""
        action, ok = QInputDialog.getItem(
            self, "Manage Pipeline Trigger Tokens", "Select Action:", 
            ["Generate Token", "List Tokens", "Delete Token"], 0, False
        )
        
        if ok and action:
            if action == "Generate Token":
                self.generate_pipeline_trigger_token()
            elif action == "List Tokens":
                self.list_pipeline_trigger_tokens()
            elif action == "Delete Token":
                self.delete_pipeline_trigger_token()
        else:
            self.update_output("Pipeline trigger token management canceled.")

    def generate_pipeline_trigger_token(self):
        """Generate a new Pipeline Trigger Token."""
        if not self.project:
            self.update_output("Please select a project first.")
            return

        try:
            description, ok_desc = QInputDialog.getText(self, "Generate Trigger Token", "Enter Token Description:")
            
            if ok_desc and description:
                trigger = self.project.triggers.create({
                    'description': description.strip()
                })
                self.update_output(f"Pipeline trigger token '{description}' created successfully. Token: {trigger.token}")
            else:
                self.update_output("Trigger token generation canceled or invalid input.")
        except gitlab.exceptions.GitlabCreateError as e:
            self.update_output(f"Error creating pipeline trigger token: {e}")
        except Exception as e:
            self.update_output(f"Unexpected error creating pipeline trigger token: {e}")

    def list_pipeline_trigger_tokens(self):
        """List all Pipeline Trigger Tokens."""
        if not self.project:
            self.update_output("Please select a project first.")
            return

        try:
            triggers = self.project.triggers.list()
            if triggers:
                self.update_output(f"Listing pipeline trigger tokens for project '{self.project.name}':")
                for trigger in triggers:
                    self.update_output(f"ID: {trigger.id}, Description: {trigger.description}, Created At: {trigger.created_at}")
            else:
                self.update_output(f"No pipeline trigger tokens found for project '{self.project.name}'.")
        except gitlab.exceptions.GitlabGetError as e:
            self.update_output(f"Error listing pipeline trigger tokens: {e}")
        except Exception as e:
            self.update_output(f"Unexpected error listing pipeline trigger tokens: {e}")

    def delete_pipeline_trigger_token(self):
        """Delete an existing Pipeline Trigger Token."""
        if not self.project:
            self.update_output("Please select a project first.")
            return

        try:
            triggers = self.project.triggers.list()
            if not triggers:
                self.update_output(f"No pipeline trigger tokens found for project '{self.project.name}'.")
                return

            trigger_descs = [trigger.description for trigger in triggers]
            selected_trigger, ok_trigger = QInputDialog.getItem(
                self, "Delete Trigger Token", "Select Trigger Token to Delete:", trigger_descs, 0, False
            )
            
            if ok_trigger and selected_trigger:
                trigger_to_delete = next((trigger for trigger in triggers if trigger.description == selected_trigger), None)
                if trigger_to_delete:
                    trigger_to_delete.delete()
                    self.update_output(f"Pipeline trigger token '{selected_trigger}' deleted successfully.")
                else:
                    self.update_output("Error finding trigger token to delete.")
            else:
                self.update_output("Trigger token deletion canceled.")
        except gitlab.exceptions.GitlabGetError as e:
            self.update_output(f"Error deleting pipeline trigger token: {e}")
        except Exception as e:
            self.update_output(f"Unexpected error deleting pipeline trigger token: {e}")

    
    ####################################################################



    







    

    

    

    

    



    

    def change_theme(self):
        """Change application theme based on selection."""
        theme = self.theme_dropdown.currentText()
        
        if theme == "Dark":
            self.setStyleSheet("""
                QWidget { background-color: #2b2b2b; color: #ffffff; }
                QPushButton { background-color: #444444; color: #ffffff; }
                QLineEdit, QComboBox { background-color: #333333; color: #ffffff; }
            """)
            self.update_output("Theme changed to Dark.")
            self.notify_signal.emit("Theme Changed", "Theme changed to Dark.")
        
        elif theme == "Light":
            self.setStyleSheet("""
                QWidget { background-color: #ffffff; color: #000000; }
                QPushButton { background-color: #f0f0f0; color: #000000; }
                QLineEdit, QComboBox { background-color: #eaeaea; color: #000000; }
            """)
            self.update_output("Theme changed to Light.")
            self.notify_signal.emit("Theme Changed", "Theme changed to Light.")
        
        elif theme == "Solarized":
            self.setStyleSheet("""
                QWidget { background-color: #002b36; color: #839496; }
                QPushButton { background-color: #073642; color: #93a1a1; }
                QLineEdit, QComboBox { background-color: #073642; color: #93a1a1; }
            """)
            self.update_output("Theme changed to Solarized.")
            self.notify_signal.emit("Theme Changed", "Theme changed to Solarized.")
        
        elif theme == "High Contrast":
            self.setStyleSheet("""
                QWidget { background-color: #000000; color: #ffffff; }
                QPushButton { background-color: #ffffff; color: #000000; }
                QLineEdit, QComboBox { background-color: #ffffff; color: #000000; }
            """)
            self.update_output("Theme changed to High Contrast.")
            self.notify_signal.emit("Theme Changed", "Theme changed to High Contrast.")
        
        else:
            # Default theme (or reset)
            self.setStyleSheet("")
            self.update_output("Theme reset to default.")
            self.notify_signal.emit("Theme Changed", "Theme reset to default.")


    

