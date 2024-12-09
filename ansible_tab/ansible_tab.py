
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import threading
from datetime import datetime

if os.name == 'nt':
    import mock_fcntl
    sys.modules['fcntl'] = mock_fcntl

import ansible_runner
import requests
import yaml
from PyQt5.QtCore import (Q_ARG, QIODevice, QMetaObject, QObject, QProcess,
                          QRunnable, Qt, QThread, QThreadPool, pyqtSignal,
                          pyqtSlot)
from PyQt5.QtWidgets import (QApplication, QComboBox, QDialog, QFileDialog,
                             QGroupBox, QHBoxLayout, QInputDialog, QLabel,
                             QMessageBox, QPushButton, QSizePolicy, QTextEdit,
                             QVBoxLayout, QWidget)

from ansible_tab.utils import get_ansible_env_path

# Configure Logging for Audit Trails
logging.basicConfig(
    filename='ansible_audit.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class AnsiblePingWorker(QRunnable):
    def __init__(self, inventory, group, output_area):
        super().__init__()
        self.inventory = inventory
        self.group = group
        self.output_area = output_area

    @pyqtSlot()
    def run(self):
        """Run Ansible ping in a separate thread."""
        os.environ["ANSIBLE_HOST_KEY_CHECKING"] = "False"

        try:
            self.output_area.append(f"Running Ansible ping for group: {self.group} in inventory: {self.inventory}\n")

            # Run the Ansible ping command using ansible-runner
            r = ansible_runner.run(
                private_data_dir='.',  # Directory for ansible-runner to work with
                inventory=self.inventory,  # Path to the selected inventory file
                host_pattern=self.group,  # The selected group or 'all'
                module='ping',  # The Ansible ping module
                module_args='',  # No extra args needed for the ping module
                quiet=True,  # Set to True to ensure no terminal output
            )

            # Display the detailed results in the output area
            for event in r.events:
                # Capture the host name from the event, fallback to 'unknown'
                host = event.get('event_data', {}).get('host', 'unknown')

                if 'event_data' in event and 'res' in event['event_data']:
                    result = event['event_data']['res']
                    formatted_result = json.dumps(result, indent=4)
                    self.output_area.append(f"Host: {host}\nResult:\n{formatted_result}\n")

            if r.rc != 0:
                self.output_area.append(f"Ansible runner finished with errors. Return code: {r.rc}\n")
            else:
                self.output_area.append("Ansible ping completed successfully!\n")

        except Exception as e:
            self.output_area.append(f"Failed to run Ansible ping: {e}\n")

def run_ansible_ping(self):
    """Run Ansible ping command based on the selected inventory from the dropdown."""
    selected_inventory = self.output_inventory_dropdown.currentText()
    if selected_inventory == "Select" or not selected_inventory:
        self.output_area.append("No inventory selected. Please select an inventory.\n")
        return

    inventory_path = os.path.join(os.getcwd(), 'inventories', selected_inventory)
    if not os.path.exists(inventory_path):
        self.output_area.append(f"Inventory file not found: {inventory_path}\n")
        return

    selected_group = self.inventory_group_dropdown.currentText()
    if selected_group == "Select" or not selected_group:
        selected_group = "all"

    # Start the worker thread for running Ansible ping
    worker = AnsiblePingWorker(inventory=inventory_path, group=selected_group, output_area=self.output_area)
    self.thread_pool.start(worker)



class RoleInstallerThread(QThread):
    """Thread to install roles or collections asynchronously."""
    install_signal = pyqtSignal(str)

    def __init__(self, role_name, is_collection=False):
        super().__init__()
        self.role_name = role_name
        self.is_collection = is_collection

    def run(self):
        try:
            # Choose the correct command based on whether it's a role or collection
            command = ['ansible-galaxy', 'install', self.role_name]
            if self.is_collection:
                command = ['ansible-galaxy', 'collection', 'install', self.role_name]

            # Execute ansible-galaxy command to install the role or collection
            result = subprocess.run(command, capture_output=True, text=True)
            
            # Emit the result to the UI
            if result.returncode == 0:
                self.install_signal.emit(f"{'Collection' if self.is_collection else 'Role'} '{self.role_name}' installed successfully.")
            else:
                self.install_signal.emit(f"Error installing {'collection' if self.is_collection else 'role'} '{self.role_name}': {result.stderr}")
        except Exception as e:
            self.install_signal.emit(f"Unexpected error installing {'collection' if self.is_collection else 'role'} '{self.role_name}': {e}")




# Custom Logging Handler to Emit Signals
class QTextEditLogger(logging.Handler, QObject):
    log_signal = pyqtSignal(str)

    def __init__(self, parent=None):
        QObject.__init__(self)
        logging.Handler.__init__(self)

    def emit(self, record):
        msg = self.format(record)
        self.log_signal.emit(msg)


# Worker Signals for Threading
class WorkerSignals(QObject):
    log_signal = pyqtSignal(str)
    finished = pyqtSignal()


# Main Tab with Grouped Sections
class AnsibleTab(QWidget):
    def __init__(self, auth_manager, main_tab_widget):
        super().__init__()
        self.auth_manager = auth_manager
        self.main_tab_widget = main_tab_widget
        self.initUI()
        self.setup_logging()
        self.thread_pool = QThreadPool()

    def initUI(self):
        # Main Layout: Horizontal Layout with two columns
        main_layout = QHBoxLayout()

        # Left Column Layout: All Management Groups
        management_layout = QVBoxLayout()
        
        # Add the Back to System Button
        back_button = QPushButton("Back to System")
        back_button.clicked.connect(self.go_back_to_system)
        back_button.setFixedSize(120, 30)
        management_layout.addWidget(back_button)

        ######################
        # Inventory Management
        ######################
        inventory_group = QGroupBox("Inventory Management")
        inventory_layout = QVBoxLayout()

        # Horizontal Layout for "View Inventory Details" Label and Dropdown
        inventory_details_layout = QHBoxLayout()
        inventory_label = QLabel("View Inventory Details:")
        self.output_inventory_dropdown = QComboBox()
        self.output_inventory_dropdown.setToolTip("Select an inventory to view details.")

        
        

        inventory_details_layout.addWidget(inventory_label)
        inventory_details_layout.addWidget(self.output_inventory_dropdown)
        
        inventory_layout.addLayout(inventory_details_layout)  # Add horizontal layout to inventory group
        
        # Horizontal Layout for Inventory Group Dropdown
        inventory_group_layout = QHBoxLayout()
        self.inventory_group_label = QLabel("Select Inventory Group:")
        self.inventory_group_dropdown = QComboBox()
        self.inventory_group_dropdown.setToolTip("Select an inventory group.")

        inventory_group_layout.addWidget(self.inventory_group_label)
        inventory_group_layout.addWidget(self.inventory_group_dropdown)

        # Add the horizontal layout to inventory group
        inventory_layout.addLayout(inventory_group_layout)

        # Action Dropdown
        self.inventory_dropdown = QComboBox()
        self.inventory_dropdown.addItems(["Add Inventory", "Edit Inventory", "Delete Inventory", "Ping Inventory"])
        inventory_layout.addWidget(self.inventory_dropdown)

        # Execute Button
        self.inventory_execute_button = QPushButton("Execute")
        self.inventory_execute_button.clicked.connect(self.execute_inventory_action)
        inventory_layout.addWidget(self.inventory_execute_button)

        inventory_group.setLayout(inventory_layout)
        management_layout.addWidget(inventory_group)

        ######################
        # Playbook Management (similar to inventory section)
        ######################
        playbook_group = QGroupBox("Playbook Management")
        playbook_layout = QVBoxLayout()
        
        # Horizontal Layout for "Project Folder" Label and Dropdown
        project_details_layout = QHBoxLayout()
        project_label = QLabel("Select Project Folder:")
        self.project_dropdown = QComboBox()
        self.project_dropdown.setToolTip("Select a project folder.")
        self.project_dropdown.currentIndexChanged.connect(self.load_playbooks_from_project)
        
        project_details_layout.addWidget(project_label)
        project_details_layout.addWidget(self.project_dropdown)
        playbook_layout.addLayout(project_details_layout)

        # Horizontal Layout for "View Playbook Details" Label and Dropdown
        playbook_details_layout = QHBoxLayout()
        playbook_label = QLabel("View Playbook Details:")
        self.output_playbook_dropdown = QComboBox()
        self.output_playbook_dropdown.setToolTip("Select a playbook to view details.")

        

        playbook_details_layout.addWidget(playbook_label)
        playbook_details_layout.addWidget(self.output_playbook_dropdown)

        playbook_layout.addLayout(playbook_details_layout)  # Add horizontal layout to playbook group

        # Action Dropdown
        self.playbook_dropdown = QComboBox()
        self.playbook_dropdown.addItems(["Create Project Folder","Add Playbook", "Delete Playbook", "Execute Playbook", "Upload Project"])
        playbook_layout.addWidget(self.playbook_dropdown)

        # Execute Button
        self.playbook_execute_button = QPushButton("Execute")
        self.playbook_execute_button.clicked.connect(self.execute_playbook_action)
        playbook_layout.addWidget(self.playbook_execute_button)

        playbook_group.setLayout(playbook_layout)
        management_layout.addWidget(playbook_group)
        
        ##################
        # Inventory + Configuration Management (Ansible + Terraform)
        ##################

        config_group = QGroupBox("Inventory + Configuration Management")
        config_layout = QVBoxLayout()

        # Horizontal Layout for "Project Folder" Label and Dropdown
        project_details_config_layout = QHBoxLayout()
        project_config_label = QLabel("Select Project Folder:")
        self.config_project_dropdown = QComboBox()
        self.config_project_dropdown.setToolTip("Select a project folder for Ansible or Terraform.")
        self.config_project_dropdown.currentIndexChanged.connect(self.update_config_details)  # Update config details on selection change

        project_details_config_layout.addWidget(project_config_label)
        project_details_config_layout.addWidget(self.config_project_dropdown)
        config_layout.addLayout(project_details_config_layout)

        # Horizontal Layout for "View Configuration Details" Label and Dropdown
        config_details_layout = QHBoxLayout()
        config_label = QLabel("View Configuration Details:")
        self.output_config_dropdown = QComboBox()
        self.output_config_dropdown.setToolTip("Select a configuration (Playbook or Terraform) to view details.")

        config_details_layout.addWidget(config_label)
        config_details_layout.addWidget(self.output_config_dropdown)

        config_layout.addLayout(config_details_layout)  # Add horizontal layout to configuration group

        # Action Dropdown
        self.config_action_dropdown = QComboBox()
        self.config_action_dropdown.addItems(["Create Project Folder", "Upload Project", "Add Configuration", "Plan Configuration", "Execute Configuration", "Generate Private Key",  "Destroy Configuration", "Delete Configuration"])
        config_layout.addWidget(self.config_action_dropdown)

        # Execute Button
        self.config_execute_button = QPushButton("Execute")
        self.config_execute_button.clicked.connect(self.execute_config_action)
        config_layout.addWidget(self.config_execute_button)

        config_group.setLayout(config_layout)
        management_layout.addWidget(config_group)


        

        ######################
        # Role Management
        ######################
        role_group = QGroupBox("Role Management")
        role_layout = QVBoxLayout()

        # Create a horizontal layout for the dropdown and button
        role_horizontal_layout = QHBoxLayout()

        self.role_dropdown = QComboBox()
        self.role_dropdown.addItems(["Install Role from Galaxy", "Delete Role", "List Roles"])
        role_horizontal_layout.addWidget(self.role_dropdown)

        self.role_execute_button = QPushButton("Execute")
        self.role_execute_button.clicked.connect(self.execute_role_action)
        role_horizontal_layout.addWidget(self.role_execute_button)

        # Add the horizontal layout to the role layout
        role_layout.addLayout(role_horizontal_layout)

        role_group.setLayout(role_layout)
        management_layout.addWidget(role_group)


        

        # Add Management Layout to Main Layout (left column)
        main_layout.addLayout(management_layout, 1)  # Stretch factor set to 1 for 50% width

        ######################
        # Output & Details
        ######################
        right_column = QVBoxLayout()

        self.output_area = QTextEdit(self)
        self.output_area.setReadOnly(True)

        right_column.addWidget(QLabel("Ansible Action Output:"))
        right_column.addWidget(self.output_area)

        # Add Output Layout to Main Layout (right column)
        main_layout.addLayout(right_column, 1)  # Stretch factor set to 1 for 50% width

        # Set Main Layout
        self.setLayout(main_layout)

        # Initialize Dropdowns
        self.load_initial_data()
        
        # Now we call the method to load the inventories after output_area is defined
        self.load_inventories_into_output()
        
        # Load the inventories and display them in the host dropdown
        self.load_inventory_groups()
        
        # Load playbooks into the dropdown
        self.load_playbooks_into_output()
        
        # Load the projects into the dropdown
        self.load_project_folders()
        
        # Call function to load project folders when the UI is initialized
        self.load_configs_from_folder()
        
    
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
        
        



    def setup_logging(self):
        # Set up custom logger
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.INFO)

        # Create QTextEditLogger and connect its signal
        self.text_edit_logger = QTextEditLogger()
        self.text_edit_logger.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.text_edit_logger.log_signal.connect(self.append_log)
        self.logger.addHandler(self.text_edit_logger)

    @pyqtSlot(str)
    def append_log(self, message):
        """Append log message to the output display."""
        self.output_area.append(message)
        
    

    def load_initial_data(self):
        """Load inventories and playbooks into the output dropdowns."""
        self.load_inventories_into_output()
        self.load_playbooks_into_output()

    def load_inventories_into_output(self):
        """Load inventories into the output inventory dropdown using a background thread."""

        # Define the worker class to handle inventory loading in the background
        class LoadInventoryWorker(QRunnable):
            def __init__(self, inventories_func, callback):
                super().__init__()
                self.inventories_func = inventories_func
                self.callback = callback

            @pyqtSlot()
            def run(self):
                """Background process to load inventories."""
                inventories = self.inventories_func()  # Call the function to get inventories
                self.callback(inventories)

        # Function to update the inventory dropdown in the main thread
        def update_inventory_dropdown(inventories):
            """Update the UI with the loaded inventories (executed in the main thread)."""
            self.output_inventory_dropdown.clear()  # Clear current items
            if inventories:
                # Populate dropdown with inventory files
                self.output_inventory_dropdown.addItems(inventories)
            else:
                # If no inventories are found
                self.output_inventory_dropdown.addItem("No Inventory Found")
                self.output_area.append("No inventory found.")

        # Start the worker to load inventories in a separate thread
        worker = LoadInventoryWorker(self.get_inventory_files, update_inventory_dropdown)
        self.thread_pool = QThreadPool()
        self.thread_pool.start(worker)


            
    def load_inventory_groups(self):
        """Load inventory group names into the dropdown from the inventory file."""
        inventories = self.get_inventory_files()
        
        self.inventory_group_dropdown.clear()  # Clear any previous entries
        
        # Add the "Select" option first
        self.inventory_group_dropdown.addItem("Select")

        group_names = set()  # Use a set to store unique group names

        if inventories:
            for inventory in inventories:
                inventory_path = os.path.join("inventories", inventory)
                try:
                    with open(inventory_path, 'r') as file:
                        lines = file.readlines()
                        for line in lines:
                            # Check if the line starts with '[' indicating a group and exclude ':vars'
                            if line.startswith("[") and "]" in line:
                                group = line.strip()[1:-1]  # Remove the brackets [ ] from the group name
                                if ':vars' not in group:  # Exclude groups that have ":vars"
                                    group_names.add(group)
                except Exception as e:
                    logging.error(f"Error reading inventory file {inventory}: {e}")

            # Ensure "all" is always included and appears first if available
            if "all" in group_names:
                group_names.remove("all")
                self.inventory_group_dropdown.addItem("all")

            # Add other groups sorted alphabetically
            for group in sorted(group_names):
                self.inventory_group_dropdown.addItem(group)
        else:
            self.inventory_group_dropdown.addItem("No Inventory Found")





    

    ######################
    # Inventory Management
    ######################

    def execute_inventory_action(self):
        """Execute the selected inventory action."""
        action = self.inventory_dropdown.currentText()
        if action == "Add Inventory":
            self.add_inventory()
        elif action == "Edit Inventory":
            self.edit_inventory()
        elif action == "Delete Inventory":
            self.delete_inventory()
        elif action == "Ping Inventory":
            self.run_ansible_ping()

    def add_inventory(self):
        """Add a new inventory."""
        inventory_name, ok = QInputDialog.getText(self, "Add Inventory", "Enter inventory name:")
        
        if ok and inventory_name:
            # Automatically construct the inventory path using the provided name
            inventory_dir = "inventories/"
            inventory_extension = ".ini"  # Default extension, can be changed if needed
            inventory_path = os.path.join(inventory_dir, f"{inventory_name}{inventory_extension}")
            
            try:
                # Ensure the directory exists
                os.makedirs(inventory_dir, exist_ok=True)
                
                # Write the default inventory template to the constructed path
                with open(inventory_path, 'w') as f:
                    # Default inventory template
                    f.write("[all]\nlocalhost ansible_connection=local\n")
                
                logging.info(f"Inventory '{inventory_name}' added successfully.")
                self.load_inventories_into_output()
            except Exception as e:
                logging.error(f"Failed to add inventory: {e}")
                QMessageBox.critical(self, "Error", f"Failed to add inventory: {e}")


    def edit_inventory(self):
        """Edit the selected inventory."""
        inventories = self.get_inventory_files()
        if not inventories:
            QMessageBox.warning(self, "Warning", "No inventories available to edit.")
            return
        inventory_name, ok = QInputDialog.getItem(
            self, "Edit Inventory", "Select inventory to edit:", inventories, 0, False
        )
        if ok and inventory_name:
            inventory_path = os.path.join("inventories", inventory_name)
            try:
                with open(inventory_path, 'r') as f:
                    content = f.read()
                # Open a dialog with a text editor
                dialog = QDialog(self)
                dialog.setWindowTitle(f"Edit Inventory: {inventory_name}")
                dialog.resize(600, 400)
                dialog_layout = QVBoxLayout(dialog)

                editor = QTextEdit()
                editor.setPlainText(content)
                editor.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
                dialog_layout.addWidget(editor)

                button_box = QHBoxLayout()
                save_button = QPushButton("Save")
                cancel_button = QPushButton("Cancel")
                button_box.addWidget(save_button)
                button_box.addWidget(cancel_button)
                dialog_layout.addLayout(button_box)

                save_button.clicked.connect(dialog.accept)
                cancel_button.clicked.connect(dialog.reject)

                if dialog.exec_() == QDialog.Accepted:
                    new_content = editor.toPlainText()
                    with open(inventory_path, 'w') as f:
                        f.write(new_content)
                    logging.info(f"Inventory '{inventory_name}' updated successfully.")
                    self.load_inventories_into_output()
            except Exception as e:
                logging.error(f"Failed to edit inventory: {e}")
                QMessageBox.critical(self, "Error", f"Failed to edit inventory: {e}")

    def delete_inventory(self):
        """Delete the selected inventory."""
        inventories = self.get_inventory_files()
        if not inventories:
            QMessageBox.warning(self, "Warning", "No inventories available to delete.")
            return
        inventory_name, ok = QInputDialog.getItem(
            self, "Delete Inventory", "Select inventory to delete:", inventories, 0, False
        )
        if ok and inventory_name:
            reply = QMessageBox.question(
                self, 'Confirm Delete',
                f"Are you sure you want to delete inventory '{inventory_name}'?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                inventory_path = os.path.join("inventories", inventory_name)
                try:
                    os.remove(inventory_path)
                    logging.info(f"Inventory '{inventory_name}' deleted successfully.")
                    self.load_inventories_into_output()
                except Exception as e:
                    logging.error(f"Failed to delete inventory: {e}")
                    QMessageBox.critical(self, "Error", f"Failed to delete inventory: {e}")
                    

    def run_ansible_ping(self):
        """Run Ansible ping command based on the selected inventory from the dropdown."""
        selected_inventory = self.output_inventory_dropdown.currentText()
        if selected_inventory == "Select" or not selected_inventory:
            self.output_area.append("No inventory selected. Please select an inventory.\n")
            return

        inventory_path = os.path.join(os.getcwd(), 'inventories', selected_inventory)
        if not os.path.exists(inventory_path):
            self.output_area.append(f"Inventory file not found: {inventory_path}\n")
            return

        selected_group = self.inventory_group_dropdown.currentText()
        if selected_group == "Select" or not selected_group:
            selected_group = "all"

        # Start the worker thread for running Ansible ping
        worker = AnsiblePingWorker(inventory=inventory_path, group=selected_group, output_area=self.output_area)
        self.thread_pool.start(worker)


    def get_inventory_files(self):
        """Retrieve a list of Ansible inventory files from a predefined directory."""
        inventory_dir = "inventories"
        try:
            if not os.path.exists(inventory_dir):
                os.makedirs(inventory_dir)
            inventory_files = [f for f in os.listdir(inventory_dir)
                               if os.path.isfile(os.path.join(inventory_dir, f))]
            return inventory_files
        except Exception as e:
            logging.error(f"Error accessing inventory directory: {e}")
            return []

    ######################
    # Playbook Execution
    ######################
    
    def load_playbooks_into_output(self):
        """Load playbooks into the output playbook dropdown based on the selected project."""
        
        # Block signals while updating the dropdown to prevent unwanted triggering
        self.output_playbook_dropdown.blockSignals(True)
        self.output_playbook_dropdown.clear()
        self.output_playbook_dropdown.addItem("Select Playbook")

        # Get the selected project folder from the project dropdown
        selected_project = self.project_dropdown.currentText()
        
        if not selected_project or selected_project == "No Projects Found":
            #self.output_area.append("No project selected. Please create or select a project.\n")
            self.output_playbook_dropdown.addItem("No Playbooks Found")
            self.output_playbook_dropdown.blockSignals(False)
            return

        # Retrieve the list of playbooks in the selected project folder
        playbooks = self.get_playbook_files(selected_project)

        # Add the playbooks to the playbook dropdown
        if playbooks:
            self.output_playbook_dropdown.addItems(playbooks)
        else:
            self.output_playbook_dropdown.addItem("No Playbooks Found")
        
        # Unblock signals after the update
        self.output_playbook_dropdown.blockSignals(False)
    
    

    def execute_playbook_action(self):
        """Execute the selected playbook action."""
        action = self.playbook_dropdown.currentText()
        if action == "Add Playbook":
            self.add_playbook()
        elif action == "Delete Playbook":
            self.delete_playbook()
        elif action == "Execute Playbook":
            self.execute_playbook()
        elif action == "Upload Project":
            self.upload_project_folder()
        elif action == "Create Project Folder":
            self.create_project_folder()
    


    def add_playbook(self):
        """Add a new playbook to an existing project folder selected from the dropdown."""
        
        # Prompt the user to enter the playbook name
        playbook_name, ok = QInputDialog.getText(self, "Add Playbook", "Enter playbook name:")
        
        if not ok or not playbook_name:
            self.output_area.append("No playbook name provided.\n")
            return
        
        # Ensure the playbook name ends with .yml or .yaml
        if not playbook_name.endswith(('.yml', '.yaml')):
            playbook_name += '.yml'

        # Get the selected project from the project dropdown
        selected_project = self.project_dropdown.currentText()

        # Check if a project is selected
        if not selected_project or selected_project == "No Projects Found":
            self.output_area.append("No project selected. Please select or create a project.\n")
            return

        # Define the project folder path and the playbook path within the selected project folder
        project_folder = os.path.join(os.getcwd(), 'playbooks', selected_project)
        playbook_path = os.path.join(project_folder, playbook_name)

        # Ensure the project folder exists
        if not os.path.exists(project_folder):
            self.output_area.append(f"Project folder '{selected_project}' not found.\n")
            return

        try:
            # Write the new playbook file in the selected project folder
            with open(playbook_path, 'w') as f:
                playbook_content = (
                    f"---\n"
                    f"- hosts: all\n"  # Using 'all' to target all hosts in the hosts file
                    f"  tasks:\n"
                    f"    - name: Example task\n"
                    f"      debug:\n"
                    f"        msg: 'Hello World'\n"
                )
                f.write(playbook_content)

            # Log success and inform the user
            logging.info(f"Playbook '{playbook_name}' added successfully to project '{selected_project}'.")
            self.output_area.append(f"Playbook '{playbook_name}' added to project '{selected_project}'.\n")

            # Reload the playbooks in the UI
            self.load_playbooks_into_output()

        except Exception as e:
            logging.error(f"Failed to add playbook to project '{selected_project}': {e}")
            self.output_area.append(f"Failed to add playbook: {e}\n")
            QMessageBox.critical(self, "Error", f"Failed to add playbook: {e}")





    def delete_playbook(self):
        """Delete the selected playbook."""
        # Get the selected project folder from the project dropdown
        selected_project = self.project_dropdown.currentText()
        playbooks = self.get_playbook_files(selected_project)
        if not playbooks:
            QMessageBox.warning(self, "Warning", "No playbooks available to delete.")
            return
        playbook_name, ok = QInputDialog.getItem(
            self, "Delete Playbook", "Select playbook to delete:", playbooks, 0, False
        )
        if ok and playbook_name:
            reply = QMessageBox.question(
                self, 'Confirm Delete',
                f"Are you sure you want to delete playbook '{playbook_name}'?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                playbook_path = os.path.join("playbooks", playbook_name)
                try:
                    os.remove(playbook_path)
                    logging.info(f"Playbook '{playbook_name}' deleted successfully.")
                    self.load_playbooks_into_output()
                except Exception as e:
                    logging.error(f"Failed to delete playbook: {e}")
                    QMessageBox.critical(self, "Error", f"Failed to delete playbook: {e}")

    def execute_playbook(self):
        """Execute the selected playbook from the selected project folder with the selected inventory."""
        
        # Get the selected project from the project dropdown
        selected_project = self.project_dropdown.currentText()

        if not selected_project or selected_project == "No Projects Found":
            QMessageBox.warning(self, "Warning", "No project selected.")
            return

        # Get the selected playbook from the playbook dropdown
        selected_playbook = self.output_playbook_dropdown.currentText()
        if not selected_playbook or selected_playbook == "Select Playbook":
            QMessageBox.warning(self, "Warning", "No playbook selected.")
            return

        # Define the path to the selected playbook in the project folder
        playbook_path = os.path.join(os.getcwd(), 'playbooks', selected_project, selected_playbook)

        # Get the selected inventory from the inventory dropdown
        selected_inventory = self.output_inventory_dropdown.currentText()
        if not selected_inventory or selected_inventory == "Select":
            QMessageBox.warning(self, "Warning", "No inventory selected.")
            return

        # Define the path to the selected inventory file
        inventory_path = os.path.join(os.getcwd(), 'inventories', selected_inventory)

        # Execute Playbook in a Separate Thread
        thread = threading.Thread(
            target=self.run_playbook, args=(playbook_path, inventory_path, selected_playbook),
            daemon=True
        )
        thread.start()

    def run_playbook(self, playbook_path, inventory_path, playbook_name):
        """Run the Ansible playbook using ansible-runner and format output similar to terminal."""
        logging.info(f"Starting playbook '{playbook_name}' with inventory '{inventory_path}'")
        self.output_area.append(f"PLAY [{playbook_name}] ****************************************************\n")

        try:
            r = ansible_runner.run(
                private_data_dir='.',  # Directory for ansible-runner to work with
                playbook=playbook_path,  # Path to the playbook file
                inventory=inventory_path,  # Path to the inventory file
                quiet=False,  # Set to False to see logs and output in real-time
                
            )

            task_results = {}
            play_recap = {}

            # Process the events to extract and format task information
            for event in r.events:
                event_type = event.get('event')
                if event_type in ['runner_on_ok', 'runner_on_failed', 'runner_on_unreachable']:
                    host = event['event_data'].get('host', 'unknown')
                    task_name = event['event_data'].get('task', 'Unnamed task')
                    result = event['event_data']['res']
                    status = 'ok' if event_type == 'runner_on_ok' else 'failed' if event_type == 'runner_on_failed' else 'unreachable'

                    # Track task results
                    if host not in task_results:
                        task_results[host] = []
                    task_results[host].append((task_name, status))

                    # Track recap information for play recap
                    if host not in play_recap:
                        play_recap[host] = {"ok": 0, "failed": 0, "unreachable": 0}
                    if status == "ok":
                        play_recap[host]["ok"] += 1
                    elif status == "failed":
                        play_recap[host]["failed"] += 1
                    elif status == "unreachable":
                        play_recap[host]["unreachable"] += 1

                    # Format task output
                    self.output_area.append(f"TASK [{task_name}] *********************************************************\n")
                    self.output_area.append(f"{status}: [{host}]\n")

            # After task processing, print the play recap
            self.output_area.append("\nPLAY RECAP *********************************************************************\n")
            for host, recap in play_recap.items():
                self.output_area.append(
                    f"{host} : ok={recap['ok']}    failed={recap['failed']}    unreachable={recap['unreachable']}\n"
                )

            if r.rc != 0:
                self.output_area.append(f"\nStatus: FAILED\n")
            else:
                self.output_area.append(f"\nStatus: SUCCESS\n")

        except Exception as e:
            self.output_area.append(f"Failed to run Ansible playbook: {e}\n")
            logging.error(f"Error running playbook '{playbook_name}': {e}")

            
    def load_project_folders(self):
        """Load all project folders from the 'playbooks' directory into the project dropdown, excluding '_inventory' folders."""
        playbook_dir = "playbooks"  # Load from the playbooks directory
        self.project_dropdown.clear()  # Clear existing entries

        try:
            if not os.path.exists(playbook_dir):
                os.makedirs(playbook_dir)

            # Get the list of directories inside 'playbooks' excluding folders with '_inventory'
            project_folders = [f for f in os.listdir(playbook_dir) 
                            if os.path.isdir(os.path.join(playbook_dir, f)) and '_inventory' not in f]
            
            if project_folders:
                self.project_dropdown.addItems(project_folders)
            else:
                self.project_dropdown.addItem("No Projects Found")

        except Exception as e:
            logging.error(f"Error loading project folders: {e}")
            self.output_area.append(f"Error loading project folders: {e}\n")


            
    def upload_project_folder(self):
        """Upload a new project folder into the 'playbooks' directory with an option to add a template."""
        
        # Open a dialog for the user to select the folder to upload
        project_folder = QFileDialog.getExistingDirectory(self, "Select Project Folder to Upload")
        
        if not project_folder:
            self.output_area.append("No folder selected for upload.\n")
            return
        
        # Define the destination path for the 'playbooks' directory
        playbook_dir = os.path.join(os.getcwd(), 'playbooks')
        
        # Ensure the 'playbooks' directory exists, if not, create it
        if not os.path.exists(playbook_dir):
            os.makedirs(playbook_dir)
            self.output_area.append(f"Created playbook directory: {playbook_dir}\n")
        
        # Get the folder name of the selected project
        folder_name = os.path.basename(project_folder)
        
        # Destination path within the 'playbooks' directory
        destination_path = os.path.join(playbook_dir, folder_name)
        
        try:
            # Copy the selected folder to the 'playbooks' directory
            shutil.copytree(project_folder, destination_path, dirs_exist_ok=True)
            self.output_area.append(f"Project folder '{folder_name}' uploaded to '{playbook_dir}'.\n")
            logging.info(f"Project folder '{folder_name}' uploaded to '{playbook_dir}'.")

            # Ask the user if they want to add a template to the uploaded folder
            add_template, ok = QInputDialog.getItem(
                self,
                "Add Template",
                "Do you want to add a template to this project?",
                ["Yes", "No"],
                0,
                False
            )
            
            if ok and add_template == "Yes":
                # Prompt the user to choose the project type (e.g., Node, Docker, Nexus, K8s)
                project_type, ok = QInputDialog.getItem(
                    self,
                    "Select Project Type",
                    "Choose the project type:",
                    ["Node", "Docker", "Nexus", "K8s"],
                    0,
                    False
                )

                if ok:
                    # Proceed to add the appropriate template files to the folder
                    self.add_template_to_project(project_type, destination_path)
                else:
                    self.output_area.append("No project type selected, skipping template addition.\n")
                    
            # Load the newly created project folder into the project dropdown
            self.load_project_folders()
            
        except Exception as e:
            self.output_area.append(f"Failed to upload project folder: {e}\n")
            logging.error(f"Error uploading project folder '{folder_name}': {e}")

    def add_template_to_project(self, project_type, project_folder):
        """Add template files, configuration files, and hosts file to the project folder based on the selected project type."""
        
        templates_dir = os.path.join(os.getcwd(), 'ansible_tab', 'templates')

        try:
            # Copy the necessary files based on the project type
            if project_type == "Node":
                shutil.copy(os.path.join(templates_dir, 'node_project-vars.yml'), project_folder)
                shutil.copy(os.path.join(templates_dir, 'deploy-node.yaml'), project_folder)
                self.output_area.append("Node project templates added.\n")
            
            elif project_type == "Docker":
                shutil.copy(os.path.join(templates_dir, 'docker_project-vars.yml'), project_folder)
                shutil.copy(os.path.join(templates_dir, 'deploy-docker.yaml'), project_folder)
                self.output_area.append("Docker project templates added.\n")
            
            elif project_type == "Nexus":
                shutil.copy(os.path.join(templates_dir, 'nexus_project-vars.yml'), project_folder)
                shutil.copy(os.path.join(templates_dir, 'deploy-nexus.yaml'), project_folder)
                self.output_area.append("Nexus project templates added.\n")
            
            elif project_type == "K8s":
                shutil.copy(os.path.join(templates_dir, 'k8s_project-vars.yml'), project_folder)
                shutil.copy(os.path.join(templates_dir, 'deploy-k8s.yaml'), project_folder)
                self.output_area.append("K8s project templates added.\n")

            # Copy the ansible.cfg file to the project folder
            self.create_ansible_cfg(project_folder)
            
            # Generate the hosts file based on the selected inventory
            self.create_hosts_file(project_folder)

            logging.info(f"All config and template files for '{project_type}' added to project folder '{project_folder}'.")

        except Exception as e:
            self.output_area.append(f"Failed to copy project files: {e}\n")
            logging.error(f"Failed to copy project files: {e}")




    def create_project_folder(self):
        """Create a new project folder inside the 'playbooks' directory based on the selected project type."""
        
        # Prompt the user to enter a project name
        project_name, ok = QInputDialog.getText(self, "Create Project Folder", "Enter project folder name:")
        
        if not ok or not project_name:
            self.output_area.append("No project name provided.\n") 
            return
        
        # Prompt the user to select the project type: Node, Docker, Nexus, K8s, or Clean Project
        project_type, ok = QInputDialog.getItem(
            self,
            "Select Project Type",
            "Choose the project type:",
            ["Node", "Docker", "Nexus", "K8s", "Clean Project"],
            0,
            False
        )
        
        if not ok or not project_type:
            self.output_area.append("No project type selected.\n")
            return
        
        # Define the path for the 'playbooks' directory
        playbook_dir = os.path.join(os.getcwd(), 'playbooks')
        
        # Ensure the 'playbooks' directory exists, if not, create it
        if not os.path.exists(playbook_dir):
            os.makedirs(playbook_dir)
            self.output_area.append(f"Created playbook directory: {playbook_dir}\n")
        
        # Define the new project folder path
        project_folder_path = os.path.join(playbook_dir, project_name)
        
        try:
            # Create the project folder inside 'playbooks'
            os.makedirs(project_folder_path, exist_ok=True)
            self.output_area.append(f"Project folder '{project_name}' created in '{playbook_dir}'.\n")
            logging.info(f"Project folder '{project_name}' created in '{playbook_dir}'.")

            # Update template directory path to the correct one
            template_dir = os.path.join(os.getcwd(), 'ansible_tab', 'templates')

            # Handle different project types
            if project_type == "Node":
                self.copy_project_files(template_dir, project_folder_path, 
                                        "node_project-vars.yml", "deploy-node.yaml", "ansible.cfg")
            elif project_type == "Docker":
                self.copy_project_files(template_dir, project_folder_path, 
                                        "docker_project-vars.yml", "deploy-docker.yaml", "ansible.cfg")
            elif project_type == "Nexus":
                self.copy_project_files(template_dir, project_folder_path, 
                                        "nexus_project-vars.yml", "deploy-nexus.yaml", "ansible.cfg")
            elif project_type == "K8s":
                self.copy_project_files(template_dir, project_folder_path, 
                                        "k8s-project-vars.yml", "kubernetes_cluster_ubuntu.yml", "ansible.cfg")
            elif project_type == "Clean Project":
                self.output_area.append(f"Clean project folder '{project_name}' created. Only the 'hosts' file will be generated.\n")
                logging.info(f"Clean project folder '{project_name}' created.")
                
            # Generate the hosts file using the existing create_hosts_file method
            self.create_hosts_file(project_folder_path)

            # Load the newly created project folder into the project dropdown
            self.load_project_folders()

        except Exception as e:
            self.output_area.append(f"Failed to create project folder: {e}\n")
            logging.error(f"Error creating project folder '{project_name}': {e}")




    def copy_project_files(self, template_dir, project_folder, vars_file, deploy_file, ansible_cfg):
        """Helper function to copy necessary files from templates to the project folder."""
        
        try:
            # Copy project variables file
            vars_file_path = os.path.join(template_dir, vars_file)
            shutil.copy(vars_file_path, os.path.join(project_folder, vars_file))
            self.output_area.append(f"Copied {vars_file} to project folder.\n")
            
            # Copy deploy YAML file
            deploy_file_path = os.path.join(template_dir, deploy_file)
            shutil.copy(deploy_file_path, os.path.join(project_folder, deploy_file))
            self.output_area.append(f"Copied {deploy_file} to project folder.\n")
            
            # Copy ansible.cfg file
            ansible_cfg_path = os.path.join(template_dir, ansible_cfg)
            shutil.copy(ansible_cfg_path, os.path.join(project_folder, ansible_cfg))
            self.output_area.append(f"Copied {ansible_cfg} to project folder.\n")

        except Exception as e:
            self.output_area.append(f"Error copying project files: {e}\n")
            logging.error(f"Failed to copy project files: {e}")





            
    def load_playbooks_from_project(self):
        """Load playbooks from the selected project folder inside the 'playbooks' directory."""
        
        # Get the selected project from the project dropdown
        selected_project = self.project_dropdown.currentText()
        
        if not selected_project or selected_project == "No Projects Found":
            #self.output_area.append("No project selected. Please select a project.\n")
            return

        # Define the project path inside the 'playbooks' directory
        project_path = os.path.join(os.getcwd(), 'playbooks', selected_project)

        try:
            # Check if the project path exists, if not, show an error message
            if not os.path.exists(project_path):
                self.output_area.append(f"Project folder not found: {project_path}\n")
                return

            # List all playbook YAML files, excluding any files that contain 'vars'
            playbook_files = [f for f in os.listdir(project_path) 
                            if f.endswith(('.yml', '.yaml')) and 'vars' not in f]

            if playbook_files:
                # Update the playbook dropdown with available playbooks
                self.output_playbook_dropdown.clear()
                self.output_playbook_dropdown.addItems(playbook_files)
            else:
                self.output_playbook_dropdown.clear()
                self.output_playbook_dropdown.addItem("No Playbooks Found")
                self.output_area.append(f"No playbooks found in project: {selected_project}\n")

        except Exception as e:
            logging.error(f"Error loading playbooks from project '{selected_project}': {e}")
            self.output_area.append(f"Error loading playbooks from project '{selected_project}': {e}\n")


    def get_playbook_files(self, selected_project):
        """Retrieve a list of Ansible playbook files from the selected project folder inside the 'playbooks' directory."""
        playbook_dir = os.path.join(os.getcwd(), 'playbooks', selected_project)  # Path to 'playbooks' folder

        try:
            # Ensure the directory exists before listing its contents
            if not os.path.exists(playbook_dir):
                self.output_area.append(f"Project folder not found: {playbook_dir}\n")
                return []

            # List all playbook YAML files, excluding any files that contain 'vars'
            playbook_files = [f for f in os.listdir(playbook_dir) 
                            if f.endswith(('.yml', '.yaml')) and 'vars' not in f]
            
            return playbook_files

        except Exception as e:
            logging.error(f"Error accessing playbook directory for project '{selected_project}': {e}")
            self.output_area.append(f"Error accessing playbook directory for project '{selected_project}': {e}\n")
            return []



        
    def create_ansible_cfg(self, project_folder):
        """Create ansible.cfg file inside the project folder with host_key_checking set to False."""
        cfg_path = os.path.join(project_folder, 'ansible.cfg')
        
        # Check if ansible.cfg already exists, and only create if it doesn't
        if not os.path.exists(cfg_path):
            try:
                with open(cfg_path, 'w') as cfg_file:
                    cfg_file.write("[defaults]\n")
                    cfg_file.write("host_key_checking = False\n")
                    logging.info("Created ansible.cfg with host_key_checking = False inside project folder.")
            except Exception as e:
                logging.error(f"Failed to create ansible.cfg: {e}")
                self.output_area.append(f"Failed to create ansible.cfg in project: {e}\n")
                
    def create_hosts_file(self, project_folder):
        """Create a default hosts file in the project folder using selected inventory."""
        
        # Get the selected inventory from the dropdown
        selected_inventory = self.output_inventory_dropdown.currentText()
        if not selected_inventory or selected_inventory == "Select":
            self.output_area.append("No inventory selected to create hosts file.\n")
            return
        
        # Define inventory and project host path
        inventory_path = os.path.join(os.getcwd(), 'inventories', selected_inventory)
        project_host_path = os.path.join(project_folder, 'hosts')

        try:
            # Copy the selected inventory file to the 'hosts' file inside the project folder
            shutil.copy(inventory_path, project_host_path)
            self.output_area.append(f"Copied inventory '{selected_inventory}' to project hosts file in '{project_folder}'.\n")
            logging.info(f"Copied inventory '{selected_inventory}' to project hosts file in '{project_folder}'.")

        except Exception as e:
            self.output_area.append(f"Failed to copy hosts file: {e}\n")
            logging.error(f"Error copying hosts file to '{project_folder}': {e}")

    ##################
    # Inventory + Configuration Management (Ansible + Terraform)
    ##################
    
    def execute_config_action(self):
        """Execute the selected playbook action."""
        action = self.config_action_dropdown.currentText()
        if action == "Add Configuration":
            self.add_configuration()
        elif action == "Delete Configuration":
            self.delete_project_folder()
        elif action == "Execute Configuration":
            self.execute_configuration()
        elif action == "Upload Project":
            self.upload_project_folder_for_config()
        elif action == "Create Project Folder":
            self.create_project_folder_for_config()
        elif action == "Destroy Configuration":
            self.destroy_configuration()
        elif action == "Plan Configuration":
            self.plan_configuration()
        elif action == "Generate Private Key":
            self.generate_private_key_for_access()
            
            
    
            
    def load_configs_from_folder(self):
        """Load only the folders with '_inventory' in their names into the management dropdown."""
        playbook_dir = os.path.join(os.getcwd(), 'playbooks')
        self.config_project_dropdown.clear()

        try:
            # Ensure the 'playbooks' directory exists
            if not os.path.exists(playbook_dir):
                os.makedirs(playbook_dir)
                self.output_area.append(f"Created playbook directory: {playbook_dir}\n")
                return

            # List directories with '_inventory' in the name
            project_folders = [f for f in os.listdir(playbook_dir) if os.path.isdir(os.path.join(playbook_dir, f)) and '_inventory' in f]

            if project_folders:
                self.config_project_dropdown.addItems(project_folders)
                #self.output_area.append(f"Loaded projects: {', '.join(project_folders)}\n")
            else:
                self.config_project_dropdown.addItem("No Projects Found")
                self.output_area.append("No project folders with '_inventory' found.\n")

        except Exception as e:
            self.output_area.append(f"Error loading project folders: {e}\n")
            logging.error(f"Error loading project folders: {e}")

    def update_config_details(self):
        """Update configuration details dropdown when a new project is selected, load .tf files."""
        selected_project = self.config_project_dropdown.currentText()

        # Ensure a project is selected and it's not the default "No Projects Found"
        if selected_project and selected_project != "No Projects Found":
            # Define the project path inside the 'playbooks' directory
            project_path = os.path.join(os.getcwd(), 'playbooks', selected_project)

            # Clear the configuration details dropdown
            self.output_config_dropdown.clear()

            try:
                # Check if the project path exists
                if os.path.exists(project_path):
                    # List all .tf files in the selected project's folder
                    tf_files = [f for f in os.listdir(project_path) if f.endswith('.tf')]

                    if tf_files:
                        # Add the .tf files to the dropdown
                        self.output_config_dropdown.addItems(tf_files)
                        #self.output_area.append(f"Loaded configuration files: {', '.join(tf_files)}\n")
                    else:
                        # If no .tf files are found, show a default message
                        self.output_config_dropdown.addItem("No Terraform Configurations Found")
                        self.output_area.append(f"No .tf files found in project: {selected_project}\n")
                else:
                    self.output_area.append(f"Project folder not found: {project_path}\n")
                    self.output_config_dropdown.addItem("No Terraform Configurations Found")
            except Exception as e:
                self.output_area.append(f"Error loading .tf files: {e}\n")
                logging.error(f"Error loading .tf files from project '{selected_project}': {e}")
        else:
            # Clear the dropdown and set a default message if no valid project is selected
            self.output_config_dropdown.clear()
            self.output_config_dropdown.addItem("No Configurations Found")

    
    def add_configuration(self):
        print("Add Configuration")
    
    def delete_project_folder(self):
        """Delete the selected project folder."""
        
        # Get the selected project from the dropdown
        selected_project = self.config_project_dropdown.currentText()
        
        if not selected_project or selected_project == "No Projects Found":
            self.output_area.append("No valid project selected for deletion.\n")
            QMessageBox.warning(self, "Delete Project Folder", "Please select a valid project to delete.")
            return
        
        # Confirm before deleting the project folder
        reply = QMessageBox.question(
            self, 
            "Delete Project Folder", 
            f"Are you sure you want to delete the project folder '{selected_project}'? This will not destroy Terraform resources.", 
            QMessageBox.Yes | QMessageBox.No, 
            QMessageBox.No
        )
        
        if reply == QMessageBox.No:
            return
        
        # Define the project folder path
        project_folder_path = os.path.join(os.getcwd(), 'playbooks', selected_project)
        
        try:
            # Remove the project folder
            shutil.rmtree(project_folder_path)
            self.output_area.append(f"Project folder '{selected_project}' removed successfully.\n")
            logging.info(f"Project folder '{selected_project}' removed successfully.")
            
            # Reload the project dropdown after deletion
            self.load_configs_from_folder()

        except Exception as e:
            self.output_area.append(f"An error occurred while deleting the project folder: {e}\n")
            logging.error(f"An error occurred while deleting the project folder '{selected_project}': {e}")
            QMessageBox.critical(self, "Delete Project Folder", f"An error occurred while deleting the project folder: {e}")

    # Execute Project
    def execute_configuration(self):
        """Execute the selected project by running Terraform and Ansible playbooks in a separate thread."""

        # Get the selected project from the dropdown
        selected_project = self.config_project_dropdown.currentText()

        if not selected_project or selected_project == "No Projects Found":
            self.output_area.append("No valid project selected for execution.\n")
            QMessageBox.warning(self, "Execute Project", "Please select a valid project to execute.")
            return

        # Define the project folder path
        project_folder_path = os.path.join(os.getcwd(), 'playbooks', selected_project)

        # Define the terraform.vars path and main.tf path
        terraform_vars_path = os.path.join(project_folder_path, 'terraform.vars')
        main_tf_path = os.path.join(project_folder_path, 'main.tf')  # Check for main.tf

        # Ensure terraform.vars exists
        if not os.path.exists(terraform_vars_path):
            self.output_area.append(f"'terraform.vars' not found in project folder '{selected_project}'.\n")
            QMessageBox.critical(self, "Execute Project", f"'terraform.vars' not found in project folder '{selected_project}'.")
            return

        # Ensure main.tf exists (or other Terraform files)
        if not os.path.exists(main_tf_path):
            self.output_area.append(f"'main.tf' not found in project folder '{selected_project}'.\n")
            QMessageBox.critical(self, "Execute Project", f"'main.tf' not found in project folder '{selected_project}'. Please ensure Terraform configuration files are present.")
            return

        # Check for Kubernetes-related content in all .yml/.yaml files
        if self.contains_kubernetes_keyword(project_folder_path):
            # Use the K8s-specific function for execution
            execution_thread = threading.Thread(
                target=self.run_k8s_terraform_and_ansible,
                args=(selected_project, project_folder_path, terraform_vars_path, main_tf_path)
            )
        else:
            # Use the general function for non-K8s projects
            execution_thread = threading.Thread(
                target=self.run_terraform_and_ansible,
                args=(selected_project, project_folder_path, terraform_vars_path, main_tf_path)
            )

        # Start the thread to execute the project
        execution_thread.start()


    def run_terraform_and_ansible(self, selected_project, project_folder_path, terraform_vars_path, main_tf_path):
        """Run Terraform and invoke Ansible playbook using Ansible's Python API."""
        temp_private_key_path = None  # Initialize variable
        try:
            import sys

            # Add the project folder path to sys.path to import playbook_runner
            sys.path.append(project_folder_path)
            from ansible_tab.playbook_runner import (  # Import the run_playbook function
                extract_remote_user_from_terraform, run_playbook,
                update_ansible_cfg)

            # Initialize Terraform
            self.output_area.append("Initializing Terraform...\n")
            self.scroll_output_to_bottom()

            init_process = subprocess.run(
                ["terraform", "init", "-no-color"], cwd=project_folder_path, capture_output=True, text=True
            )
            self.output_area.append(init_process.stdout)
            self.scroll_output_to_bottom()

            if init_process.returncode != 0:
                self.output_area.append(f"Terraform init failed: {init_process.stderr}\n")
                self.scroll_output_to_bottom()
                return
            self.output_area.append("Terraform initialized successfully.\n")
            self.scroll_output_to_bottom()

            # Apply Terraform
            self.output_area.append("Applying Terraform configuration...\n")
            self.scroll_output_to_bottom()

            apply_process = subprocess.run(
                ["terraform", "apply", "-auto-approve", "-input=false",  "-no-color", "-var-file", terraform_vars_path],
                cwd=project_folder_path,
                capture_output=True,
                text=True
            )
            self.output_area.append(apply_process.stdout)
            self.scroll_output_to_bottom()

            if apply_process.returncode != 0:
                self.output_area.append(f"Terraform apply failed: {apply_process.stderr}\n")
                self.scroll_output_to_bottom()
                return
            self.output_area.append("Terraform applied successfully.\n")
            self.scroll_output_to_bottom()

            # Retrieve the private key generated by Terraform
            self.output_area.append("Retrieving the private key from Terraform output...\n")
            terraform_output_process = subprocess.run(
                ["terraform", "output", "-raw", "private_key_pem"],
                cwd=project_folder_path, capture_output=True, text=True
            )
            ssh_key_private = terraform_output_process.stdout.strip()

            if terraform_output_process.returncode != 0 or not ssh_key_private:
                self.output_area.append(f"Failed to retrieve SSH private key: {terraform_output_process.stderr}\n")
                self.scroll_output_to_bottom()
                return

            # Save the private key to a temporary file for Ansible to use
            temp_private_key_path = os.path.join(project_folder_path, 'temp_ssh_key.pem')
            with open(temp_private_key_path, 'w') as private_key_file:
                private_key_file.write(ssh_key_private)
            os.chmod(temp_private_key_path, 0o600)  # Secure the key file

            self.output_area.append("Private key retrieved and saved for Ansible.\n")
            self.scroll_output_to_bottom()
            
            # Dynamically determine the remote_user from Terraform output or instance type
            remote_user = extract_remote_user_from_terraform(project_folder_path)

            # Update the ansible.cfg with remote_user
            update_ansible_cfg(project_folder_path, remote_user)

            # Read variables from terraform.vars
            config_vars = {}
            with open(terraform_vars_path, 'r') as tf_vars_file:
                for line in tf_vars_file:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        config_vars[key.strip()] = value.strip().strip('"')

            playbook_name = config_vars.get('playbook_name', '')
            inventory_file = config_vars.get('inventory_file', '')
            env_path = config_vars.get('env_path', '')

            if not playbook_name or not inventory_file or not env_path:
                self.output_area.append("Required variables are missing in 'terraform.vars'.\n")
                self.scroll_output_to_bottom()
                return

            # Ensure paths are absolute
            inventory_file = os.path.abspath(inventory_file)
            playbook_name = os.path.abspath(playbook_name)
            temp_private_key_path = os.path.abspath(temp_private_key_path)

            

            # Run the Ansible playbook using Ansible's Python API
            self.output_area.append(f"Running Ansible playbook '{playbook_name}' with inventory '{inventory_file}'...\n")
            self.scroll_output_to_bottom()

            # Redirect stdout and stderr to capture output
            import contextlib
            from io import StringIO

            output_buffer = StringIO()
            with contextlib.redirect_stdout(output_buffer), contextlib.redirect_stderr(output_buffer):
                result = run_playbook(playbook_name, inventory_file, temp_private_key_path, remote_user)

            # Display the captured output
            output = output_buffer.getvalue()
            self.output_area.append(output)
            self.scroll_output_to_bottom()

            if result == 0:
                self.output_area.append("Ansible playbook executed successfully.\n")
            else:
                self.output_area.append(f"Ansible playbook execution failed with code {result}.\n")

            self.scroll_output_to_bottom()

        except Exception as e:
            self.output_area.append(f"An unexpected error occurred: {e}\n")
            logging.error(f"An unexpected error occurred: {e}")
            #QMessageBox.critical(self, "Execute Project", f"An unexpected error occurred: {e}")

        finally:
            # Cleanup the temporary private key file
            if os.path.exists(temp_private_key_path):
                os.remove(temp_private_key_path)
            self.output_area.append("Cleaned up temporary SSH key.\n")
            self.scroll_output_to_bottom()
            
    
    def run_k8s_terraform_and_ansible(self, selected_project, project_folder_path, terraform_vars_path, main_tf_path):
        """Run Terraform and invoke Ansible playbook specifically for EKS projects."""
        temp_private_key_path = None  # Initialize variable
        try:
            import json
            import os
            import subprocess
            import sys

            # Add the project folder path to sys.path to import playbook_runner
            sys.path.append(project_folder_path)
            from ansible_tab.playbook_runner import (
                extract_remote_user_from_terraform, run_playbook)

            # Path for the hosts.ini file
            inventory_file = os.path.join(project_folder_path, 'hosts.ini')

            # Create the hosts.ini file early with placeholder content
            with open(inventory_file, 'w') as ini_file:
                ini_file.write("[masters]\nmaster ansible_host=<master_ip_placeholder>\n\n")
                ini_file.write("[workers]\n<worker_ip_placeholder>\n\n")
                ini_file.write("[all:vars]\n")
                ini_file.write("ansible_user=<remote_user_placeholder>\n")
                ini_file.write("ansible_ssh_private_key_file=<private_key_placeholder>\n")
                ini_file.write("ansible_python_interpreter=/usr/bin/python3\n")
                ini_file.write("ansible_ssh_common_args='-o IdentitiesOnly=yes'\n")

            self.output_area.append(f"\nCreated initial Ansible inventory file at '{inventory_file}'.\n")
            self.scroll_output_to_bottom()

            # Initialize Terraform
            self.output_area.append("Initializing Terraform...\n")
            self.scroll_output_to_bottom()

            init_process = subprocess.run(
                ["terraform", "init", "-no-color"], cwd=project_folder_path, capture_output=True, text=True
            )
            self.output_area.append(init_process.stdout)
            self.scroll_output_to_bottom()

            if init_process.returncode != 0:
                self.output_area.append(f"Terraform init failed: {init_process.stderr}\n")
                self.scroll_output_to_bottom()
                return
            self.output_area.append("Terraform initialized successfully.\n")
            self.scroll_output_to_bottom()

            # Apply Terraform
            self.output_area.append("Applying Terraform configuration...\n")
            self.scroll_output_to_bottom()

            apply_process = subprocess.run(
                ["terraform", "apply", "-auto-approve", "-lock=false",  "-input=false", "-no-color", "-var-file", terraform_vars_path],
                cwd=project_folder_path,
                capture_output=True,
                text=True
            )
            self.output_area.append(apply_process.stdout)
            self.scroll_output_to_bottom()

            if apply_process.returncode != 0:
                self.output_area.append(f"Terraform apply failed: {apply_process.stderr}\n")
                self.scroll_output_to_bottom()
                return
            self.output_area.append("Terraform applied successfully.\n")
            self.scroll_output_to_bottom()

            # Retrieve the private key generated by Terraform
            self.output_area.append("Retrieving the private key from Terraform output...\n")
            terraform_output_process = subprocess.run(
                ["terraform", "output", "-raw", "private_key_pem"],
                cwd=project_folder_path, capture_output=True, text=True
            )
            ssh_key_private = terraform_output_process.stdout.strip()

            if terraform_output_process.returncode != 0 or not ssh_key_private:
                self.output_area.append(f"Failed to retrieve SSH private key: {terraform_output_process.stderr}\n")
                self.scroll_output_to_bottom()
                return

            # Save the private key to a temporary file for Ansible to use
            temp_private_key_path = os.path.join(project_folder_path, 'temp_ssh_key.pem')
            with open(temp_private_key_path, 'w') as private_key_file:
                private_key_file.write(ssh_key_private)
            os.chmod(temp_private_key_path, 0o600)  # Secure the key file

            self.output_area.append("Private key retrieved and saved for Ansible.\n")
            self.scroll_output_to_bottom()

            # Extract IP addresses for Ansible inventory
            master_ip_process = subprocess.run(
                ["terraform", "output", "-raw", "master_public_ip"],
                cwd=project_folder_path, capture_output=True, text=True
            )
            master_ip = master_ip_process.stdout.strip()

            worker_ips_process = subprocess.run(
                ["terraform", "output", "-json", "worker_public_ips"],
                cwd=project_folder_path, capture_output=True, text=True
            )
            worker_ips = json.loads(worker_ips_process.stdout.strip())

            # Dynamically determine the remote_user from Terraform output or instance type
            remote_user = extract_remote_user_from_terraform(project_folder_path)

            # Update the inventory file with the actual values
            with open(inventory_file, 'w') as ini_file:
                ini_file.write(f"[masters]\nmaster ansible_host={master_ip}\n\n")
                ini_file.write("[workers]\n")
                for index, worker_ip in enumerate(worker_ips, start=1):
                    ini_file.write(f"worker{index} ansible_host={worker_ip}\n")
                ini_file.write("\n[all:vars]\n")
                ini_file.write(f"ansible_user={remote_user}\n")
                ini_file.write(f"ansible_ssh_private_key_file={temp_private_key_path}\n")
                ini_file.write("ansible_python_interpreter=/usr/bin/python3\n")
                ini_file.write("ansible_ssh_common_args='-o IdentitiesOnly=yes'\n")

            self.output_area.append(f"Updated Ansible inventory file '{inventory_file}' with actual values.\n")
            self.scroll_output_to_bottom()

            # Read variables from terraform.vars
            config_vars = {}
            with open(terraform_vars_path, 'r') as tf_vars_file:
                for line in tf_vars_file:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        config_vars[key.strip()] = value.strip().strip('"')

            playbook_name = config_vars.get('playbook_name', '')
            env_path = config_vars.get('env_path', '')

            if not playbook_name or not env_path:
                self.output_area.append("Required variables are missing in 'terraform.vars'.\n")
                self.scroll_output_to_bottom()
                return

            # Ensure paths are absolute
            playbook_name = os.path.abspath(playbook_name)
            temp_private_key_path = os.path.abspath(temp_private_key_path)

            # Run the Ansible playbook using the generated hosts.ini file
            self.output_area.append(f"Running Ansible playbook '{playbook_name}' with inventory '{inventory_file}'...\n")
            self.scroll_output_to_bottom()

            # Redirect stdout and stderr to capture output
            import contextlib
            from io import StringIO

            output_buffer = StringIO()
            with contextlib.redirect_stdout(output_buffer), contextlib.redirect_stderr(output_buffer):
                result = run_playbook(playbook_name, inventory_file, temp_private_key_path, remote_user)

            # Display the captured output
            output = output_buffer.getvalue()
            self.output_area.append(output)
            self.scroll_output_to_bottom()

            if result == 0:
                self.output_area.append("Ansible playbook executed successfully.\n")
            else:
                self.output_area.append(f"Ansible playbook execution failed with code {result}.\n")

            self.scroll_output_to_bottom()

        except Exception as e:
            self.output_area.append(f"An unexpected error occurred: {e}\n")
            logging.error(f"An unexpected error occurred: {e}")

        finally:
            # Cleanup the temporary private key file
            if temp_private_key_path and os.path.exists(temp_private_key_path):
                os.remove(temp_private_key_path)
            self.output_area.append("Cleaned up temporary SSH key.\n")
            self.scroll_output_to_bottom()


            
            
    
    def generate_private_key_for_access(self):
        """Generate and save the SSH private key for manual server access."""
        
        selected_project = self.config_project_dropdown.currentText()
        
        if not selected_project:
            self.output_area.append("No project selected. Please select a project to proceed.\n")
            self.scroll_output_to_bottom()
            return None
        
        # Assume the project_folder_path is derived from the selected_project
        # Define the project folder path
        project_folder_path = os.path.join(os.getcwd(), 'playbooks', selected_project)
        
        if not os.path.exists(project_folder_path):
            self.output_area.append(f"The project path '{project_folder_path}' does not exist. Check the configuration.\n")
            self.scroll_output_to_bottom()
            return None

        try:
            self.output_area.append(f"Generating private key for project '{selected_project}'...\n")
            self.scroll_output_to_bottom()
            
            terraform_output_process = subprocess.run(
                ["terraform", "output", "-raw", "private_key_pem"],
                cwd=project_folder_path, capture_output=True, text=True
            )
            ssh_key_private = terraform_output_process.stdout.strip()

            if terraform_output_process.returncode != 0 or not ssh_key_private:
                self.output_area.append(f"Failed to retrieve SSH private key: {terraform_output_process.stderr}\n")
                self.scroll_output_to_bottom()
                return None

            # Save the private key to a file for access
            private_key_path = os.path.join(project_folder_path, 'ssh_access_key.pem')
            with open(private_key_path, 'w') as private_key_file:
                private_key_file.write(ssh_key_private)
            os.chmod(private_key_path, 0o600)  # Secure the key file

            self.output_area.append(f"SSH private key saved to '{private_key_path}' for server access.\n")
            self.scroll_output_to_bottom()
            return ssh_key_private

        except Exception as e:
            self.output_area.append(f"An error occurred while generating SSH private key: {e}\n")
            logging.error(f"An error occurred while generating SSH private key: {e}")
            return None

            
    
    def contains_kubernetes_keyword(self, folder_path):
        """Check all .yml/.yaml files in the folder for the keyword 'kubernetes'."""
        keyword_found = False
        for root, _, files in os.walk(folder_path):
            for file in files:
                if file.endswith(('.yml', '.yaml')):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r') as f:
                        content = f.read().lower()
                        if 'kubernetes' in content:
                            keyword_found = True
                            break
            if keyword_found:
                break
        return keyword_found




    # Utility function to scroll to the bottom of the output area
    def scroll_output_to_bottom(self):
        """Scroll the output area to the bottom if the user is not manually scrolling."""
        if self.output_area.verticalScrollBar().value() == self.output_area.verticalScrollBar().maximum():
            # Automatically scroll to the bottom
            self.output_area.verticalScrollBar().setValue(self.output_area.verticalScrollBar().maximum())





    # Terraform Plan
    def plan_configuration(self):
        """Run Terraform plan for the selected project and display the output with sensitive data masked."""

        # Get the selected project from the dropdown
        selected_project = self.config_project_dropdown.currentText()

        if not selected_project or selected_project == "No Projects Found":
            QMetaObject.invokeMethod(self.output_area, "append", Qt.QueuedConnection, Q_ARG(str, "No valid project selected for planning.\n"))
            return

        # Define the project folder path
        project_folder_path = os.path.join(os.getcwd(), 'playbooks', selected_project)

        # Define the terraform.vars path
        terraform_vars_path = os.path.join(project_folder_path, 'terraform.vars')
        main_tf_path = os.path.join(project_folder_path, 'main.tf')  # Check for main.tf

        # Ensure terraform.vars exists
        if not os.path.exists(terraform_vars_path):
            QMetaObject.invokeMethod(self.output_area, "append", Qt.QueuedConnection, Q_ARG(str, f"'terraform.vars' not found in project folder '{selected_project}'.\n"))
            return

        # Ensure main.tf exists (or other Terraform files)
        if not os.path.exists(main_tf_path):
            QMetaObject.invokeMethod(self.output_area, "append", Qt.QueuedConnection, Q_ARG(str, f"'main.tf' not found in project folder '{selected_project}'.\n"))
            return

        # Run the plan command in a separate thread to avoid blocking the UI "-lock=false",
        def run_terraform_plan():
            try:
                QMetaObject.invokeMethod(self.output_area, "append", Qt.QueuedConnection, Q_ARG(str, "Running Terraform plan...\n"))
                
                # Run Terraform plan with -no-color and using the terraform.vars file
                plan_process = subprocess.run(
                    ["terraform", "plan", "-no-color",  "-var-file", "terraform.vars"],
                    cwd=project_folder_path,
                    check=True,
                    capture_output=True,
                    text=True
                )
                # Mask sensitive data from the output
                masked_output = self.mask_sensitive_data(plan_process.stdout)
                
                # Display the masked output in the output_area
                QMetaObject.invokeMethod(self.output_area, "append", Qt.QueuedConnection, Q_ARG(str, masked_output))
                QMetaObject.invokeMethod(self.output_area, "append", Qt.QueuedConnection, Q_ARG(str, "Terraform plan completed.\n"))

            except subprocess.CalledProcessError as e:
                QMetaObject.invokeMethod(self.output_area, "append", Qt.QueuedConnection, Q_ARG(str, f"Terraform plan failed: {e.stderr}\n"))

        # Start the thread
        threading.Thread(target=run_terraform_plan, daemon=True).start()
        
    
    def mask_sensitive_data(self,output):
        """Mask sensitive data such as public and private keys in the output."""
        # Define patterns for common sensitive data (e.g., private key, public key, password)
        sensitive_patterns = [
            r'(ssh_private_key\s*=\s*")([^\"]+)',  # Match private key
            r'(public_key\s*=\s*")([^\"]+)',       # Match public key
            r'(password\s*=\s*")([^\"]+)'          # Match password
        ]

        # Replace sensitive data with masked versions
        for pattern in sensitive_patterns:
            output = re.sub(pattern, r'\1********', output)  # Mask with '********'

        return output


    # Terraform Destroy
    def destroy_configuration(self):
        """Destroy the selected project Terraform resources without removing the project folder using threading."""
        
        # Get the selected project from the dropdown
        selected_project = self.config_project_dropdown.currentText()
        
        if not selected_project or selected_project == "No Projects Found":
            self.output_area.append("No valid project selected for destruction.\n")
            QMessageBox.warning(self, "Destroy Configuration", "Please select a valid project to destroy.")
            return
        
        # Confirm before destroying resources
        reply = QMessageBox.question(
            self, 
            "Destroy Configuration", 
            f"Are you sure you want to destroy the Terraform resources for '{selected_project}'?", 
            QMessageBox.Yes | QMessageBox.No, 
            QMessageBox.No
        )
        
        if reply == QMessageBox.No:
            return

        # Define the project folder path
        project_folder_path = os.path.join(os.getcwd(), 'playbooks', selected_project)
        
        # Define the terraform.vars path
        terraform_vars_path = os.path.join(project_folder_path, 'terraform.vars')
        main_tf_path = os.path.join(project_folder_path, 'main.tf')  # Check for main.tf

        # Ensure terraform.vars exists
        if not os.path.exists(terraform_vars_path):
            self.output_area.append(f"'terraform.vars' not found in project folder '{selected_project}'.\n")
            QMessageBox.critical(self, "Destroy Configuration", f"'terraform.vars' not found in project folder '{selected_project}'.")
            return
        
        # Ensure main.tf exists (or other Terraform files)
        if not os.path.exists(main_tf_path):
            self.output_area.append(f"'main.tf' not found in project folder '{selected_project}'.\n")
            QMessageBox.critical(self, "Destroy Configuration", f"'main.tf' not found in project folder '{selected_project}'. Please ensure Terraform configuration files are present.")
            return
        
        # Create a thread to run the destroy process
        thread = threading.Thread(target=self.run_destroy_process, args=(project_folder_path,))
        thread.start()


    def run_destroy_process(self, project_folder_path):
        """Run the Terraform destroy process in a separate thread and display output in real-time."""
        
        try:
            # Destroy Terraform resources
            self.output_area.append("Destroying Terraform resources...\n")
            process = subprocess.Popen(
                ["terraform", "destroy", "-auto-approve", "-no-color", "-var-file", "terraform.vars"],
                cwd=project_folder_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Capture output in real time
            for line in process.stdout:
                self.output_area.append(line)
                QApplication.processEvents()  # Process UI events to update the output area in real-time

            process.wait()  # Wait for the process to finish

            if process.returncode == 0:
                self.output_area.append("Terraform resources destroyed successfully.\n")
                logging.info("Terraform resources destroyed successfully.")
            else:
                self.output_area.append(f"Terraform destroy failed with return code {process.returncode}.\n")
                logging.error(f"Terraform destroy failed with return code {process.returncode}.")
        
        except subprocess.CalledProcessError as e:
            self.output_area.append(f"Terraform destroy failed: {e}\n")
            logging.error(f"Terraform destroy failed: {e}")
        except Exception as e:
            self.output_area.append(f"An unexpected error occurred while destroying the configuration: {e}\n")
            logging.error(f"An unexpected error occurred while destroying the configuration: {e}")


            
            
            
    
    def upload_project_folder_for_config(self):
        pass
    

    def create_project_folder_for_config(self):
        """Create a new project folder inside the 'playbooks' directory with Terraform configurations and templates."""
        
        # Define the playbook mapping
        PLAYBOOK_MAP = {
            "Node": "deploy-node.yaml",
            "Docker": "deploy-docker.yaml",
            "Nexus": "deploy-nexus.yaml",
            "K8s": "kubernetes_cluster_ubuntu.yml",
            "Clean Project": None  # No playbook for Clean Project
        }
        
        # Prompt the user to enter a project name
        project_name, ok = QInputDialog.getText(self, "Create Project Folder", "Enter project folder name:")
        
        if not ok or not project_name:
            self.output_area.append("No project name provided.\n")
            return
        
        # Define the path for the 'playbooks' directory
        playbook_dir = os.path.join(os.getcwd(), 'playbooks')
        
        # Ensure the 'playbooks' directory exists, if not, create it
        if not os.path.exists(playbook_dir):
            os.makedirs(playbook_dir)
            self.output_area.append(f"Created playbook directory: {playbook_dir}\n")
            logging.info(f"Created playbook directory: {playbook_dir}")
        
        # Append '_inventory' to the project name and define the project folder path
        project_name_with_inventory = f"{project_name}_inventory"
        project_folder_path = os.path.join(playbook_dir, project_name_with_inventory)
        
        # Ask the user for project type
        project_type, ok = QInputDialog.getItem(
            self,
            "Select Project Type",
            "Choose the project type:",
            ["Node", "Docker", "Nexus", "K8s", "Clean Project"],
            0,
            False
        )
        
        if not ok or not project_type:
            self.output_area.append("No project type selected.\n")
            return
        
        try:
            # Generate the dynamic env_path
            env_path = get_ansible_env_path()
            
            # Create the project folder
            os.makedirs(project_folder_path, exist_ok=True)
            self.output_area.append(f"Project folder '{project_name_with_inventory}' created in '{playbook_dir}'.\n")
            logging.info(f"Project folder '{project_name_with_inventory}' created in '{playbook_dir}'.")
            
            # Define template directory path
            templates_dir = os.path.join(os.getcwd(), 'ansible_tab', 'templates')
            
            # Handle K8s or other project types
            if project_type == "K8s":
                self.handle_k8s_project(templates_dir, project_folder_path, env_path)
            else:
                self.handle_other_projects(templates_dir, project_folder_path, project_type, PLAYBOOK_MAP, project_name_with_inventory, env_path)
            
            self.output_area.append(f"Project '{project_name_with_inventory}' setup completed. You can execute it when ready.\n")
            logging.info(f"Project '{project_name_with_inventory}' setup completed.")

            # Reload the project dropdown
            self.load_configs_from_folder()

        except Exception as e:
            self.output_area.append(f"Failed to create project folder: {e}\n")
            logging.error(f"Error creating project folder '{project_name_with_inventory}': {e}")

    def handle_k8s_project(self, templates_dir, project_folder_path, env_path):
        """Handle the setup for the K8s project type."""
        
        # Define necessary paths
        k8s_tf_path = os.path.join(templates_dir, 'k8s.tf')
        kubernetes_playbook_path = os.path.join(templates_dir, 'kubernetes_cluster_ubuntu.yml')
        k8s_vars_path = os.path.join(templates_dir, 'terraform-k8s.vars')
        k8s_project_vars_path = os.path.join(templates_dir, 'k8s_project-vars.yml')

        # Destination paths
        main_tf_dest = os.path.join(project_folder_path, 'main.tf')
        terraform_vars_path = os.path.join(project_folder_path, 'terraform.vars')
        playbook_dest_path = os.path.join(project_folder_path, 'kubernetes_cluster_ubuntu.yml')
        ansible_cfg_dest_path = os.path.join(project_folder_path, 'ansible.cfg')
        k8s_project_vars_dest_path = os.path.join(project_folder_path, 'k8s_project-vars.yml')

        # Step 1: Copy necessary files to the project folder
        try:
            # Copy k8s.tf as main.tf
            shutil.copy(k8s_tf_path, main_tf_dest)
            
            # Copy inventory, wait-for-ssh, ansible.cfg, and k8s_project-vars.yml
            shutil.copy(k8s_project_vars_path, k8s_project_vars_dest_path)
            
            self.output_area.append("Copied all necessary files to the project folder.\n")
            logging.info("Copied all necessary files to the project folder.")
            
            # Copy Kubernetes playbook
            shutil.copy(kubernetes_playbook_path, playbook_dest_path)
            self.output_area.append("Copied 'kubernetes_cluster_ubuntu.yml' to project folder.\n")
            logging.info("Copied 'kubernetes_cluster_ubuntu.yml' to project folder.")
            
        except Exception as e:
            self.output_area.append(f"Failed to copy files to project folder: {e}\n")
            logging.error(f"Error copying files to project folder '{project_folder_path}': {e}")
            return
        
        # Step 2: Convert terraform-k8s.vars to terraform.vars
        try:
            # Read the contents of terraform-k8s.vars and write to terraform.vars
            with open(k8s_vars_path, 'r') as k8s_vars_file:
                k8s_vars_content = k8s_vars_file.read()
            
            # Create terraform.vars and write the content into it
            with open(terraform_vars_path, 'w') as terraform_vars_file:
                terraform_vars_file.write(k8s_vars_content)
            
            self.output_area.append("Created 'terraform.vars' in project folder with content from 'terraform-k8s.vars'.\n")
            logging.info("Created 'terraform.vars' in project folder with content from 'terraform-k8s.vars'.")
        
        except Exception as e:
            self.output_area.append(f"Failed to convert 'terraform-k8s.vars' to 'terraform.vars': {e}\n")
            logging.error(f"Error converting 'terraform-k8s.vars' to 'terraform.vars' in '{project_folder_path}': {e}")
            return
        
        # Step 3: Append necessary paths to terraform.vars
        playbook_runner_path = os.path.join(os.path.dirname(__file__), 'playbook_runner.py')
        try:
            with open(terraform_vars_path, 'a') as tf_vars_file:
                tf_vars_file.write(f'\nproject_folder = "{project_folder_path}"\n')
                tf_vars_file.write(f'env_path = "{env_path}"\n')
                tf_vars_file.write(f'playbook_name = "{playbook_dest_path}"\n')
                tf_vars_file.write(f'playbook_runner_path = "{playbook_runner_path}"\n')


            self.output_area.append("Updated 'terraform.vars' with all necessary paths.\n")
            logging.info("Updated 'terraform.vars' with project folder, env path, playbook name, playbook runner path, and inventory file.")
        
        except Exception as e:
            self.output_area.append(f"Failed to update 'terraform.vars': {e}\n")
            logging.error(f"Error updating 'terraform.vars' in '{project_folder_path}': {e}")
            return
        



    def handle_other_projects(self, templates_dir, project_folder_path, project_type, PLAYBOOK_MAP, project_name_with_inventory, env_path):
        """Handle the setup for non-K8s project types."""
        # Copy Terraform and inventory files
        ec2_tf_path = os.path.join(templates_dir, 'ec2.tf')
        main_tf_dest = os.path.join(project_folder_path, 'main.tf')  # Rename ec2.tf to main.tf
        shutil.copy(ec2_tf_path, main_tf_dest)
        terraform_vars_path = os.path.join(project_folder_path, 'terraform.vars')
        inventory_file_path = os.path.join(project_folder_path, 'inventory_aws_ec2.yaml')
        
        shutil.copy(os.path.join(templates_dir, 'terraform.vars'), terraform_vars_path)
        shutil.copy(os.path.join(templates_dir, 'inventory_aws_ec2.yaml'), project_folder_path)
        shutil.copy(os.path.join(templates_dir, 'wait-for-ssh.yaml'), project_folder_path)

        # Determine playbook based on project type
        playbook_file = PLAYBOOK_MAP.get(project_type)
        playbook_full_path = ""
        
        if playbook_file:
            # Map project type to vars file
            vars_file = f"{project_type.lower()}_project-vars.yml"
            # Copy vars file
            shutil.copy(os.path.join(templates_dir, vars_file), project_folder_path)
            self.output_area.append(f"Copied {vars_file} to project folder.\n")
            logging.info(f"Copied {vars_file} to project folder.")

            # Read the selected playbook content
            playbook_src_path = os.path.join(templates_dir, playbook_file)
            playbook_full_path = os.path.join(project_folder_path, playbook_file)
            with open(playbook_src_path, 'r') as f:
                playbook_content = f.read()
            
            # Read wait-for-ssh.yaml content
            wait_for_ssh_path = os.path.join(project_folder_path, 'wait-for-ssh.yaml')
            with open(wait_for_ssh_path, 'r') as f:
                wait_for_ssh_content = f.read()
            
            
            # Combine wait-for-ssh content and playbook content
            combined_playbook_content = wait_for_ssh_content + '\n\n' + playbook_content
            
            # Write the combined content to the playbook file in the project folder
            with open(playbook_full_path, 'w') as f:
                f.write(combined_playbook_content)
            self.output_area.append(f"Copied and combined {playbook_file} with wait-for-ssh.yaml in project folder.\n")
            logging.info(f"{project_type} playbook with wait-for-ssh.yaml added to '{project_folder_path}'.")

        elif project_type == "Clean Project":
            self.output_area.append("Clean project selected. Only the hosts and config files are created.\n")
            logging.info(f"Clean project '{project_name_with_inventory}' created.")
        
        # Copy the ansible.cfg from templates
        shutil.copy(os.path.join(templates_dir, 'ansible.cfg'), project_folder_path)
        self.output_area.append("Copied 'ansible.cfg' to project folder.\n")
        logging.info("Copied 'ansible.cfg' to project folder.")

        # Prepare file paths for terraform.vars
        playbook_runner_path = os.path.join(os.path.dirname(__file__), 'playbook_runner.py')
        
        # Update terraform.vars with paths
        if os.path.exists(terraform_vars_path):
            with open(terraform_vars_path, 'a') as tf_vars_file:
                if playbook_full_path:
                    tf_vars_file.write(f'\nplaybook_name = "{playbook_full_path}"\n')
                else:
                    tf_vars_file.write('\nplaybook_name = ""\n')
                tf_vars_file.write(f'playbook_runner_path = "{playbook_runner_path}"\n')
                tf_vars_file.write(f'inventory_file = "{inventory_file_path}"\n')
                tf_vars_file.write(f'project_folder = "{project_folder_path}"\n')
                tf_vars_file.write(f'env_path = "{env_path}"\n')
            self.output_area.append("Updated 'terraform.vars' with playbook_name, playbook_runner_path, inventory_file, and project_folder.\n")
            logging.info("Updated 'terraform.vars' with playbook_name, playbook_runner_path, inventory_file, and project_folder.")
        else:
            self.output_area.append(f"'terraform.vars' not found in project folder.\n")
            logging.error(f"'terraform.vars' not found in project folder '{project_folder_path}'.")







    def run_terraform_apply(self, project_folder):
        """Run terraform apply in the project folder."""
        try:
            # Initialize Terraform
            subprocess.run(["terraform", "init"], cwd=project_folder, check=True)
            self.output_area.append("Terraform initialized successfully.\n")
            logging.info("Terraform initialized successfully.")
            
            # Apply Terraform
            subprocess.run(["terraform", "apply", "-auto-approve"], cwd=project_folder, check=True)
            self.output_area.append("Terraform applied successfully.\n")
            logging.info("Terraform applied successfully.")
        
        except subprocess.CalledProcessError as e:
            self.output_area.append(f"Terraform apply failed: {e}\n")
            logging.error(f"Terraform apply failed: {e}")


    
    

    ######################
    # Role Management
    ######################

    def execute_role_action(self):
        """Execute the selected role action."""
        action = self.role_dropdown.currentText()
        if action == "Install Role from Galaxy":
            self.install_role_from_galaxy()
        elif action == "Delete Role":
            self.delete_role()
        elif action == "List Roles":
            self.list_ansible_roles_and_collections()

    def install_role_from_galaxy(self):
        """Prompt the user to enter a role name or collection to install from Ansible Galaxy."""
        role_name, ok_name = QInputDialog.getText(self, "Install Role or Collection", "Enter role/collection name (e.g., amazon.aws):")
        if not ok_name or not role_name:
            self.output_area.append("Role/collection installation canceled or invalid input.")
            return
        
        is_collection, ok_type = QInputDialog.getItem(
            self, 
            "Install Type", 
            "Is this a role or a collection?", 
            ["Role", "Collection"], 
            0, 
            False
        )

        # Convert to boolean for easier handling
        is_collection = is_collection == "Collection"

        # Update the output area to indicate the installation process has started
        self.output_area.append(f"Starting installation of {'collection' if is_collection else 'role'} '{role_name}'...")
        
        # Create and start the installation thread
        self.install_thread = RoleInstallerThread(role_name, is_collection)
        self.install_thread.install_signal.connect(self.append_output_area)
        self.install_thread.start()
        
    @pyqtSlot(str)
    def append_output_area(self, text):
        """Append text to the output area."""
        self.output_area.append(text)



    def delete_role(self):
        """Delete an Ansible role from the system."""
        roles_directory = "/etc/ansible/roles"  # Define where roles are stored
        try:
            # Get the list of roles installed in the system
            roles = [d for d in os.listdir(roles_directory) if os.path.isdir(os.path.join(roles_directory, d))]
            
            if roles:
                # Prompt user to select a role to delete
                role_name, ok = QInputDialog.getItem(self, "Delete Role", "Select role to delete:", roles, 0, False)
                
                if ok and role_name:
                    # Delete the role directory
                    role_path = os.path.join(roles_directory, role_name)
                    shutil.rmtree(role_path)
                    self.update_output(f"Role '{role_name}' deleted successfully.")
                else:
                    self.update_output("Role deletion canceled.")
            else:
                self.update_output("No roles found on the system.")
        except Exception as e:
            self.update_output(f"Error deleting role: {e}")
            
    def list_ansible_roles_and_collections(self):
        """List Ansible roles and collections installed on the system."""
        # Initialize output for roles and collections
        roles_output = "Ansible Roles:\n"
        collections_output = "\nAnsible Collections:\n"

        # Check for roles in ~/.ansible/roles
        roles_dir = os.path.expanduser('~/.ansible/roles')
        if os.path.exists(roles_dir) and os.path.isdir(roles_dir):
            roles = [role for role in os.listdir(roles_dir) if os.path.isdir(os.path.join(roles_dir, role))]
            if roles:
                roles_output += "\n".join(roles) + "\n"
            else:
                roles_output += "No roles found.\n"
        else:
            roles_output += f"Roles directory '{roles_dir}' does not exist.\n"

        # Check for collections using ansible-galaxy command
        try:
            result = subprocess.run(['ansible-galaxy', 'collection', 'list'], capture_output=True, text=True)
            if result.returncode == 0:
                collections_output += result.stdout
            else:
                collections_output += f"Failed to list collections: {result.stderr}\n"
        except Exception as e:
            collections_output += f"Error listing collections: {e}\n"

        # Display the combined output in your output area
        combined_output = roles_output + collections_output
        self.output_area.append(combined_output)


    def get_roles_directory(self):
        """Determine the appropriate Ansible roles directory based on the OS."""
        # Try to get the default Ansible roles path
        try:
            # Use Ansible command to get the roles path dynamically
            roles_path = subprocess.check_output(['ansible-config', 'dump', '--only-changed']).decode('utf-8')
            for line in roles_path.splitlines():
                if "DEFAULT_ROLES_PATH" in line:
                    # Extract and return the path
                    ansible_path = line.split('=')[-1].strip()
                    break
            else:
                ansible_path = None
        except Exception as e:
            print(f"Failed to detect roles path using Ansible: {e}")
            ansible_path = None
        
        # If unable to get dynamically, set defaults based on OS
        if not ansible_path:
            os_name = platform.system().lower()
            if os_name == 'windows':
                # Windows default role path
                ansible_path = os.path.join(os.getenv('USERPROFILE'), '.ansible', 'roles')
            elif os_name in ['linux', 'darwin']:
                # Linux or MacOS default role path
                ansible_path = os.path.join(os.getenv('HOME'), '.ansible', 'roles')
            else:
                # Fallback to a generic path
                ansible_path = os.path.join(os.getcwd(), 'ansible_roles')
        
        # Check if the roles directory exists
        if not os.path.exists(ansible_path):
            print(f"Roles directory '{ansible_path}' does not exist. Creating directory.")
            os.makedirs(ansible_path, exist_ok=True)

        # List roles if the directory exists
        if os.path.isdir(ansible_path):
            roles = os.listdir(ansible_path)
            if roles:
                print(f"Roles found in '{ansible_path}': {roles}")
            else:
                print(f"No roles found in '{ansible_path}'.")
        else:
            print(f"Roles directory '{ansible_path}' could not be found or created.")

        return ansible_path



    


