import boto3
import botocore
from PyQt5.QtCore import Q_ARG, QMetaObject, QObject, Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import (QComboBox, QFormLayout, QHBoxLayout, QInputDialog,
                             QLabel, QMessageBox, QPushButton, QTextEdit,
                             QVBoxLayout, QWidget)


class SignalManager(QObject):
    message_signal = pyqtSignal(str)
    clear_signal = pyqtSignal()


class Worker(QObject):
    """
    Worker class to handle background tasks.
    """
    finished = pyqtSignal()
    error = pyqtSignal(str)
    data_fetched = pyqtSignal(list, list, list)  # For refresh_dropdowns
    user_details_fetched = pyqtSignal(str)       # For display_user_details
    action_completed = pyqtSignal(str)           # For execute_user_action and others

    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs

    def run(self):
        """
        Executes the assigned function and emits appropriate signals based on the function.
        """
        try:
            print(f"Worker: Running function '{self.func.__name__}'")  # Debugging
            if self.func.__name__ == "_refresh_dropdowns":
                user_list, group_list, policy_list = self.func(*self.args, **self.kwargs)
                print("Worker: Emitting data_fetched signal")  # Debugging
                self.data_fetched.emit(user_list, group_list, policy_list)
                self.action_completed.emit("IAM resources refreshed successfully.")
            elif self.func.__name__ == "_display_user_details":
                details = self.func(*self.args, **self.kwargs)
                self.user_details_fetched.emit(details)
            elif self.func.__name__ == "_execute_user_action":
                message = self.func(*self.args, **self.kwargs)
                self.action_completed.emit(message)
            else:
                # Handle other functions as needed
                result = self.func(*self.args, **self.kwargs)
                self.action_completed.emit(result)
        except botocore.exceptions.ClientError as e:
            print(f"Worker: ClientError occurred - {e}")  # Debugging
            self.error.emit(f"ClientError: {str(e)}")
        except Exception as e:
            print(f"Worker: Exception occurred - {e}")  # Debugging
            self.error.emit(f"Error: {str(e)}")
        finally:
            print("Worker: Emitting finished signal")  # Debugging
            self.finished.emit()


class IAMTab(QWidget):
    def __init__(self, session):
        super().__init__()
        self.session = session
        self.iam_client = session.client('iam')
        self.signal_manager = SignalManager()

        # Initialize threads and workers lists **before** calling initUI
        self.threads = []   # List to keep references to QThread instances
        self.workers = []   # List to keep references to Worker instances

        self.initUI()
        self.connect_signals()

    def initUI(self):
        main_layout = QHBoxLayout()

        left_column = QVBoxLayout()
        management_layout = QFormLayout()

        # Dropdowns
        self.user_dropdown = QComboBox(self)
        self.group_dropdown = QComboBox(self)
        self.aws_policy_dropdown = QComboBox(self)

        self.user_dropdown.currentIndexChanged.connect(self.display_user_details)

        # Refresh Button
        self.refresh_dropdowns_button = QPushButton("Refresh IAM Resources", self)
        self.refresh_dropdowns_button.clicked.connect(self.refresh_dropdowns)

        # Add to layout
        management_layout.addRow(QLabel("Select IAM User:"), self.user_dropdown)
        management_layout.addRow(QLabel("Select IAM Group:"), self.group_dropdown)
        management_layout.addRow(QLabel("Select AWS Policy:"), self.aws_policy_dropdown)
        management_layout.addRow(self.refresh_dropdowns_button)

        # Action Dropdowns and Buttons
        self.user_action_dropdown = QComboBox(self)
        self.user_action_dropdown.addItems([
            "Create User", "Create Access Key", "Create Login Profile",
            "Attach Policy to User", "Detach Policy from User",
            "Add User to Group", "Remove User from Group", "Delete User",
            "Update User Name", "Update Access Key"
        ])

        self.group_action_dropdown = QComboBox(self)
        self.group_action_dropdown.addItems([
            "Create Group", "Attach Policy to Group", "Detach Policy from Group"
        ])

        self.policy_action_dropdown = QComboBox(self)
        self.policy_action_dropdown.addItems(["Create Policy"])

        self.execute_user_action_button = QPushButton("Execute User Action", self)
        self.execute_user_action_button.clicked.connect(self.execute_user_action)

        self.execute_group_action_button = QPushButton("Execute Group Action", self)
        self.execute_group_action_button.clicked.connect(self.execute_group_action)

        self.execute_policy_action_button = QPushButton("Execute Policy Action", self)
        self.execute_policy_action_button.clicked.connect(self.execute_policy_action)

        # Add to layout
        management_layout.addRow(QLabel("Select User Action:"), self.user_action_dropdown)
        management_layout.addRow(self.execute_user_action_button)
        management_layout.addRow(QLabel("Select Group Action:"), self.group_action_dropdown)
        management_layout.addRow(self.execute_group_action_button)
        management_layout.addRow(QLabel("Select Policy Action:"), self.policy_action_dropdown)
        management_layout.addRow(self.execute_policy_action_button)

        left_column.addLayout(management_layout)

        # Output Area
        right_column = QVBoxLayout()

        self.output_area = QTextEdit(self)
        self.output_area.setReadOnly(True)

        right_column.addWidget(QLabel("IAM Action Output:"))
        right_column.addWidget(self.output_area)

        main_layout.addLayout(left_column, 2)
        main_layout.addLayout(right_column, 3)

        self.setLayout(main_layout)

        # Initial refresh
        self.refresh_dropdowns()

    def connect_signals(self):
        self.signal_manager.message_signal.connect(self.show_message)
        self.signal_manager.clear_signal.connect(self.clear_output_area)

    def refresh_dropdowns(self):
        """
        Initiates the background task to refresh IAM dropdowns.
        """
        self.clear_output_area()
        self.clear_dropdowns()

        # Create a new thread and worker
        thread = QThread()
        worker = Worker(self._refresh_dropdowns)
        worker.moveToThread(thread)

        # Connect signals
        thread.started.connect(worker.run)
        worker.data_fetched.connect(self.update_dropdowns)
        worker.action_completed.connect(self.show_message)
        worker.error.connect(self.show_message)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)

        # Start the thread
        thread.start()

        # Keep references to thread and worker to prevent garbage collection
        self.threads.append(thread)
        self.workers.append(worker)

    def _refresh_dropdowns(self):
        """
        Fetches IAM users, groups, and policies.
        Returns lists of users, groups, and policies.
        """
        user_list = []
        group_list = []
        policy_list = []

        try:
            # Fetch users
            print("Fetching IAM users...")
            users_response = self.iam_client.list_users()
            print(f"Users Response: {users_response}")  # Debugging
            for user in users_response['Users']:
                user_list.append(user['UserName'])
            print(f"User List: {user_list}")  # Debugging

            # Fetch groups
            print("Fetching IAM groups...")
            groups_response = self.iam_client.list_groups()
            print(f"Groups Response: {groups_response}")  # Debugging
            for group in groups_response['Groups']:
                group_list.append(group['GroupName'])
            print(f"Group List: {group_list}")  # Debugging

            # Fetch policies
            print("Fetching IAM policies...")
            paginator = self.iam_client.get_paginator('list_policies')
            for page in paginator.paginate(Scope='All', OnlyAttached=False):
                for policy in page['Policies']:
                    policy_name = policy['PolicyName']
                    policy_arn = policy['Arn']
                    display_text = f"{policy_name[:50]}..." if len(policy_name) > 50 else policy_name
                    policy_list.append((policy_name, policy_arn))
            print(f"Policy List: {policy_list}")  # Debugging

            return user_list, group_list, policy_list
        except botocore.exceptions.ClientError as e:
            error_message = f"ClientError during refresh_dropdowns: {str(e)}"
            print(error_message)  # Debugging
            self.signal_manager.error.emit(error_message)
            return user_list, group_list, policy_list
        except Exception as e:
            error_message = f"Exception during refresh_dropdowns: {str(e)}"
            print(error_message)  # Debugging
            self.signal_manager.error.emit(error_message)
            return user_list, group_list, policy_list

    def update_dropdowns(self, user_list, group_list, policy_list):
        """
        Updates the dropdowns with fetched IAM data.
        """
        print("Updating dropdowns with fetched data...")  # Debugging
        self.user_dropdown.clear()
        self.group_dropdown.clear()
        self.aws_policy_dropdown.clear()

        if user_list:
            self.user_dropdown.addItems(user_list)
            print("User Dropdown populated.")  # Debugging
        else:
            self.signal_manager.message_signal.emit("No IAM users found.")

        if group_list:
            self.group_dropdown.addItems(group_list)
            print("Group Dropdown populated.")  # Debugging
        else:
            self.signal_manager.message_signal.emit("No IAM groups found.")

        if policy_list:
            for policy_name, policy_arn in policy_list:
                self.aws_policy_dropdown.addItem(policy_name, policy_arn)
            print("AWS Policy Dropdown populated.")  # Debugging
        else:
            self.signal_manager.message_signal.emit("No IAM policies found.")

    def show_message(self, message):
        """
        Appends a message to the output area.
        """
        QMetaObject.invokeMethod(
            self.output_area,
            "append",
            Qt.QueuedConnection,
            Q_ARG(str, message)
        )
        print(f"IAMTab Output: {message}")  # Debugging

    def clear_output_area(self):
        """
        Clears the output area.
        """
        QMetaObject.invokeMethod(self.output_area, "clear", Qt.QueuedConnection)

    def clear_dropdowns(self):
        """
        Clears all dropdowns.
        """
        self.user_dropdown.clear()
        self.group_dropdown.clear()
        self.aws_policy_dropdown.clear()

    def display_user_details(self):
        """
        Initiates the background task to display selected user's details.
        """
        self.signal_manager.clear_signal.emit()

        selected_user = self.user_dropdown.currentText()
        if not selected_user:
            self.signal_manager.message_signal.emit("No user selected.")
            return

        # Create a new thread and worker
        thread = QThread()
        worker = Worker(self._display_user_details, selected_user)
        worker.moveToThread(thread)

        # Connect signals
        thread.started.connect(worker.run)
        worker.user_details_fetched.connect(self.show_message)
        worker.action_completed.connect(self.show_message)  # For any additional messages
        worker.error.connect(self.show_message)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)

        # Start the thread
        thread.start()

        # Keep references to thread and worker to prevent garbage collection
        self.threads.append(thread)
        self.workers.append(worker)

    def _display_user_details(self, user_name):
        """
        Fetches details for the selected IAM user.
        Returns a formatted string with user details.
        """
        details = f"Details for user: {user_name}\n"
        try:
            print(f"Fetching details for user: {user_name}")  # Debugging
            attached_policies_response = self.iam_client.list_attached_user_policies(UserName=user_name)
            details += "\nAttached Policies:\n"
            if attached_policies_response['AttachedPolicies']:
                for policy in attached_policies_response['AttachedPolicies']:
                    details += f"  - {policy['PolicyName']} (ARN: {policy['PolicyArn']})\n"
            else:
                details += "  No attached policies.\n"

            groups_response = self.iam_client.list_groups_for_user(UserName=user_name)
            details += "\nGroups:\n"
            if groups_response['Groups']:
                for group in groups_response['Groups']:
                    details += f"  - {group['GroupName']}\n"

                    # Display attached policies for each group the user is in
                    attached_group_policies_response = self.iam_client.list_attached_group_policies(GroupName=group['GroupName'])
                    details += "\n  Attached Policies for Group:\n"
                    if attached_group_policies_response['AttachedPolicies']:
                        for policy in attached_group_policies_response['AttachedPolicies']:
                            details += f"    - {policy['PolicyName']} (ARN: {policy['PolicyArn']})\n"
                    else:
                        details += "    No attached policies for this group.\n"
            else:
                details += "  No groups.\n"

            return details
        except botocore.exceptions.ClientError as e:
            error_message = f"Error fetching user details: {str(e)}"
            print(error_message)  # Debugging
            self.signal_manager.error.emit(error_message)
            return details

    def execute_user_action(self):
        """
        Initiates the background task to execute the selected user action.
        """
        action = self.user_action_dropdown.currentText()
        selected_user = self.user_dropdown.currentText()

        if not selected_user and action not in ["Create User"]:
            self.signal_manager.message_signal.emit("No user selected.")
            return

        self.signal_manager.clear_signal.emit()

        if action == "Create User":
            # Prompt for user input on main thread
            user_name, ok = self.get_user_input("Enter the new IAM user name:")
            if not ok or not user_name:
                self.signal_manager.message_signal.emit("User creation canceled or invalid input.")
                return
            # Start worker thread with user_name
            self.start_worker(self._create_iam_user, user_name)
        elif action == "Create Access Key":
            if not selected_user:
                self.signal_manager.message_signal.emit("No user selected for creating access key.")
                return
            self.start_worker(self._create_access_key, selected_user)
        elif action == "Create Login Profile":
            if not selected_user:
                self.signal_manager.message_signal.emit("No user selected for creating login profile.")
                return
            # Prompt for password on main thread
            password, ok = self.get_user_input("Enter the password for the new login profile:")
            if not ok or not password:
                self.signal_manager.message_signal.emit("Login profile creation canceled or invalid input.")
                return
            self.start_worker(self._create_login_profile, selected_user, password)
        elif action == "Attach Policy to User":
            if not selected_user:
                self.signal_manager.message_signal.emit("No user selected for attaching policy.")
                return
            self.start_worker(self._attach_policy_to_user, selected_user)
        elif action == "Detach Policy from User":
            if not selected_user:
                self.signal_manager.message_signal.emit("No user selected for detaching policy.")
                return
            self.start_worker(self._detach_policy_from_user, selected_user)
        elif action == "Add User to Group":
            if not selected_user:
                self.signal_manager.message_signal.emit("No user selected for adding to group.")
                return
            self.start_worker(self._add_user_to_group, selected_user)
        elif action == "Remove User from Group":
            if not selected_user:
                self.signal_manager.message_signal.emit("No user selected for removing from group.")
                return
            self.start_worker(self._remove_user_from_group, selected_user)
        elif action == "Delete User":
            if not selected_user:
                self.signal_manager.message_signal.emit("No user selected for deletion.")
                return
            self.start_worker(self._delete_user, selected_user)
        elif action == "Update User Name":
            if not selected_user:
                self.signal_manager.message_signal.emit("No user selected for updating name.")
                return
            # Prompt for new user name on main thread
            new_user_name, ok = self.get_user_input("Enter the new IAM user name:")
            if not ok or not new_user_name:
                self.signal_manager.message_signal.emit("User name update canceled or invalid input.")
                return
            self.start_worker(self._update_user_name, selected_user, new_user_name)
        elif action == "Update Access Key":
            if not selected_user:
                self.signal_manager.message_signal.emit("No user selected for updating access key.")
                return
            # Prompt for Access Key ID on main thread
            access_key_id, ok = self.get_user_input("Enter the Access Key ID to update:")
            if not ok or not access_key_id:
                self.signal_manager.message_signal.emit("Access key update canceled or invalid input.")
                return
            # Prompt for new status on main thread
            status, ok = QInputDialog.getItem(
                self,
                "Select Status",
                "Select the new status for the access key:",
                ["Active", "Inactive"],
                0,
                False
            )
            if not ok or not status:
                self.signal_manager.message_signal.emit("Access key status update canceled or invalid selection.")
                return
            self.start_worker(self._update_access_key, selected_user, access_key_id, status)
        else:
            self.signal_manager.message_signal.emit("Unknown action selected.")

    def execute_group_action(self):
        """
        Initiates the background task to execute the selected group action.
        """
        action = self.group_action_dropdown.currentText()
        selected_group = self.group_dropdown.currentText()

        if not selected_group and action not in ["Create Group"]:
            self.signal_manager.message_signal.emit("No group selected.")
            return

        self.signal_manager.clear_signal.emit()

        if action == "Create Group":
            # Prompt for group name on main thread
            group_name, ok = self.get_user_input("Enter the new IAM group name:")
            if not ok or not group_name:
                self.signal_manager.message_signal.emit("Group creation canceled or invalid input.")
                return
            self.start_worker(self._create_iam_group, group_name)
        elif action == "Attach Policy to Group":
            if not selected_group:
                self.signal_manager.message_signal.emit("No group selected for attaching policy.")
                return
            self.start_worker(self._attach_policy_to_group, selected_group)
        elif action == "Detach Policy from Group":
            if not selected_group:
                self.signal_manager.message_signal.emit("No group selected for detaching policy.")
                return
            self.start_worker(self._detach_policy_from_group, selected_group)
        else:
            self.signal_manager.message_signal.emit("Unknown action selected.")

    def execute_policy_action(self):
        """
        Initiates the background task to execute the selected policy action.
        """
        action = self.policy_action_dropdown.currentText()

        self.signal_manager.clear_signal.emit()

        if action == "Create Policy":
            # Prompt for policy name on main thread
            policy_name, ok = self.get_user_input("Enter the new IAM policy name:")
            if not ok or not policy_name:
                self.signal_manager.message_signal.emit("Policy creation canceled or invalid input.")
                return
            # Ask if user wants to input JSON policy document
            use_json, _ = self.ask_user("Would you like to input a JSON policy document?")
            if use_json:
                # Prompt for JSON policy document on main thread
                policy_document, ok = self.get_user_input("Enter the policy document (JSON):", is_text=True)
                if not ok or not policy_document:
                    self.signal_manager.message_signal.emit("Policy creation canceled or invalid JSON input.")
                    return
                self.start_worker(self._create_iam_policy_with_json, policy_name, policy_document)
            else:
                # Attach existing policy to copy its document
                selected_policy = self.aws_policy_dropdown.currentText()
                if not selected_policy:
                    self.signal_manager.message_signal.emit("No AWS policy selected for copying.")
                    return
                policy_arn = self.get_selected_policy_arn()
                if not policy_arn:
                    self.signal_manager.message_signal.emit("No valid policy selected for copying.")
                    return
                self.start_worker(self._create_iam_policy_by_copying, policy_name, selected_policy, policy_arn)
        else:
            self.signal_manager.message_signal.emit("Unknown action selected.")

    def start_worker(self, func, *args, **kwargs):
        """
        Helper method to start a worker thread with the given function and arguments.
        """
        thread = QThread()
        worker = Worker(func, *args, **kwargs)
        worker.moveToThread(thread)

        # Connect signals
        thread.started.connect(worker.run)
        worker.action_completed.connect(self.show_message)
        worker.error.connect(self.show_message)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)

        # Start the thread
        thread.start()

        # Keep references to thread and worker to prevent garbage collection
        self.threads.append(thread)
        self.workers.append(worker)

    # --- IAM Action Methods ---

    def _create_iam_user(self, user_name):
        """
        Worker function to create IAM user.
        """
        try:
            print(f"Creating IAM user: {user_name}")  # Debugging
            response = self.iam_client.create_user(UserName=user_name)
            formatted_message = self.format_response_message("User created", user_name, response)
            return formatted_message
        except botocore.exceptions.ClientError as e:
            print(f"Error creating user: {str(e)}")  # Debugging
            return f"Error creating user: {str(e)}"

    def _create_access_key(self, user_name):
        try:
            print(f"Creating access key for user: {user_name}")  # Debugging
            response = self.iam_client.create_access_key(UserName=user_name)
            access_key = response['AccessKey']
            formatted_message = self.format_response_message("Access Key created for user", user_name, response)
            return (
                f"Access Key ID: {access_key['AccessKeyId']}\n"
                f"Secret Access Key: {access_key['SecretAccessKey']}\n"
                f"{formatted_message}"
            )
        except botocore.exceptions.ClientError as e:
            print(f"Error creating access key: {str(e)}")  # Debugging
            return f"Error creating access key: {str(e)}"

    def _create_login_profile(self, user_name, password):
        try:
            print(f"Creating login profile for user: {user_name}")  # Debugging
            response = self.iam_client.create_login_profile(
                UserName=user_name,
                Password=password,
                PasswordResetRequired=False
            )
            formatted_message = self.format_response_message("Login profile created for user", user_name, response)
            return formatted_message
        except botocore.exceptions.ClientError as e:
            print(f"Error creating login profile: {str(e)}")  # Debugging
            return f"Error creating login profile: {str(e)}"

    def _attach_policy_to_user(self, user_name):
        policy_arn = self.get_selected_policy_arn()
        if policy_arn:
            try:
                print(f"Attaching policy {policy_arn} to user: {user_name}")  # Debugging
                response = self.iam_client.attach_user_policy(
                    UserName=user_name,
                    PolicyArn=policy_arn
                )
                formatted_message = self.format_response_message("Policy attached to user", user_name, response)
                return formatted_message
            except botocore.exceptions.ClientError as e:
                print(f"Error attaching policy to user: {str(e)}")  # Debugging
                return f"Error attaching policy to user: {str(e)}"
        else:
            return "No valid policy selected for attachment."

    def _detach_policy_from_user(self, user_name):
        policy_arn = self.get_selected_policy_arn()
        if policy_arn:
            try:
                print(f"Detaching policy {policy_arn} from user: {user_name}")  # Debugging
                response = self.iam_client.detach_user_policy(
                    UserName=user_name,
                    PolicyArn=policy_arn
                )
                formatted_message = self.format_response_message("Policy detached from user", user_name, response)
                return formatted_message
            except botocore.exceptions.ClientError as e:
                print(f"Error detaching policy from user: {str(e)}")  # Debugging
                return f"Error detaching policy from user: {str(e)}"
        else:
            return "No valid policy selected for detachment."

    def _add_user_to_group(self, user_name):
        group_name = self.group_dropdown.currentText()
        if group_name:
            try:
                print(f"Adding user {user_name} to group {group_name}")  # Debugging
                response = self.iam_client.add_user_to_group(
                    GroupName=group_name,
                    UserName=user_name
                )
                formatted_message = self.format_response_message("User added to group", group_name, response)
                return formatted_message
            except botocore.exceptions.ClientError as e:
                print(f"Error adding user to group: {str(e)}")  # Debugging
                return f"Error adding user to group: {str(e)}"
        else:
            return "No group selected to add the user."

    def _remove_user_from_group(self, user_name):
        group_name = self.group_dropdown.currentText()
        if group_name:
            try:
                print(f"Removing user {user_name} from group {group_name}")  # Debugging
                response = self.iam_client.remove_user_from_group(
                    GroupName=group_name,
                    UserName=user_name
                )
                formatted_message = self.format_response_message("User removed from group", group_name, response)
                return formatted_message
            except botocore.exceptions.ClientError as e:
                print(f"Error removing user from group: {str(e)}")  # Debugging
                return f"Error removing user from group: {str(e)}"
        else:
            return "No group selected to remove the user from."

    def _delete_user(self, user_name):
        try:
            print(f"Deleting user: {user_name}")  # Debugging
            response = self.iam_client.delete_user(UserName=user_name)
            formatted_message = self.format_response_message("User deleted", user_name, response)
            return formatted_message
        except botocore.exceptions.ClientError as e:
            print(f"Error deleting user: {str(e)}")  # Debugging
            return f"Error deleting user: {str(e)}"

    def _attach_policy_to_group(self, group_name):
        policy_arn = self.get_selected_policy_arn()
        if policy_arn:
            try:
                print(f"Attaching policy {policy_arn} to group: {group_name}")  # Debugging
                response = self.iam_client.attach_group_policy(
                    GroupName=group_name,
                    PolicyArn=policy_arn
                )
                formatted_message = self.format_response_message("Policy attached to group", group_name, response)
                return formatted_message
            except botocore.exceptions.ClientError as e:
                print(f"Error attaching policy to group: {str(e)}")  # Debugging
                return f"Error attaching policy to group: {str(e)}"
        else:
            return "No valid policy selected for attachment."

    def _detach_policy_from_group(self, group_name):
        policy_arn = self.get_selected_policy_arn()
        if policy_arn:
            try:
                print(f"Detaching policy {policy_arn} from group: {group_name}")  # Debugging
                response = self.iam_client.detach_group_policy(
                    GroupName=group_name,
                    PolicyArn=policy_arn
                )
                formatted_message = self.format_response_message("Policy detached from group", group_name, response)
                return formatted_message
            except botocore.exceptions.ClientError as e:
                print(f"Error detaching policy from group: {str(e)}")  # Debugging
                return f"Error detaching policy from group: {str(e)}"
        else:
            return "No valid policy selected for detachment."

    def _create_iam_policy_with_json(self, policy_name, policy_document):
        """
        Worker function to create IAM policy with custom JSON.
        """
        try:
            print(f"Creating IAM policy with custom JSON: {policy_name}")  # Debugging
            response = self.iam_client.create_policy(
                PolicyName=policy_name,
                PolicyDocument=policy_document
            )
            formatted_message = self.format_response_message("Policy created with custom JSON", policy_name, response)
            return formatted_message
        except botocore.exceptions.ClientError as e:
            print(f"Error creating policy: {str(e)}")  # Debugging
            return f"Error creating policy: {str(e)}"

    def _create_iam_policy_by_copying(self, policy_name, selected_policy, policy_arn):
        """
        Worker function to create IAM policy by copying from an existing policy.
        """
        try:
            print(f"Creating IAM policy by copying from: {selected_policy}")  # Debugging
            existing_policy = self.iam_client.get_policy(PolicyArn=policy_arn)
            policy_version = self.iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=existing_policy['Policy']['DefaultVersionId']
            )
            policy_document = policy_version['PolicyVersion']['Document']
            response = self.iam_client.create_policy(
                PolicyName=policy_name,
                PolicyDocument=policy_document
            )
            formatted_message = self.format_response_message("Policy created by copying from", selected_policy, response)
            return formatted_message
        except botocore.exceptions.ClientError as e:
            print(f"Error creating policy by copying: {str(e)}")  # Debugging
            return f"Error creating policy by copying: {str(e)}"

    # --- Utility Methods ---

    def format_response_message(self, action, resource_name, response):
        request_id = response['ResponseMetadata']['RequestId']
        status_code = response['ResponseMetadata']['HTTPStatusCode']
        date = response['ResponseMetadata']['HTTPHeaders']['date']

        return (
            f"{action} '{resource_name}' successfully.\n"
            f"Request ID: {request_id}\n"
            f"HTTP Status Code: {status_code}\n"
            f"Date: {date}\n"
        )

    def get_selected_policy_arn(self):
        selected_index = self.aws_policy_dropdown.currentIndex()
        if selected_index >= 0:
            policy_arn = self.aws_policy_dropdown.itemData(selected_index)
            if policy_arn:
                return policy_arn
        self.signal_manager.message_signal.emit("No valid policy selected.")
        return None

    def get_user_input(self, prompt, is_text=False):
        if is_text:
            text, ok = QInputDialog.getMultiLineText(self, "Input Required", prompt)
        else:
            text, ok = QInputDialog.getText(self, "Input Required", prompt)
        return text, ok

    def ask_user(self, message):
        reply = QMessageBox.question(
            self,
            'Input Required',
            message,
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        return reply == QMessageBox.Yes, reply

    def show_message(self, message):
        """
        Appends a message to the output area.
        """
        QMetaObject.invokeMethod(
            self.output_area,
            "append",
            Qt.QueuedConnection,
            Q_ARG(str, message)
        )
        print(f"IAMTab Output: {message}")  # Debugging

    def clear_output_area(self):
        """
        Clears the output area.
        """
        QMetaObject.invokeMethod(self.output_area, "clear", Qt.QueuedConnection)

    def clear_inputs(self):
        self.user_dropdown.setCurrentIndex(-1)
        self.group_dropdown.setCurrentIndex(-1)
        self.aws_policy_dropdown.setCurrentIndex(-1)
        self.user_action_dropdown.setCurrentIndex(-1)
        self.group_action_dropdown.setCurrentIndex(-1)
        self.policy_action_dropdown.setCurrentIndex(-1)

    # --- Cleanup ---

    def closeEvent(self, event):
        """
        Ensures that all threads are properly terminated when the widget is closed.
        """
        print("Closing IAMTab. Terminating all threads.")  # Debugging
        for thread in self.threads:
            if thread.isRunning():
                thread.quit()
                thread.wait()
        event.accept()
