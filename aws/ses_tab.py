import json
import sys
import threading

import boto3
import botocore
from botocore.exceptions import ParamValidationError
from PyQt5.QtCore import Q_ARG, QMetaObject, QObject, Qt, pyqtSignal
from PyQt5.QtWidgets import (QApplication, QComboBox, QFileDialog, QFormLayout,
                             QGroupBox, QHBoxLayout, QInputDialog, QLabel,
                             QLineEdit, QMessageBox, QPushButton, QScrollArea,
                             QSizePolicy, QTabWidget, QTextEdit, QVBoxLayout,
                             QWidget)


class SignalManager(QObject):
    message_signal = pyqtSignal(str)
    dropdown_signal = pyqtSignal(list)
    clear_signal = pyqtSignal()


class SESTab(QWidget):
    def __init__(self, session):
        super().__init__()
        self.current_session = session
        self.ses_client = session.client('ses')
        self.signal_manager = SignalManager()
        self.initUI()
        self.connect_signals()
        self.load_verified_identities()

    def initUI(self):
        main_layout = QHBoxLayout()

        # Left Column: SES Management Section with Subtabs
        left_column = QVBoxLayout()

        # Refresh Button for Verified Identities
        self.refresh_button = QPushButton("Refresh Verified Identities", self)
        self.refresh_button.clicked.connect(self.refresh_verified_identities)
        left_column.addWidget(self.refresh_button)

        # Verified Identities Dropdown (available globally within SESTab)
        self.verified_identities_dropdown = QComboBox(self)
        self.verified_identities_dropdown.setPlaceholderText("Select a Verified Identity")
        left_column.addWidget(QLabel("Verified Identities:"))
        left_column.addWidget(self.verified_identities_dropdown)

        # Create Subtabs for Different Functionalities
        self.ses_subtabs = QTabWidget()
        left_column.addWidget(self.ses_subtabs)

        # Email Sending Subtab
        self.email_sending_tab = QWidget()
        self.ses_subtabs.addTab(self.email_sending_tab, "Email Sending")
        self.setup_email_sending_tab()

        # Verified Identities Management Subtab
        self.verified_identities_tab = QWidget()
        self.ses_subtabs.addTab(self.verified_identities_tab, "Verified Identities")
        self.setup_verified_identities_tab()

        # Email Templates Subtab
        self.email_templates_tab = QWidget()
        self.ses_subtabs.addTab(self.email_templates_tab, "Email Templates")
        self.setup_email_templates_tab()

        # Sending Statistics Subtab
        self.sending_statistics_tab = QWidget()
        self.ses_subtabs.addTab(self.sending_statistics_tab, "Sending Statistics")
        self.setup_sending_statistics_tab()

        # Suppression List Management Subtab
        self.suppression_list_tab = QWidget()
        self.ses_subtabs.addTab(self.suppression_list_tab, "Suppression List")
        self.setup_suppression_list_tab()

        # Add stretch to push elements to the top
        left_column.addStretch()

        # Right Column: Output Area
        right_column = QVBoxLayout()

        self.output_area = QTextEdit(self)
        self.output_area.setReadOnly(True)

        right_column.addWidget(QLabel("SES Action Output:"))
        right_column.addWidget(self.output_area)

        # Add columns to the main layout with specific stretch factors
        main_layout.addLayout(left_column, 2)
        main_layout.addLayout(right_column, 3)

        self.setLayout(main_layout)

    def connect_signals(self):
        self.signal_manager.message_signal.connect(self.show_message)
        self.signal_manager.dropdown_signal.connect(self.populate_verified_identities)
        self.signal_manager.clear_signal.connect(self.clear_output_area)

    def run_in_thread(self, target, *args, **kwargs):
        thread = threading.Thread(target=target, args=args, kwargs=kwargs)
        thread.start()

    def refresh_verified_identities(self):
        self.run_in_thread(self.load_verified_identities)
        self.signal_manager.message_signal.emit("Refreshing verified identities...")

    def load_verified_identities(self):
        try:
            identities = []

            # 1. Fetch verified email addresses (Non-pagable)
            response_emails = self.ses_client.list_verified_email_addresses()
            identities.extend(response_emails.get('VerifiedEmailAddresses', []))

            # 2. Fetch verified domains (Pagable)
            paginator = self.ses_client.get_paginator('list_identities')
            for page in paginator.paginate(IdentityType='Domain'):
                identities.extend(page.get('Identities', []))

            self.signal_manager.dropdown_signal.emit(identities)
            self.signal_manager.message_signal.emit("Verified identities loaded successfully.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error loading verified identities: {str(e)}")

    def populate_verified_identities(self, items):
        self.verified_identities_dropdown.clear()
        self.verified_identities_dropdown.addItems(items)

    def show_message(self, message):
        QMetaObject.invokeMethod(
            self.output_area, "append", Qt.QueuedConnection, Q_ARG(str, message)
        )

    def clear_output_area(self):
        QMetaObject.invokeMethod(
            self.output_area, "clear", Qt.QueuedConnection
        )

    def setup_email_sending_tab(self):
        layout = QFormLayout()

        # From Email (must be a verified identity)
        self.from_email_input = QComboBox(self)
        self.from_email_input.setEditable(True)
        layout.addRow(QLabel("From Email:"), self.from_email_input)

        # To Emails
        self.to_emails_input = QLineEdit(self)
        self.to_emails_input.setPlaceholderText("Enter recipient emails, separated by commas")
        layout.addRow(QLabel("To Emails:"), self.to_emails_input)

        # Subject
        self.email_subject_input = QLineEdit(self)
        self.email_subject_input.setPlaceholderText("Enter email subject")
        layout.addRow(QLabel("Subject:"), self.email_subject_input)

        # Body
        self.email_body_input = QTextEdit(self)
        self.email_body_input.setPlaceholderText("Enter email body")
        layout.addRow(QLabel("Body:"), self.email_body_input)

        # Execute Button
        self.execute_send_email_button = QPushButton("Send Email", self)
        self.execute_send_email_button.clicked.connect(self.execute_send_email)
        layout.addRow(self.execute_send_email_button)

        self.email_sending_tab.setLayout(layout)

    def setup_verified_identities_tab(self):
        layout = QFormLayout()

        # Add Verified Email Address
        self.add_email_button = QPushButton("Add Verified Email Address", self)
        self.add_email_button.clicked.connect(self.execute_add_verified_email)
        layout.addRow(QLabel("Add Verified Email:"), self.add_email_button)

        # Add Verified Domain
        self.add_domain_button = QPushButton("Add Verified Domain", self)
        self.add_domain_button.clicked.connect(self.execute_add_verified_domain)
        layout.addRow(QLabel("Add Verified Domain:"), self.add_domain_button)

        # Remove Verified Identity
        self.remove_identity_button = QPushButton("Remove Verified Identity", self)
        self.remove_identity_button.clicked.connect(self.execute_remove_verified_identity)
        layout.addRow(QLabel("Remove Verified Identity:"), self.remove_identity_button)

        self.verified_identities_tab.setLayout(layout)

    def setup_email_templates_tab(self):
        layout = QFormLayout()

        # Template Name
        self.template_name_input = QLineEdit(self)
        self.template_name_input.setPlaceholderText("Enter template name")
        layout.addRow(QLabel("Template Name:"), self.template_name_input)

        # Subject Part
        self.template_subject_input = QLineEdit(self)
        self.template_subject_input.setPlaceholderText("Enter template subject")
        layout.addRow(QLabel("Subject Part:"), self.template_subject_input)

        # Text Part
        self.template_text_input = QTextEdit(self)
        self.template_text_input.setPlaceholderText("Enter template text part")
        layout.addRow(QLabel("Text Part:"), self.template_text_input)

        # HTML Part
        self.template_html_input = QTextEdit(self)
        self.template_html_input.setPlaceholderText("Enter template HTML part")
        layout.addRow(QLabel("HTML Part:"), self.template_html_input)

        # Execute Buttons
        self.execute_create_template_button = QPushButton("Create Template", self)
        self.execute_create_template_button.clicked.connect(self.execute_create_template)
        layout.addRow(self.execute_create_template_button)

        self.update_template_button = QPushButton("Update Template", self)
        self.update_template_button.clicked.connect(self.execute_update_template)
        layout.addRow(self.update_template_button)

        self.delete_template_button = QPushButton("Delete Template", self)
        self.delete_template_button.clicked.connect(self.execute_delete_template)
        layout.addRow(self.delete_template_button)

        self.list_templates_button = QPushButton("List Templates", self)
        self.list_templates_button.clicked.connect(self.execute_list_templates)
        layout.addRow(self.list_templates_button)

        self.email_templates_tab.setLayout(layout)

    def setup_sending_statistics_tab(self):
        layout = QFormLayout()

        # Time Range Inputs
        self.start_time_input = QLineEdit(self)
        self.start_time_input.setPlaceholderText("Enter start time (e.g., 2023-01-01T00:00:00Z)")
        layout.addRow(QLabel("Start Time:"), self.start_time_input)

        self.end_time_input = QLineEdit(self)
        self.end_time_input.setPlaceholderText("Enter end time (e.g., 2023-12-31T23:59:59Z)")
        layout.addRow(QLabel("End Time:"), self.end_time_input)

        # Execute Button
        self.execute_view_statistics_button = QPushButton("View Sending Statistics", self)
        self.execute_view_statistics_button.clicked.connect(self.execute_view_sending_statistics)
        layout.addRow(self.execute_view_statistics_button)

        self.sending_statistics_tab.setLayout(layout)

    def setup_suppression_list_tab(self):
        layout = QFormLayout()

        # Add Email to Suppression List
        self.add_suppression_button = QPushButton("Add Email to Suppression List", self)
        self.add_suppression_button.clicked.connect(self.execute_add_suppression)
        layout.addRow(QLabel("Add Email:"), self.add_suppression_button)

        # Remove Email from Suppression List
        self.remove_suppression_button = QPushButton("Remove Email from Suppression List", self)
        self.remove_suppression_button.clicked.connect(self.execute_remove_suppression)
        layout.addRow(QLabel("Remove Email:"), self.remove_suppression_button)

        # List Suppression List
        self.list_suppression_button = QPushButton("List Suppression List", self)
        self.list_suppression_button.clicked.connect(self.execute_list_suppression)
        layout.addRow(QLabel("List Suppression:"), self.list_suppression_button)

        self.suppression_list_tab.setLayout(layout)

    # -------------------- Email Sending Functionality --------------------
    def execute_send_email(self):
        from_email = self.from_email_input.currentText()
        to_emails = self.to_emails_input.text()
        subject = self.email_subject_input.text()
        body = self.email_body_input.toPlainText()

        if not all([from_email, to_emails, subject, body]):
            self.signal_manager.message_signal.emit("Please fill all fields to send an email.")
            return

        to_emails_list = [email.strip() for email in to_emails.split(",") if email.strip()]

        self.run_in_thread(self._send_email, from_email, to_emails_list, subject, body)

    def _send_email(self, from_email, to_emails, subject, body):
        try:
            response = self.ses_client.send_email(
                Source=from_email,
                Destination={
                    'ToAddresses': to_emails
                },
                Message={
                    'Subject': {
                        'Data': subject
                    },
                    'Body': {
                        'Text': {
                            'Data': body
                        }
                    }
                }
            )
            message_id = response['MessageId']
            self.signal_manager.message_signal.emit(f"Email sent successfully! Message ID: {message_id}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error sending email: {str(e)}")

    # -------------------- Verified Identities Functionality --------------------
    def execute_add_verified_email(self):
        email_address, ok = QInputDialog.getText(
            self, "Add Verified Email", "Enter the email address to verify:"
        )
        if ok and email_address:
            self.run_in_thread(self._add_verified_email, email_address)

    def _add_verified_email(self, email_address):
        try:
            response = self.ses_client.verify_email_identity(EmailAddress=email_address)
            self.signal_manager.message_signal.emit(f"Verification email sent to {email_address}. Please check your inbox to verify.")
            self.run_in_thread(self.load_verified_identities)  # Refresh identities list
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error verifying email address: {str(e)}")

    def execute_add_verified_domain(self):
        domain, ok = QInputDialog.getText(
            self, "Add Verified Domain", "Enter the domain to verify:"
        )
        if ok and domain:
            self.run_in_thread(self._add_verified_domain, domain)

    def _add_verified_domain(self, domain):
        try:
            response = self.ses_client.verify_domain_identity(Domain=domain)
            verification_token = response['VerificationToken']
            self.signal_manager.message_signal.emit(
                f"Verification token for domain '{domain}': {verification_token}\n"
                f"Add a TXT record to your DNS settings to verify the domain."
            )
            self.run_in_thread(self.load_verified_identities)  # Refresh identities list
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error verifying domain: {str(e)}")

    def execute_remove_verified_identity(self):
        identity = self.verified_identities_dropdown.currentText()
        if not identity:
            self.signal_manager.message_signal.emit("Please select a verified identity to remove.")
            return

        confirm = QMessageBox.question(
            self, "Remove Verified Identity",
            f"Are you sure you want to remove the verified identity '{identity}'?",
            QMessageBox.Yes | QMessageBox.No
        )

        if confirm == QMessageBox.Yes:
            self.run_in_thread(self._remove_verified_identity, identity)

    def _remove_verified_identity(self, identity):
        try:
            self.ses_client.delete_identity(Identity=identity)
            self.signal_manager.message_signal.emit(f"Verified identity '{identity}' removed successfully.")
            self.run_in_thread(self.load_verified_identities)  # Refresh identities list
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error removing verified identity: {str(e)}")

    # -------------------- Email Templates Functionality --------------------
    def execute_create_template(self):
        template_name = self.template_name_input.text()
        subject_part = self.template_subject_input.text()
        text_part = self.template_text_input.toPlainText()
        html_part = self.template_html_input.toPlainText()

        if not all([template_name, subject_part, text_part, html_part]):
            self.signal_manager.message_signal.emit("Please fill all fields to create a template.")
            return

        self.run_in_thread(self._create_template, template_name, subject_part, text_part, html_part)

    def _create_template(self, template_name, subject_part, text_part, html_part):
        try:
            response = self.ses_client.create_template(
                Template={
                    'TemplateName': template_name,
                    'SubjectPart': subject_part,
                    'TextPart': text_part,
                    'HtmlPart': html_part
                }
            )
            self.signal_manager.message_signal.emit(f"Template '{template_name}' created successfully.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error creating template: {str(e)}")

    def execute_update_template(self):
        template_name, ok = QInputDialog.getText(
            self, "Update Template", "Enter the template name to update:"
        )
        if not ok or not template_name:
            return

        # Fetch existing template to pre-fill fields
        try:
            response = self.ses_client.get_template(TemplateName=template_name)
            current_template = response['Template']
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error fetching template: {str(e)}")
            return

        # Prompt user to enter new values (pre-filled with existing ones)
        subject_part, ok = QInputDialog.getText(
            self, "Update Template", "Enter new subject part:", text=current_template['SubjectPart']
        )
        if not ok or not subject_part:
            return

        text_part, ok = QInputDialog.getMultiLineText(
            self, "Update Template", "Enter new text part:", current_template['TextPart']
        )
        if not ok or not text_part:
            return

        html_part, ok = QInputDialog.getMultiLineText(
            self, "Update Template", "Enter new HTML part:", current_template['HtmlPart']
        )
        if not ok or not html_part:
            return

        self.run_in_thread(self._update_template, template_name, subject_part, text_part, html_part)

    def _update_template(self, template_name, subject_part, text_part, html_part):
        try:
            response = self.ses_client.update_template(
                Template={
                    'TemplateName': template_name,
                    'SubjectPart': subject_part,
                    'TextPart': text_part,
                    'HtmlPart': html_part
                }
            )
            self.signal_manager.message_signal.emit(f"Template '{template_name}' updated successfully.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error updating template: {str(e)}")

    def execute_delete_template(self):
        template_name, ok = QInputDialog.getText(
            self, "Delete Template", "Enter the template name to delete:"
        )
        if not ok or not template_name:
            return

        confirm = QMessageBox.question(
            self, "Delete Template",
            f"Are you sure you want to delete the template '{template_name}'?",
            QMessageBox.Yes | QMessageBox.No
        )

        if confirm == QMessageBox.Yes:
            self.run_in_thread(self._delete_template, template_name)

    def _delete_template(self, template_name):
        try:
            response = self.ses_client.delete_template(TemplateName=template_name)
            self.signal_manager.message_signal.emit(f"Template '{template_name}' deleted successfully.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error deleting template: {str(e)}")

    def execute_list_templates(self):
        self.run_in_thread(self._list_templates)

    def _list_templates(self):
        try:
            paginator = self.ses_client.get_paginator('list_templates')
            templates = []
            for page in paginator.paginate():
                templates.extend(page['TemplatesMetadata'])
            if templates:
                templates_list = "\n".join([f"Name: {t['Name']}, Created: {t['CreatedTimestamp']}" for t in templates])
                self.signal_manager.message_signal.emit(f"Templates:\n{templates_list}")
            else:
                self.signal_manager.message_signal.emit("No templates found.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error listing templates: {str(e)}")

    # -------------------- Sending Statistics Functionality --------------------
    def execute_view_sending_statistics(self):
        start_time = self.start_time_input.text()
        end_time = self.end_time_input.text()

        if not all([start_time, end_time]):
            self.signal_manager.message_signal.emit("Please enter both start time and end time.")
            return

        self.run_in_thread(self._view_sending_statistics, start_time, end_time)

    def _view_sending_statistics(self, start_time, end_time):
        try:
            # SES does not provide direct API for sending statistics.
            # Typically, you'd use Amazon CloudWatch for monitoring SES metrics.
            # For demonstration, we'll fetch CloudWatch metrics related to SES.

            cloudwatch = self.current_session.client('cloudwatch')

            metrics = [
                'Send',
                'Reject',
                'Bounce',
                'Complaint',
                'Delivery',
                'Open',
                'Click',
                'Rendering Failure'
            ]

            statistics = {}
            for metric in metrics:
                response = cloudwatch.get_metric_statistics(
                    Namespace='AWS/SES',
                    MetricName=metric,
                    Dimensions=[
                        {
                            'Name': 'SESIdentity',
                            'Value': 'All'  # Modify as needed
                        },
                    ],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400,  # Daily
                    Statistics=['Sum']
                )
                datapoints = response.get('Datapoints', [])
                total = sum([dp['Sum'] for dp in datapoints])
                statistics[metric] = total

            stats_str = "\n".join([f"{metric}: {count}" for metric, count in statistics.items()])
            self.signal_manager.message_signal.emit(f"Sending Statistics from {start_time} to {end_time}:\n{stats_str}")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error fetching sending statistics: {str(e)}")

    # -------------------- Suppression List Management Functionality --------------------
    def execute_add_suppression(self):
        email_address, ok = QInputDialog.getText(
            self, "Add to Suppression List", "Enter the email address to suppress:"
        )
        if not ok or not email_address:
            return

        self.run_in_thread(self._add_suppression, email_address)

    def _add_suppression(self, email_address):
        try:
            response = self.ses_client.put_suppressed_destination(
                EmailAddress=email_address,
                Reason='BOUNCE'  # Can be BOUNCE or COMPLAINT
            )
            self.signal_manager.message_signal.emit(f"Email address '{email_address}' added to suppression list.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error adding to suppression list: {str(e)}")

    def execute_remove_suppression(self):
        email_address, ok = QInputDialog.getText(
            self, "Remove from Suppression List", "Enter the email address to remove:"
        )
        if not ok or not email_address:
            return

        self.run_in_thread(self._remove_suppression, email_address)

    def _remove_suppression(self, email_address):
        try:
            response = self.ses_client.delete_suppressed_destination(
                EmailAddress=email_address
            )
            self.signal_manager.message_signal.emit(f"Email address '{email_address}' removed from suppression list.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error removing from suppression list: {str(e)}")

    def execute_list_suppression(self):
        self.run_in_thread(self._list_suppression)

    def _list_suppression(self):
        try:
            paginator = self.ses_client.get_paginator('list_suppressed_destinations')
            suppressed = []
            for page in paginator.paginate():
                for dest in page.get('SuppressedDestinationSummaries', []):
                    suppressed.append(f"Email: {dest['EmailAddress']}, Reason: {dest['Reason']}, CreatedAt: {dest['CreatedTimestamp']}")
            if suppressed:
                suppressed_list = "\n".join(suppressed)
                self.signal_manager.message_signal.emit(f"Suppressed Destinations:\n{suppressed_list}")
            else:
                self.signal_manager.message_signal.emit("Suppression list is empty.")
        except botocore.exceptions.ClientError as e:
            self.signal_manager.message_signal.emit(f"Error listing suppression list: {str(e)}")
