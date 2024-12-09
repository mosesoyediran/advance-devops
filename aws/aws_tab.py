import boto3
import botocore
from PyQt5.QtCore import QObject, QThread, pyqtSignal
from PyQt5.QtWidgets import (QButtonGroup, QComboBox, QFormLayout, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QRadioButton,
                             QTextEdit, QVBoxLayout, QWidget)

from aws.cloud_formation_tab import CloudFormationTab
from aws.dynamo_db import DynamoDBTab
from aws.ec2_tab import EC2Tab  # Import the EC2Tab
from aws.eks_tab import EKSTab  # Import the EKSTab
from aws.elastic_cache_tab import ElastiCacheTab
from aws.elb_tab import ELBTab
from aws.iam_tab import IAMTab  # Import the IAMTab
from aws.lamda_tab import LambdaTab  # Import the LambdaTab
from aws.rds_tab import RDSTab  # Import the RDSTab
from aws.s3_tab import S3Tab  # Import the S3Tab
from aws.ses_tab import SESTab  # Import the SESTab


class Worker(QObject):
    finished = pyqtSignal()
    result = pyqtSignal(object)

    def __init__(self, function, *args, **kwargs):
        super().__init__()
        self.function = function
        self.args = args
        self.kwargs = kwargs

    def run(self):
        """Run the function with the provided arguments and emit the result."""
        try:
            result = self.function(*self.args, **self.kwargs)
            self.result.emit(result)
        except Exception as e:
            self.result.emit(f"Error: {str(e)}")
        finally:
            self.finished.emit()


class AWSTab(QWidget):
    def __init__(self, auth_manager, main_tab_widget):
        super().__init__()
        self.auth_manager = auth_manager
        self.main_tab_widget = main_tab_widget
        self.s3_tab = None  # Placeholder for S3Tab
        self.current_session = None  # Placeholder for current AWS session
        self.initUI()

    def initUI(self):
        main_layout = QHBoxLayout()

        # Left Column
        left_column = QVBoxLayout()

        # Back to System Button
        back_button = QPushButton("Back to System")
        back_button.clicked.connect(self.go_back_to_system)

        main_layout.addWidget(back_button)

        aws_form_layout = QFormLayout()

        # Radio buttons to choose between default credentials and new login
        self.default_credentials_radio = QRadioButton("Use default AWS CLI credentials", self)
        self.new_login_radio = QRadioButton("New Login", self)

        # Grouping radio buttons so only one can be selected at a time
        self.credentials_group = QButtonGroup(self)
        self.credentials_group.addButton(self.default_credentials_radio)
        self.credentials_group.addButton(self.new_login_radio)

        self.default_credentials_radio.setChecked(True)  # Default selection

        self.credentials_group.buttonClicked.connect(self.toggle_credentials_input)

        # Default credentials display (will be shown when "Use default AWS CLI credentials" is selected)
        self.aws_default_credentials_label = QLabel(self)

        # Login inputs - initially hidden
        self.aws_access_key_label = QLabel("Access Key:", self)
        self.aws_access_key_input = QLineEdit(self)
        self.aws_access_key_input.setPlaceholderText("Enter AWS Access Key")

        self.aws_secret_key_label = QLabel("Secret Key:", self)
        self.aws_secret_key_input = QLineEdit(self)
        self.aws_secret_key_input.setPlaceholderText("Enter AWS Secret Key")
        self.aws_secret_key_input.setEchoMode(QLineEdit.Password)

        self.aws_region_label = QLabel("Region:", self)
        self.aws_region_input = QLineEdit(self)
        self.aws_region_input.setPlaceholderText("Enter AWS Region")

        # Service dropdown
        self.aws_service_input = QComboBox(self)
        self.aws_service_input.addItems([ "s3", "iam", "rds","ec2", "eks", "lambda", "ses", "cloudformation", "elb", "elastiCache", "dynamodb" ]) 

        # Add radio buttons to the layout
        aws_form_layout.addRow(self.default_credentials_radio)
        aws_form_layout.addRow(self.new_login_radio)

        # Add the default credentials display label
        aws_form_layout.addRow(QLabel("AWS Credentials:"))
        aws_form_layout.addRow(self.aws_default_credentials_label)

        # Add credentials input fields to the layout but hide them initially
        aws_form_layout.addRow(self.aws_access_key_label, self.aws_access_key_input)
        aws_form_layout.addRow(self.aws_secret_key_label, self.aws_secret_key_input)
        aws_form_layout.addRow(self.aws_region_label, self.aws_region_input)
        aws_form_layout.addRow("Service:", self.aws_service_input)

        self.aws_connect_button = QPushButton("Connect", self)
        self.aws_connect_button.clicked.connect(self.run_service_command)

        left_column.addLayout(aws_form_layout)
        left_column.addWidget(self.aws_connect_button)

        # Right Column
        right_column = QVBoxLayout()
        self.aws_output = QTextEdit(self)
        self.aws_output.setReadOnly(True)  # Ensure the output is read-only
        right_column.addWidget(self.aws_output)

        main_layout.addLayout(left_column)
        main_layout.addLayout(right_column)
        self.setLayout(main_layout)

        # Initially toggle based on the default setting
        self.toggle_credentials_input()

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

    def toggle_credentials_input(self):
        """
        Show or hide manual credentials input and display default credentials based on the selected radio button.
        """
        use_default = self.default_credentials_radio.isChecked()

        # Hide or show the manual input fields and their labels
        self.aws_access_key_label.setVisible(not use_default)
        self.aws_access_key_input.setVisible(not use_default)
        self.aws_secret_key_label.setVisible(not use_default)
        self.aws_secret_key_input.setVisible(not use_default)
        self.aws_region_label.setVisible(not use_default)
        self.aws_region_input.setVisible(not use_default)

        # If using default credentials, display the default credentials summary
        if use_default:
            session = boto3.Session()
            credentials = session.get_credentials()
            region = session.region_name

            if credentials:
                access_key = credentials.access_key
                self.aws_default_credentials_label.setText(
                    f"Access Key: {access_key}\nRegion: {region if region else 'Not Set'}"
                )
            else:
                self.aws_default_credentials_label.setText("No AWS CLI credentials found.")

            self.aws_default_credentials_label.setVisible(True)
        else:
            # Hide the default credentials display
            self.aws_default_credentials_label.setVisible(False)

    def run_service_command(self):
        """
        Determine which service is selected and run the operation in a separate thread.
        """
        service = self.aws_service_input.currentText()

        # Create a session based on the selected credentials
        if self.default_credentials_radio.isChecked():
            self.current_session = boto3.Session()
        else:
            access_key = self.aws_access_key_input.text()
            secret_key = self.aws_secret_key_input.text()
            region = self.aws_region_input.text()
            self.current_session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region
            )

        # Perform the selected service operation in a separate thread
        if service == "s3":
            self.run_in_thread(self.connect_to_s3, self.current_session)
        elif service == "iam":
            self.run_in_thread(self.connect_to_iam, self.current_session)
        elif service == "rds":
            self.run_in_thread(self.connect_to_rds, self.current_session)
        elif service == "ec2":  
            self.run_in_thread(self.connect_to_ec2, self.current_session)
        elif service == "eks":
            self.run_in_thread(self.connect_to_eks, self.current_session)
        elif service == "lambda":
            self.run_in_thread(self.connect_to_lambda, self.current_session)
        elif service == "ses":
            self.run_in_thread(self.connect_to_ses, self.current_session)
        elif service == "cloudformation":
            self.run_in_thread(self.connect_to_cloudformation, self.current_session)
        elif service == "elb":
            self.run_in_thread(self.connect_to_elb, self.current_session)
        elif service == "elastiCache":
            self.run_in_thread(self.connect_to_elastiCache, self.current_session)
        elif service == "dynamodb":
            self.run_in_thread(self.connect_to_dynamodb, self.current_session)
    

    def run_in_thread(self, function, *args, **kwargs):
        """
        Run a given function in a separate thread.
        """
        self.thread = QThread()  # Create a new thread
        self.worker = Worker(function, *args, **kwargs)  # Create a worker to run the function
        self.worker.moveToThread(self.thread)  # Move the worker to the thread

        # Connect signals and slots
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.worker.result.connect(self.process_result)

        # Start the thread
        self.thread.start()

    def connect_to_iam(self, session):
        """
        Connect to IAM and return a message indicating success.
        """
        try:
            return "Connected to IAM. Now you can create IAM UI elements in the main thread."
        except botocore.exceptions.BotoCoreError as e:
            return f"Error: {str(e)}"
        
    def connect_to_rds(self, session):
        """
        Connect to RDS and return a message indicating success.
        """
        try:
            # The actual connection to RDS is handled here.
            rds_client = session.client('rds')
            return "Connected to RDS. Now you can create RDS UI elements in the main thread."
        except botocore.exceptions.BotoCoreError as e:
            return f"Error: {str(e)}"
        
    def connect_to_s3(self, session):
        """
        Connect to S3 and return a message indicating success.
        """
        try:
            # The actual connection to S3 is handled here.
            s3_client = session.client('s3')
            return "Connected to S3. Now you can create S3 UI elements in the main thread."
        except botocore.exceptions.BotoCoreError as e:
            return f"Error: {str(e)}"
        
    def connect_to_ec2(self, session):
        """
        Connect to EC2 and return a message indicating success.
        """
        try:
            ec2_client = session.client('ec2')
            return "Connected to EC2. Now you can create EC2 UI elements in the main thread."
        except botocore.exceptions.BotoCoreError as e:
            return f"Error: {str(e)}"
        
    def connect_to_eks(self, session):
        """
        Connect to EKS and return a message indicating success.
        """
        try: 
            eks_client = session.client('eks')
            return "Connected to EKS. Now you can create EKS UI elements in the main thread."
        except botocore.exceptions.BotoCoreError as e:
            return f"Error: {str(e)}"
        
    def connect_to_lambda(self, session):
        """
        Connect to Lambda and return a message indicating success.
        """
        try:
            lambda_client = session.client('lambda')
            return "Connected to Lambda. Now you can create Lambda UI elements in the main thread."
        except botocore.exceptions.BotoCoreError as e:
            return f"Error: {str(e)}"
        
    def connect_to_ses(self, session):
        """
        Connect to SES and return a message indicating success.
        """
        try:
            ses_client = session.client('ses')
            return "Connected to SES. Now you can create SES UI elements in the main thread."
        except botocore.exceptions.BotoCoreError as e:
            return f"Error: {str(e)}"
        
    def connect_to_cloudformation(self, session):
        """
        Connect to CloudFormation and return a message indicating success.
        """
        try:
            cloudformation_client = session.client('cloudformation')
            return "Connected to CloudFormation. Now you can create CloudFormation UI elements in the main thread."
        except botocore.exceptions.BotoCoreError as e:
            return f"Error: {str(e)}"
    
    def connect_to_elb(self, session):
        """
        Connect to ELB and return a message indicating success.
        """
        try:
            elb_client = session.client('elb')
            return "Connected to ELB. Now you can create ELB UI elements in the main thread."
        except botocore.exceptions.BotoCoreError as e:
            return f"Error: {str(e)}"
        
    def connect_to_elastiCache(self, session):
        """
        Connect to ElastiCache and return a message indicating success.
        """
        try:
            elastiCache_client = session.client('elasticache')
            return "Connected to ElastiCache. Now you can create ElastiCache UI elements in the main thread."
        except botocore.exceptions.BotoCoreError as e:
            return f"Error: {str(e)}"
        
    def connect_to_dynamodb(self, session):
        """
        Connect to DynamoDB and return a message indicating success.
        """
        try:
            dynamodb_client = session.client('dynamodb')
            return "Connected to DynamoDB. Now you can create DynamoDB UI elements in the main thread."
        except botocore.exceptions.BotoCoreError as e:
            return f"Error: {str(e)}"

    def process_result(self, result):
        """
        Process the result from the worker thread.
        """
        if "Connected to IAM" in result:
            # Create IAM tab in the main thread after successful IAM connection
            iam_tab = IAMTab(self.current_session)  # Session is passed here
            self.main_tab_widget.addTab(iam_tab, "IAM")
            self.main_tab_widget.setCurrentWidget(iam_tab)
        elif "Connected to S3" in result:
            # Create S3 tab in the main thread after successful S3 connection
            s3_tab = S3Tab(self.current_session)  # Session is passed here
            self.main_tab_widget.addTab(s3_tab, "S3")
            self.main_tab_widget.setCurrentWidget(s3_tab)
        elif "Connected to RDS" in result:
            rds_tab = RDSTab(self.current_session)  # Session is passed here
            self.main_tab_widget.addTab(rds_tab, "RDS")
            self.main_tab_widget.setCurrentWidget(rds_tab)
            
        elif "Connected to EC2" in result:  # Handle EC2 connection
            ec2_tab = EC2Tab(self.current_session)  # You need to create an EC2Tab class
            self.main_tab_widget.addTab(ec2_tab, "EC2")
            self.main_tab_widget.setCurrentWidget(ec2_tab)
            
        elif "Connected to EKS" in result:  # Handle EKS connection
            eks_tab = EKSTab(self.current_session)  # You need to create an EKSTab class
            self.main_tab_widget.addTab(eks_tab, "EKS")
            self.main_tab_widget.setCurrentWidget(eks_tab)
            
        elif "Connected to Lambda" in result:  # Handle Lambda connection
            lambda_tab = LambdaTab(self.current_session)  # You need to create an LambdaTab class
            self.main_tab_widget.addTab(lambda_tab, "Lambda")
            self.main_tab_widget.setCurrentWidget(lambda_tab)
            
        elif "Connected to SES" in result:  # Handle SES connection
            ses_tab = SESTab(self.current_session)  # You need to create an SESTab class
            self.main_tab_widget.addTab(ses_tab, "SES")
            self.main_tab_widget.setCurrentWidget(ses_tab)
        
        elif "Connected to CloudFormation" in result:  # Handle CloudFormation connection
            cloud_formation_tab = CloudFormationTab(self.current_session)  # You need to create an CloudFormationTab class
            self.main_tab_widget.addTab(cloud_formation_tab, "CloudFormation")
            self.main_tab_widget.setCurrentWidget(cloud_formation_tab)
            
        elif "Connected to ELB" in result:  # Handle ELB connection
            elb_tab = ELBTab(self.current_session)  # You need to create an ELBTab class
            self.main_tab_widget.addTab(elb_tab, "ELB")
            self.main_tab_widget.setCurrentWidget(elb_tab)
            
        elif "Connected to ElastiCache" in result:  # Handle ElastiCache connection
            elastiCache_tab = ElastiCacheTab(self.current_session)  # You need to create an ElastiCacheTab class
            self.main_tab_widget.addTab(elastiCache_tab, "ElastiCache")
            self.main_tab_widget.setCurrentWidget(elastiCache_tab)
            
        elif "Connected to DynamoDB" in result:  # Handle DynamoDB connection
            dynamodb_tab = DynamoDBTab(self.current_session)  # You need to create an DynamoDBTab class
            self.main_tab_widget.addTab(dynamodb_tab, "DynamoDB")
            self.main_tab_widget.setCurrentWidget(dynamodb_tab)

        # Display the result in the output area
        self.aws_output.append(result)
