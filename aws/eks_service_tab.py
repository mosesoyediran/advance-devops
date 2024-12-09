import base64
import datetime
import json
import os
import subprocess
import tempfile

import boto3
import yaml
from kubernetes import client, config
from PyQt5.QtWidgets import (QComboBox, QFileDialog, QHBoxLayout, QLabel,
                             QLineEdit, QPushButton, QTextEdit, QVBoxLayout,
                             QWidget)


class ServiceManagementTab(QWidget):
    def __init__(self, session):
        super().__init__()
        self.eks_client = None
        self.selected_region = None
        self.selected_cluster = None
        self.session = session  
        self.initUI()

    def initUI(self):
        """Initialize the UI for the Service Management tab."""
        main_layout = QHBoxLayout()

        # Left Column Layout for Controls
        left_column_layout = QVBoxLayout()

        # Region selection row
        region_selection_layout = QHBoxLayout()
        region_selection_layout.addWidget(QLabel("Select Region:"))
        self.region_dropdown = QComboBox()
        self.region_dropdown.currentIndexChanged.connect(self.on_region_selected)  # Handle region selection
        region_selection_layout.addWidget(self.region_dropdown)
        left_column_layout.addLayout(region_selection_layout)

        # Cluster selection row
        cluster_selection_layout = QHBoxLayout()
        cluster_selection_layout.addWidget(QLabel("Select Cluster:"))
        self.cluster_dropdown = QComboBox()
        self.cluster_dropdown.currentIndexChanged.connect(self.on_cluster_selected)  # Handle cluster selection
        cluster_selection_layout.addWidget(self.cluster_dropdown)
        left_column_layout.addLayout(cluster_selection_layout)
        
        
        # Namespace selection row
        namespace_selection_layout = QHBoxLayout()
        namespace_selection_layout.addWidget(QLabel("Select Namespace:"))
        self.namespace_dropdown = QComboBox()
        self.namespace_dropdown.currentIndexChanged.connect(self.on_namespace_selected)
        namespace_selection_layout.addWidget(self.namespace_dropdown)
        left_column_layout.addLayout(namespace_selection_layout)
        
        
        

        # Service Management Dropdown
        left_column_layout.addWidget(QLabel("Service Management:"))
        
        service_selection_layout = QHBoxLayout()
        service_selection_layout.addWidget(QLabel("Select Service:"))
        self.service_dropdown = QComboBox()
        service_selection_layout.addWidget(self.service_dropdown)
        left_column_layout.addLayout(service_selection_layout)
        
        dynamic_input_layout = QHBoxLayout()

        # Label Key
        dynamic_input_layout.addWidget(QLabel("Label Key:"))
        self.label_key_input = QLineEdit()  # Input for dynamic label key
        self.label_key_input.setFixedWidth(100)  # Make the textbox smaller
        dynamic_input_layout.addWidget(self.label_key_input)

        # Label Value
        dynamic_input_layout.addWidget(QLabel("Label Value:"))
        self.label_value_input = QLineEdit()  # Input for dynamic label value
        self.label_value_input.setFixedWidth(100)  # Make the textbox smaller
        dynamic_input_layout.addWidget(self.label_value_input)

        # Port
        dynamic_input_layout.addWidget(QLabel("Port:"))
        self.port_input = QLineEdit()  # Input for port
        self.port_input.setFixedWidth(80)  # Make the textbox smaller
        self.port_input.setPlaceholderText("e.g., 8080")
        dynamic_input_layout.addWidget(self.port_input)

        # Target Port
        dynamic_input_layout.addWidget(QLabel("Target Port:"))
        self.target_port_input = QLineEdit()  # Input for target port
        self.target_port_input.setFixedWidth(80)  # Make the textbox smaller
        self.target_port_input.setPlaceholderText("e.g., 80")
        dynamic_input_layout.addWidget(self.target_port_input)

        # Add the dynamic input layout to the left column layout
        left_column_layout.addLayout(dynamic_input_layout)
        
        # Replica scaling input
        replica_layout = QHBoxLayout()
        replica_layout.addWidget(QLabel("Replicas:"))
        self.replicas_input = QLineEdit()  # Input for replicas
        self.replicas_input.setPlaceholderText("e.g., 3")
        self.replicas_input.setFixedWidth(80)  # Adjust width
        replica_layout.addWidget(self.replicas_input)
        
        left_column_layout.addLayout(replica_layout)

        
        self.service_management_dropdown = QComboBox()
        self.service_management_dropdown.addItems([
            "Get Services", 
            "Delete Service", 
            "Apply Config",
            "Update Service", 
            "Scale Service", 
            "Patch Service", 
            "Describe Service", 
            "List Endpoints", 
            "Get Service Metrics", 
            "Restart Service", 
            "Expose Service", 
            "Port Forward Service", 
            "Delete All Services in Namespace"
        ])
        left_column_layout.addWidget(self.service_management_dropdown)
        
        # Upload config file section
        self.upload_button = QPushButton("Upload Config.yaml")
        self.upload_button.clicked.connect(self.browse_file)
        left_column_layout.addWidget(self.upload_button)

        self.config_input = QLineEdit()  # Display the file path
        self.config_input.setPlaceholderText("No file selected")
        left_column_layout.addWidget(self.config_input)

        # Execute button
        self.execute_button = QPushButton("Execute")
        self.execute_button.clicked.connect(self.execute_service_management)
        left_column_layout.addWidget(self.execute_button)

        # Right Column for Output
        right_column_layout = QVBoxLayout()

        # Text area to show the output
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)  # Make the output read-only
        right_column_layout.addWidget(self.output_area)

        # Add both columns to the main layout
        main_layout.addLayout(left_column_layout, 1)  # 1/2 of the screen
        main_layout.addLayout(right_column_layout, 2)  # 2/3 of the screen for output

        # Set the main layout for the ServiceManagementTab
        self.setLayout(main_layout)
        
        # Populate the region dropdown with available regions
        self.populate_region_dropdown() 

    def load_kubernetes_config_from_eks(self):
        """Load Kubernetes configuration dynamically from the EKS cluster using boto3."""
        cluster_name = self.cluster_dropdown.currentText()
        region = self.selected_region

        if not cluster_name or not region:
            self.show_output("No cluster or region selected.")
            return

        try:
            eks_client = boto3.client('eks', region_name=region)
            cluster_info = eks_client.describe_cluster(name=cluster_name)['cluster']

            # Extract the necessary details
            cluster_endpoint = cluster_info['endpoint']
            cluster_ca_data = cluster_info['certificateAuthority']['data']
            cluster_token = self.get_eks_bearer_token(cluster_name, region)

            if not cluster_token:
                raise ValueError("Failed to retrieve EKS token.")

            # Configure Kubernetes client directly
            configuration = client.Configuration()
            configuration.host = cluster_endpoint
            configuration.verify_ssl = True
            ca_cert_path = self.get_ca_cert_file(cluster_ca_data)  # Get CA cert file
            if not ca_cert_path:
                raise ValueError("Failed to process CA certificate.")
            configuration.ssl_ca_cert = ca_cert_path
            configuration.api_key = {"authorization": "Bearer " + cluster_token}

            client.Configuration.set_default(configuration)
            self.show_output(f"Kubernetes config loaded for cluster: {cluster_name}")

        except Exception as e:
            self.show_output(f"Error loading Kubernetes config: {str(e)}")

  
    def get_ca_cert_file(self, ca_data):
        """Decode the CA certificate and write it to a temporary file."""
        try:
            decoded_ca_data = base64.b64decode(ca_data)
            temp_file = tempfile.NamedTemporaryFile(delete=False)
            temp_file.write(decoded_ca_data)
            temp_file.close()
            return temp_file.name
        except Exception as e:
            self.show_output(f"Error processing CA certificate: {str(e)}")
            return None

    def get_eks_bearer_token(self, cluster_name, region):
        """Get the EKS bearer token using boto3."""
        try:
            token_command = f"aws eks get-token --cluster-name {cluster_name} --region {region}"
            token_output = subprocess.check_output(token_command, shell=True).decode('utf-8')
            token_json = json.loads(token_output)
            return token_json['status']['token']
        except Exception as e:
            self.show_output(f"Error getting EKS token: {str(e)}")
            return None

    def show_output(self, message):
        """Display output in the output area."""
        if self.output_area is not None:
            self.output_area.append(message)
        else:
            print(f"Output Area is None. Message: {message}")


    def populate_region_dropdown(self):
        """Populate the regions dropdown with available AWS regions."""
        try:
            ec2_client = boto3.client('ec2')
            regions = ec2_client.describe_regions()['Regions']
            region_names = [region['RegionName'] for region in regions]
            self.region_dropdown.addItems(region_names)
        except Exception as e:
            self.show_output(f"Error fetching regions: {str(e)}")

    def on_region_selected(self):
        """When a region is selected, update the cluster dropdown."""
        self.selected_region = self.region_dropdown.currentText()
        if self.selected_region:
            self.populate_cluster_dropdown()
        else:
            self.show_output("No region selected.")
            
    def populate_cluster_dropdown(self):
        """Populate the cluster dropdown based on the selected region."""
        if self.selected_region is None:
            self.show_output("No region selected.")
            return

        self.cluster_dropdown.clear()  # Clear any existing clusters
        try:
            eks_client = boto3.client('eks', region_name=self.selected_region)
            clusters = eks_client.list_clusters()["clusters"]
            self.cluster_dropdown.addItems(clusters)
        except Exception as e:
            self.show_output(f"Error fetching clusters: {str(e)}")

    def on_cluster_selected(self):
        """When a cluster is selected, populate the namespaces and services."""
        self.selected_cluster = self.cluster_dropdown.currentText()
        if self.selected_cluster:
            self.populate_namespace_dropdown()
            self.show_output(f"Selected cluster: {self.selected_cluster}")
        else:
            self.show_output("No cluster selected.")
        
    def populate_namespace_dropdown(self):
        """Populate the namespace dropdown based on the selected cluster."""
        self.load_kubernetes_config_from_eks()
        self.namespace_dropdown.clear()  # Clear the existing namespaces

        try:
            v1 = client.CoreV1Api()
            namespaces = v1.list_namespace().items

            if not namespaces:
                self.show_output("No namespaces found.")
                return

            # Populate the namespace dropdown
            for ns in namespaces:
                self.namespace_dropdown.addItem(ns.metadata.name)
            
            self.show_output("Namespaces loaded successfully.")

        except Exception as e:
            self.show_output(f"Error fetching namespaces: {str(e)}")

    def populate_service_dropdown(self):
        """Populate the service dropdown based on the selected namespace."""
        selected_namespace = self.namespace_dropdown.currentText()

        if not selected_namespace:
            self.show_output("No namespace selected.")
            return

        self.load_kubernetes_config_from_eks()
        self.service_dropdown.clear()  # Clear the existing services

        try:
            v1 = client.CoreV1Api()
            services = v1.list_namespaced_service(namespace=selected_namespace).items

            if not services:
                self.show_output(f"No services found in namespace {selected_namespace}.")
                return

            # Populate the service dropdown
            for svc in services:
                self.service_dropdown.addItem(svc.metadata.name)

            self.show_output(f"Services in namespace {selected_namespace} loaded successfully.")

        except Exception as e:
            self.show_output(f"Error fetching services: {str(e)}")

    def on_namespace_selected(self):
        """When a namespace is selected, populate the services."""
        self.populate_service_dropdown()


    def browse_file(self):
        """Open a file dialog to select a config.yaml file."""
        file_path, _ = QFileDialog.getOpenFileName(self, "Open YAML Config File", "", "YAML Files (*.yaml *.yml)")

        if file_path:
            self.config_input.setText(file_path)  # Display the selected file path in the text input
        else:
            self.show_output("No file selected.")






### Service Management Tab ###

    def execute_service_management(self):
        """Handle execution of service management based on selected action."""
        action = self.service_management_dropdown.currentText()
        

        if action == "Get Services":
            self.get_services()
        elif action == "Delete Service":
            self.delete_service()
        elif action == "Apply Config":
            self.apply_config()
        elif action == "Update Service":
            self.update_service()
        elif action == "Scale Service":
            self.scale_service()
        elif action == "Patch Service":
            self.patch_service()
        elif action == "Describe Service":
            self.describe_service()
        elif action == "List Endpoints":
            self.list_endpoints()
        elif action == "Get Service Metrics":
            self.get_service_metrics()
        elif action == "Restart Service":
            self.restart_service()
        elif action == "Expose Service":
            self.expose_service()
        elif action == "Port Forward Service":
            self.port_forward_service()
        elif action == "Delete All Services in Namespace":
            self.delete_all_services_in_namespace()
        
            
            
    def get_services(self):
        """Get the list of services in the current Kubernetes cluster and display in a table format."""
        self.load_kubernetes_config_from_eks()

        try:
            v1 = client.CoreV1Api()
            services = v1.list_service_for_all_namespaces().items

            if not services:
                self.show_output("No services found.")
                return

            # Header for the table
            output = f"{'Name':<30} {'Type':<15} {'Cluster IP/Port':<45} {'External IP':<25}\n"
            output += "-" * 120 + "\n"

            # Format and display each service in the table
            for svc in services:
                name = svc.metadata.name
                svc_type = svc.spec.type
                cluster_ip = svc.spec.cluster_ip
                ports = ', '.join([f"{port.port}/{port.protocol}" for port in svc.spec.ports])  # Format port with protocol
                cluster_ip_ports = f"{cluster_ip}:{ports}" if ports else cluster_ip
                external_ip = ', '.join(svc.status.load_balancer.ingress[0].ip for ingress in svc.status.load_balancer.ingress) if svc.status.load_balancer and svc.status.load_balancer.ingress else "None"
                
                # Add row to the output
                output += f"{name:<30} {svc_type:<15} {cluster_ip_ports:<45} {external_ip:<25}\n"

            # Show the formatted output in the text area
            self.show_output(output)

        except Exception as e:
            self.show_output(f"Error getting services: {str(e)}")

            
            
    def delete_service(self):
        """Delete a specified service."""
        service_name = self.service_dropdown.currentText().strip()

        if not service_name:
            self.show_output("No service selected.")
            return

        self.load_kubernetes_config_from_eks()

        try:
            v1 = client.CoreV1Api()
            v1.delete_namespaced_service(
                name=service_name,
                namespace=self.namespace_dropdown.currentText()  # Fetch the selected namespace from dropdown
            )
            self.show_output(f"Service {service_name} deleted.")
        except Exception as e:
            self.show_output(f"Error deleting service {service_name}: {str(e)}")

  
      
    def apply_config(self):
        """Apply a config.yaml with multiple documents to the Kubernetes cluster."""
        config_path = self.config_input.text().strip()

        if not config_path or not os.path.exists(config_path):
            self.show_output(f"Invalid or missing config file path: {config_path}")
            return

        self.load_kubernetes_config_from_eks()

        try:
            with open(config_path, 'r') as f:
                configs = yaml.safe_load_all(f)  # Use safe_load_all to handle multiple documents

                for config_data in configs:
                    kind = config_data.get("kind")
                    namespace = config_data.get('metadata', {}).get('namespace', 'default')

                    # Apply the configuration based on the resource kind
                    if kind == "Deployment":
                        k8s_api = client.AppsV1Api()
                        k8s_api.create_namespaced_deployment(
                            namespace=namespace,
                            body=config_data
                        )
                        self.show_output(f"Deployment applied in namespace: {namespace}")

                    elif kind == "Service":
                        k8s_api = client.CoreV1Api()
                        k8s_api.create_namespaced_service(
                            namespace=namespace,
                            body=config_data
                        )
                        self.show_output(f"Service applied in namespace: {namespace}")

                    else:
                        self.show_output(f"Unsupported resource kind: {kind}")

                self.show_output(f"Config file applied successfully: {config_path}")

        except Exception as e:
            self.show_output(f"Error applying config file: {str(e)}")


            
    def update_service(self):
        """Update the configuration of a service dynamically."""
        service_name = self.service_dropdown.currentText().strip()
        namespace = self.namespace_dropdown.currentText().strip()
        label_key = self.label_key_input.text().strip()
        label_value = self.label_value_input.text().strip()
        port = self.port_input.text().strip()
        target_port = self.target_port_input.text().strip()

        if not service_name or not namespace:
            self.show_output("Please select a service and a namespace.")
            return

        self.load_kubernetes_config_from_eks()

        try:
            v1 = client.CoreV1Api()

            # Dynamically construct the patch body based on user input
            patch_body = {
                "metadata": {
                    "labels": {
                        label_key: label_value  # Use dynamic label key and value
                    }
                },
                "spec": {
                    "ports": []
                }
            }

            # Add ports to the patch body if provided
            if port and target_port:
                patch_body["spec"]["ports"].append({
                    "port": int(port),  # Convert to integer
                    "targetPort": int(target_port)  # Convert to integer
                })

            # Update the service with the dynamic patch body
            v1.patch_namespaced_service(name=service_name, namespace=namespace, body=patch_body)
            self.show_output(f"Service {service_name} in namespace {namespace} updated successfully.")

        except Exception as e:
            self.show_output(f"Error updating service {service_name}: {str(e)}")


    def scale_service(self):
        """Scale the number of replicas for the service."""
        service_name = self.service_dropdown.currentText()  # Get service name from dropdown
        replicas_input = self.replicas_input.text().strip()  # Get replicas from input field
        namespace = self.namespace_dropdown.currentText()  # Get namespace from dropdown

        if not service_name:
            self.show_output("No service selected.")
            return

        if not replicas_input or not replicas_input.isdigit():
            self.show_output("Invalid number of replicas provided.")
            return

        if not namespace:
            self.show_output("No namespace selected.")
            return

        replicas = int(replicas_input)

        self.load_kubernetes_config_from_eks()
        try:
            apps_v1 = client.AppsV1Api()

            # Create a patch object with only the fields we want to modify
            patch_body = {
                "spec": {
                    "replicas": replicas
                }
            }

            # Patch the deployment to update the replicas
            apps_v1.patch_namespaced_deployment_scale(
                name=service_name, 
                namespace=namespace, 
                body=patch_body
            )
            self.show_output(f"Scaled {service_name} to {replicas} replicas in namespace {namespace}.")
        except Exception as e:
            self.show_output(f"Error scaling service {service_name} in namespace {namespace}: {str(e)}")


    def patch_service(self):
        """Patch a specific attribute of a service."""
        service_name = self.service_dropdown.currentText()  # Get the service name from the dropdown
        namespace = self.namespace_dropdown.currentText()  # Get the namespace from the dropdown
        label_key = self.label_key_input.text().strip()  # Get the label key from input
        label_value = self.label_value_input.text().strip()  # Get the label value from input

        if not service_name:
            self.show_output("No service selected.")
            return

        if not namespace:
            self.show_output("No namespace selected.")
            return

        if not label_key or not label_value:
            self.show_output("Both label key and value must be provided.")
            return

        # Create the patch body dynamically based on user input
        patch_body = {
            "metadata": {
                "labels": {
                    label_key: label_value  # Dynamic label update
                }
            }
        }

        self.load_kubernetes_config_from_eks()

        try:
            v1 = client.CoreV1Api()
            # Patch the service with the new label in the specified namespace
            v1.patch_namespaced_service(name=service_name, namespace=namespace, body=patch_body)
            self.show_output(f"Service {service_name} patched successfully with label '{label_key}: {label_value}' in namespace {namespace}.")
        except Exception as e:
            self.show_output(f"Error patching service {service_name} in namespace {namespace}: {str(e)}")


    def describe_service(self):
        """Describe the details of a service."""
        service_name = self.service_dropdown.currentText()  # Get the service name from the dropdown
        namespace = self.namespace_dropdown.currentText()  # Get the namespace from the dropdown

        if not service_name:
            self.show_output("No service selected.")
            return

        if not namespace:
            self.show_output("No namespace selected.")
            return

        self.load_kubernetes_config_from_eks()

        try:
            v1 = client.CoreV1Api()
            # Fetch the service details
            service = v1.read_namespaced_service(name=service_name, namespace=namespace)
            
            # Extract service details for a more readable output
            service_description = f"""
            Service Name: {service.metadata.name}
            Namespace: {service.metadata.namespace}
            Type: {service.spec.type}
            Cluster IP: {service.spec.cluster_ip}
            External IP: {service.status.load_balancer.ingress[0].ip if service.status.load_balancer.ingress else 'None'}
            Ports: {', '.join([f'{port.port}/{port.protocol}' for port in service.spec.ports])}
            Labels: {service.metadata.labels}
            Annotations: {service.metadata.annotations}
            """

            self.show_output(f"Service Description:\n{service_description}")
        except Exception as e:
            self.show_output(f"Error describing service {service_name} in namespace {namespace}: {str(e)}")

            
    
    def list_endpoints(self):
        """List the endpoints for a specific service."""
        service_name = self.service_dropdown.currentText()  # Get the service name from the dropdown
        namespace = self.namespace_dropdown.currentText()  # Get the namespace from the dropdown

        if not service_name:
            self.show_output("No service selected.")
            return

        if not namespace:
            self.show_output("No namespace selected.")
            return

        self.load_kubernetes_config_from_eks()

        try:
            v1 = client.CoreV1Api()
            # Fetch the endpoints for the service in the selected namespace
            endpoints = v1.read_namespaced_endpoints(name=service_name, namespace=namespace)

            # Format and display the endpoints
            if not endpoints.subsets:
                self.show_output(f"No endpoints found for service {service_name} in namespace {namespace}.")
            else:
                endpoint_addresses = []
                for subset in endpoints.subsets:
                    for address in subset.addresses:
                        endpoint_addresses.append(f"IP: {address.ip}, Node: {address.node_name}")
                formatted_endpoints = "\n".join(endpoint_addresses)
                self.show_output(f"Endpoints for service {service_name} in namespace {namespace}:\n{formatted_endpoints}")

        except Exception as e:
            self.show_output(f"Error listing endpoints for service {service_name} in namespace {namespace}: {str(e)}")

           
    def get_service_metrics(self):
        """Retrieve metrics for the selected service."""
        service_name = self.service_dropdown.currentText()  # Get the service name from the dropdown
        namespace = self.namespace_dropdown.currentText()  # Get the namespace from the dropdown

        if not service_name:
            self.show_output("No service selected.")
            return

        if not namespace:
            self.show_output("No namespace selected.")
            return

        self.load_kubernetes_config_from_eks()

        try:
            # Assuming metrics server or a Prometheus integration is available.
            # Replace this with actual metrics integration logic.
            v1 = client.CustomObjectsApi()
            metrics = v1.get_namespaced_custom_object(
                group="metrics.k8s.io",
                version="v1beta1",
                namespace=namespace,
                plural="services",
                name=service_name
            )
            
            # Show the retrieved metrics
            cpu_usage = metrics["usage"]["cpu"]
            memory_usage = metrics["usage"]["memory"]
            self.show_output(f"Service {service_name} - CPU Usage: {cpu_usage}, Memory Usage: {memory_usage}")

        except Exception as e:
            self.show_output(f"Error getting service metrics for {service_name} in namespace {namespace}: {str(e)}")


        except Exception as e:
            self.show_output(f"Error getting service metrics: {str(e)}") 
            
    def restart_service(self):
        """Restart a service by forcing a redeployment."""
        service_name = self.service_dropdown.currentText()  # Get the service name from the dropdown
        namespace = self.namespace_dropdown.currentText()  # Get the namespace from the dropdown

        if not service_name:
            self.show_output("No service selected.")
            return

        if not namespace:
            self.show_output("No namespace selected.")
            return

        self.load_kubernetes_config_from_eks()

        try:
            apps_v1 = client.AppsV1Api()
            # Assuming the service is backed by a deployment
            deployment = apps_v1.read_namespaced_deployment(name=service_name, namespace=namespace)
            # Update deployment metadata to force a new rollout
            if 'annotations' not in deployment.spec.template.metadata:
                deployment.spec.template.metadata.annotations = {}
            deployment.spec.template.metadata.annotations['kubectl.kubernetes.io/restartedAt'] = datetime.datetime.utcnow().isoformat()

            # Apply the patch to trigger the rollout
            apps_v1.patch_namespaced_deployment(name=service_name, namespace=namespace, body=deployment)
            self.show_output(f"Service {service_name} restarted in namespace {namespace}.")
        except Exception as e:
            self.show_output(f"Error restarting service {service_name} in namespace {namespace}: {str(e)}")

            
    
    def expose_service(self):
        """Expose an internal service to the external world."""
        service_name = self.service_dropdown.currentText()  # Get the service name from the dropdown
        namespace = self.namespace_dropdown.currentText()  # Get the namespace from the dropdown

        if not service_name:
            self.show_output("No service selected.")
            return

        if not namespace:
            self.show_output("No namespace selected.")
            return

        self.load_kubernetes_config_from_eks()

        try:
            v1 = client.CoreV1Api()
            service = v1.read_namespaced_service(name=service_name, namespace=namespace)

            # Convert ClusterIP to LoadBalancer
            service.spec.type = "LoadBalancer"
            v1.patch_namespaced_service(name=service_name, namespace=namespace, body=service)

            self.show_output(f"Service {service_name} in namespace {namespace} exposed as LoadBalancer.")
        except Exception as e:
            self.show_output(f"Error exposing service {service_name} in namespace {namespace}: {str(e)}")

     
    def port_forward_service(self):
        """Forward local traffic to a pod's port."""
        service_name = self.service_dropdown.currentText()  # Get the service name from the dropdown
        namespace = self.namespace_dropdown.currentText()  # Get the namespace from the dropdown
        local_port = self.local_port_input.text().strip()  # Get the local port from user input
        pod_port = self.pod_port_input.text().strip()  # Get the pod port from user input

        if not service_name or not namespace or not local_port or not pod_port:
            self.show_output("Please provide the service, namespace, local port, and pod port.")
            return

        self.load_kubernetes_config_from_eks()

        try:
            # Assume that a port-forward command is executed via subprocess
            # This command will run `kubectl port-forward` for the service's pod
            forward_command = f"kubectl port-forward svc/{service_name} {local_port}:{pod_port} --namespace={namespace}"
            subprocess.Popen(forward_command, shell=True)
            self.show_output(f"Port forwarding setup: Local Port {local_port} -> Pod Port {pod_port} for service {service_name} in namespace {namespace}")

        except Exception as e:
            self.show_output(f"Error setting up port forwarding for service {service_name}: {str(e)}")

            
    
    def delete_all_services_in_namespace(self):
        """Delete all services in the selected namespace."""
        namespace = self.namespace_dropdown.currentText()  # Dynamically get the selected namespace
        if not namespace:
            self.show_output("No namespace selected.")
            return

        self.load_kubernetes_config_from_eks()

        try:
            v1 = client.CoreV1Api()
            services = v1.list_namespaced_service(namespace=namespace).items

            if not services:
                self.show_output(f"No services found in namespace {namespace}.")
                return

            # Iterate through and delete each service
            for svc in services:
                service_name = svc.metadata.name
                v1.delete_namespaced_service(name=service_name, namespace=namespace)
                self.show_output(f"Deleted service {service_name} in namespace {namespace}.")

        except Exception as e:
            self.show_output(f"Error deleting services in namespace {namespace}: {str(e)}")



            

    



