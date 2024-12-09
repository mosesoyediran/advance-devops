import base64
import json
import subprocess
import tempfile

import boto3
from kubernetes import client, config
from kubernetes.stream import stream
from PyQt5.QtWidgets import (QComboBox, QHBoxLayout, QLabel, QLineEdit,
                             QPushButton, QTableWidget, QTableWidgetItem,
                             QTextEdit, QVBoxLayout, QWidget)


class ClusterManagementTab(QWidget):
    def __init__(self, session):
        super().__init__()
        self.session = session
        self.eks_client = None
        self.selected_region = None
        self.selected_cluster = None
        self.cluster_dropdown = None  # Initialize the cluster dropdown attribute
        self.output_area = None  # Initialize the output_area attribute
        self.nodegroup_dropdown = None
        
        self.initUI()

    def initUI(self):
        main_layout = QHBoxLayout()

        # Left Column: Cluster, Region selection and management dropdowns
        left_column = QVBoxLayout()

        # Region selection dropdown
        # Create a horizontal layout for the region label and dropdown
        region_selection_layout = QHBoxLayout()  # Change to QHBoxLayout for horizontal arrangement

        # Add the label and the dropdown for regions
        region_label = QLabel("Select Region:")
        region_selection_layout.addWidget(region_label)

        self.region_dropdown = QComboBox()
        self.region_dropdown.setFixedWidth(150)  # Set a fixed width to make the dropdown smaller
        self.region_dropdown.currentIndexChanged.connect(self.on_region_selected)
        region_selection_layout.addWidget(self.region_dropdown)
        self.populate_region_dropdown()  # Populate the regions dynamically

        # Cluster selection dropdown
        cluster_selection_layout = QHBoxLayout()  # Change to QHBoxLayout for horizontal arrangement

        # Add the label and the dropdown for clusters
        cluster_label = QLabel("Select Cluster:")
        cluster_selection_layout.addWidget(cluster_label)

        self.cluster_dropdown = QComboBox()  # Initialize the cluster dropdown
        self.cluster_dropdown.setFixedWidth(150)  # Set a fixed width to make the dropdown smaller
        self.cluster_dropdown.currentIndexChanged.connect(self.on_cluster_selected)  # Connect cluster selection
        cluster_selection_layout.addWidget(self.cluster_dropdown)
        
        
        # Node group selection dropdown
        node_group_selection_layout = QHBoxLayout()  # Change to QHBoxLayout for horizontal arrangement

        # Add the label and the dropdown for node groups
        node_group_label = QLabel("Select Node group:")
        node_group_selection_layout.addWidget(node_group_label)

        self.nodegroup_dropdown = QComboBox()  # Initialize the nodegroup dropdown
        self.nodegroup_dropdown.setFixedWidth(150)  # Set a fixed width to make the dropdown smaller
        node_group_selection_layout.addWidget(self.nodegroup_dropdown)

        # Add region and cluster selection to left column
        left_column.addLayout(region_selection_layout)
        left_column.addLayout(cluster_selection_layout)
        left_column.addLayout(node_group_selection_layout)

        # Node Management Dropdown
        self.create_node_management_dropdown(left_column)

        # Pod Management Dropdown
        self.create_pod_management_dropdown(left_column)

        # Namespace Management Dropdown
        self.create_namespace_management_dropdown(left_column)

        # Right Column: Output panel
        right_column = QVBoxLayout()
        right_column.addWidget(QLabel("Output:"))
        
        # Initialize output area here
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)  # To display command output
        right_column.addWidget(self.output_area)

        # Add columns to the main layout
        main_layout.addLayout(left_column, 1)
        main_layout.addLayout(right_column, 2)

        # Set the main layout
        self.setLayout(main_layout)
        
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
            # Generate the token for EKS using the awscli's get-token command
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
        """Populate AWS regions dynamically."""
        try:
            ec2_client = boto3.client('ec2')
            regions = ec2_client.describe_regions()['Regions']
            region_names = [region['RegionName'] for region in regions]
            self.region_dropdown.addItems(region_names)
            self.show_output("Regions populated dynamically.")
        except Exception as e:
            self.show_output(f"Error fetching regions: {str(e)}")

    def on_region_selected(self):
        """When a region is selected, update the cluster dropdown."""
        self.selected_region = self.region_dropdown.currentText()
        if not self.selected_region:
            self.show_output("No region selected.")
            return

        # Initialize EKS client for the selected region
        self.eks_client = boto3.client('eks', region_name=self.selected_region)
        self.populate_cluster_dropdown()

    def populate_cluster_dropdown(self):
        """Populate clusters based on the selected region."""
        if self.cluster_dropdown is None:
            self.show_output("Cluster dropdown is not initialized.")
            return

        self.cluster_dropdown.clear()  # Clear any existing entries
        if not self.selected_region:
            return

        try:
            # Fetch clusters from AWS EKS for the selected region
            clusters = self.eks_client.list_clusters()["clusters"]
            self.cluster_dropdown.addItems(clusters)
            self.show_output(f"Clusters in region {self.selected_region} fetched.")
        except Exception as e:
            self.show_output(f"Error fetching clusters: {str(e)}")
            
    def on_cluster_selected(self):
        """When a cluster is selected, populate the node group and namespace dropdowns."""
        self.selected_cluster = self.cluster_dropdown.currentText()
        
        if self.selected_cluster:
            # Populate the node group dropdown
            self.populate_nodegroup_dropdown()

            # Populate the namespace dropdown
            self.populate_namespace_dropdown()

            self.show_output(f"Cluster {self.selected_cluster} selected.")
        else:
            self.show_output("No cluster selected.")


    def show_output(self, message):
        """Display output in the output area."""
        if self.output_area is not None:
            self.output_area.append(message)
        else:
            print(f"Output Area is None. Message: {message}")
            
    def create_node_management_dropdown(self, layout):
        """Node Management Dropdown and Execute Button."""
        layout.addWidget(QLabel("Node Management"))
        
        # Create a horizontal layout for the "Nodes" label and node dropdown
        node_layout = QHBoxLayout()

        # Add the "Nodes" label to the horizontal layout
        node_label = QLabel("Nodes:")
        node_layout.addWidget(node_label)

        # Add the node dropdown to the horizontal layout
        self.node_dropdown = QComboBox()  # New dropdown for displaying nodes
        node_layout.addWidget(self.node_dropdown)

        # Add the horizontal layout to the main layout
        layout.addLayout(node_layout)
        
        # Automatically load nodes when a node group is selected
        self.nodegroup_dropdown.currentIndexChanged.connect(self.populate_node_dropdown)

        self.node_management_dropdown = QComboBox()
        self.node_management_dropdown.addItems(["Get Nodes", "Drain Node", "Cordon Node","Uncordon Node", 
                                                "Taint Node","Remove Taint from Node", 
                                                "Label Node","Remove Label from Node",
                                                "Node Maintenance Mode", "Get Node Maintenance Status",
                                                "Uncordon All Nodes", "Taint All Nodes", "Cordon All Nodes", 
                                                "Get Node Resource Utilization", "Reboot Node", 
                                                "Detach Node from Cluster", "Reattach Node to Cluster", 
                                                "Update Node Labels", "Monitor Node Network Health", 
                                                "Get Node Events"
                                                ])
        layout.addWidget(self.node_management_dropdown)
        
        # Create a horizontal layout for Label Key and Label Value inputs
        label_layout = QHBoxLayout()
        
        # Input for label key
        label_layout.addWidget(QLabel("Label Key:"))
        self.label_key_input = QLineEdit()
        self.label_key_input.setMaxLength(20)  # Set max length for the label key
        self.label_key_input.setFixedWidth(120)  # Adjust the width
        self.label_key_input.setPlaceholderText("Key")
        label_layout.addWidget(self.label_key_input)

        # Input for label value
        label_layout.addWidget(QLabel("Label Value:"))
        self.label_value_input = QLineEdit()
        self.label_value_input.setMaxLength(20)  # Set max length for the label value
        self.label_value_input.setFixedWidth(120)  # Adjust the width
        self.label_value_input.setPlaceholderText("Value")
        label_layout.addWidget(self.label_value_input)

        # Add the horizontal layout to the main layout
        layout.addLayout(label_layout)


        node_management_button = QPushButton("Execute")
        node_management_button.clicked.connect(self.execute_node_management)
        layout.addWidget(node_management_button)

   
            
    
## Node Management Functions

    def execute_node_management(self):
        """Handle node management based on selected action."""
        action = self.node_management_dropdown.currentText()
        selected_node = self.node_dropdown.currentText()
        label_key = self.label_key_input.text()
        label_value = self.label_value_input.text()

        if action == "Get Nodes":
            self.get_nodes()
        elif action == "Drain Node":
            self.drain_node(selected_node)
        elif action == "Cordon Node":
            self.cordon_node(selected_node)
        elif action == "Uncordon Node":
            self.uncordon_node(selected_node)
        elif action == "Taint Node":
            self.taint_node(selected_node)
        elif action == "Remove Taint from Node":
            self.remove_taint_from_node(selected_node)
        elif action == "Label Node":
            self.label_node(selected_node, label_key, label_value)
        elif action == "Remove Label from Node":
            self.remove_label_from_node(selected_node, label_key)
        elif action == "Monitor Node Metrics":
            self.monitor_node_metrics(selected_node)
        elif action == "Node Maintenance Mode":
            self.node_maintenance_mode(selected_node)
        elif action == "Uncordon All Nodes":
            self.uncordon_all_nodes()
        elif action == "Taint All Nodes":
            self.taint_all_nodes()
        elif action == "Cordon All Nodes":
            self.cordon_all_nodes()
        elif action == "Get Node Resource Utilization":
            self.get_node_resource_utilization(selected_node)
        elif action == "Reboot Node":
            self.reboot_node(selected_node)
        elif action == "Detach Node from Cluster":
            self.detach_node_from_cluster(selected_node)
        elif action == "Reattach Node to Cluster":
            self.reattach_node_to_cluster(selected_node)
        elif action == "Update Node Labels":
            self.update_node_labels(selected_node, label_key, label_value)
        elif action == "Monitor Node Network Health":
            self.monitor_node_network_health(selected_node)
        elif action == "Get Node Events":
            self.get_node_events(selected_node)
        
    def populate_nodegroup_dropdown(self):
        """Populate node groups based on the selected cluster."""
        if not self.selected_cluster:
            self.show_output("No cluster selected.")
            return

        # Clear any existing node groups from the dropdown
        self.nodegroup_dropdown.clear()

        try:
            # Fetch node groups associated with the selected cluster
            response = self.eks_client.list_nodegroups(clusterName=self.selected_cluster)
            nodegroups = response.get("nodegroups", [])

            if nodegroups:
                self.nodegroup_dropdown.addItems(nodegroups)
                self.show_output(f"Node groups for cluster {self.selected_cluster}: {nodegroups}")
            else:
                self.show_output(f"No node groups found for cluster {self.selected_cluster}.")

        except Exception as e:
            self.show_output(f"Error fetching node groups: {str(e)}")
            
            
    def populate_node_dropdown(self):
        """Populate the nodes based on the selected node group."""
        nodegroup_name = self.nodegroup_dropdown.currentText()
        self.selected_cluster = self.cluster_dropdown.currentText()

        if not self.selected_cluster or not nodegroup_name:
            self.show_output("No cluster or node group selected.")
            return

        # Clear existing nodes in the dropdown
        self.node_dropdown.clear()

        try:
            # Load Kubernetes config to access the cluster
            self.load_kubernetes_config_from_eks()

            # Fetch all nodes from the cluster using the Kubernetes API
            v1 = client.CoreV1Api()
            nodes = v1.list_node().items

            # Filter nodes that belong to the selected node group
            nodegroup_label = f"eks.amazonaws.com/nodegroup"
            nodegroup_nodes = [node for node in nodes if nodegroup_label in node.metadata.labels and node.metadata.labels[nodegroup_label] == nodegroup_name]

            if nodegroup_nodes:
                for node in nodegroup_nodes:
                    node_name = node.metadata.name
                    self.node_dropdown.addItem(node_name)
                self.show_output(f"Nodes in node group '{nodegroup_name}' populated successfully.")
            else:
                self.show_output(f"No nodes found in node group '{nodegroup_name}'.")

        except Exception as e:
            self.show_output(f"Error fetching nodes: {str(e)}")
    
    

    def get_nodes(self):
        """Fetch and display nodes in the selected cluster in a user-friendly format."""
        self.selected_cluster = self.cluster_dropdown.currentText()
        
        if not self.selected_cluster:
            self.show_output("No cluster selected.")
            return

        # Load the Kubernetes configuration
        self.load_kubernetes_config_from_eks()

        try:
            # Get the list of nodes in the cluster using the Kubernetes client
            v1 = client.CoreV1Api()
            nodes = v1.list_node().items
            
            if not nodes:
                self.show_output(f"No nodes found in cluster {self.selected_cluster}.")
                return
            
            # Header for the table
            self.show_output(f"Nodes in cluster '{self.selected_cluster}':\n")
            self.show_output(f"{'Node Name':<25} {'Status':<10} {'Roles':<20}")
            self.show_output("-" * 55)

            # Display node information in a formatted table
            for node in nodes:
                node_name = node.metadata.name
                node_status = "Ready" if any(
                    condition.status == "True" and condition.type == "Ready"
                    for condition in node.status.conditions
                ) else "Not Ready"
                node_roles = node.metadata.labels.get("kubernetes.io/role", "worker")

                self.show_output(f"{node_name:<25} {node_status:<10} {node_roles:<20}")

        except Exception as e:
            self.show_output(f"Error refreshing nodes: {str(e)}")


    def drain_node(self, node_name):
        """Drain a node by evicting all pods."""
        self.load_kubernetes_config_from_eks()
        try:
            v1 = client.CoreV1Api()
            pods = v1.list_pod_for_all_namespaces(field_selector=f"spec.nodeName={node_name}").items
            for pod in pods:
                eviction = client.V1Eviction(
                    metadata=client.V1ObjectMeta(name=pod.metadata.name, namespace=pod.metadata.namespace)
                )
                v1.create_namespaced_pod_eviction(name=pod.metadata.name, namespace=pod.metadata.namespace, body=eviction)
                self.show_output(f"Evicted pod {pod.metadata.name} from node {node_name}.")
            self.show_output(f"Node {node_name} drained successfully.")
        except Exception as e:
            self.show_output(f"Error draining node: {str(e)}")
            
    def cordon_node(self, node_name):
        """Cordon a node to prevent new pods from being scheduled."""
        self.load_kubernetes_config_from_eks()
        try:
            v1 = client.CoreV1Api()
            body = {"spec": {"unschedulable": True}}
            v1.patch_node(node_name, body)
            self.show_output(f"Node {node_name} cordoned successfully.")
        except Exception as e:
            self.show_output(f"Error cordoning node: {str(e)}")
            
    def uncordon_node(self, node_name):
        """Uncordon a node to allow scheduling of new pods."""
        self.load_kubernetes_config_from_eks()
        try:
            v1 = client.CoreV1Api()
            body = {"spec": {"unschedulable": False}}
            v1.patch_node(node_name, body)
            self.show_output(f"Node {node_name} uncordoned successfully.")
        except Exception as e:
            self.show_output(f"Error uncordoning node: {str(e)}")
            
            
    def taint_node(self, node_name):
        """Add a taint to the node."""
        self.load_kubernetes_config_from_eks()
        try:
            v1 = client.CoreV1Api()
            body = {
                "spec": {
                    "taints": [
                        {
                            "effect": "NoSchedule",
                            "key": "example-key",
                            "value": "example-value"
                        }
                    ]
                }
            }
            v1.patch_node(node_name, body)
            self.show_output(f"Node {node_name} tainted successfully.")
        except Exception as e:
            self.show_output(f"Error tainting node: {str(e)}")
            
    def remove_taint_from_node(self, node_name):
        """Remove a specific taint from the node."""
        self.load_kubernetes_config_from_eks()
        try:
            v1 = client.CoreV1Api()
            body = {
                "spec": {
                    "taints": []
                }
            }
            v1.patch_node(node_name, body)
            self.show_output(f"Taint removed from node {node_name} successfully.")
        except Exception as e:
            self.show_output(f"Error removing taint from node: {str(e)}")


    def node_maintenance_mode(self, node_name):
        """
        Put the node in maintenance mode by cordoning and draining it.
        """
        self.load_kubernetes_config_from_eks()

        try:
            v1 = client.CoreV1Api()
            
            # Step 1: Cordon the node to prevent new pods from being scheduled
            body = {"spec": {"unschedulable": True}}
            v1.patch_node(node_name, body)
            self.show_output(f"Node {node_name} cordoned successfully.")

            # Step 2: Drain the node by evicting all pods from it
            pods = v1.list_pod_for_all_namespaces(field_selector=f"spec.nodeName={node_name}").items
            for pod in pods:
                eviction = client.V1beta1Eviction(
                    metadata=client.V1ObjectMeta(name=pod.metadata.name, namespace=pod.metadata.namespace)
                )
                v1.create_namespaced_pod_eviction(name=pod.metadata.name, namespace=pod.metadata.namespace, body=eviction)
                self.show_output(f"Evicted pod {pod.metadata.name} from node {node_name}.")

            self.show_output(f"Node {node_name} successfully put into maintenance mode.")

        except Exception as e:
            self.show_output(f"Error putting node into maintenance mode: {str(e)}")
            
    def monitor_node_metrics(self, node_name):
        """
        Monitor node metrics like CPU and memory usage using the Kubernetes Metrics API.
        """
        self.load_kubernetes_config_from_eks()

        try:
            # Kubernetes Metrics API client (requires metrics-server to be installed)
            metrics_api = client.CustomObjectsApi()

            # Fetch metrics for the selected node
            metrics = metrics_api.get_cluster_custom_object(
                group="metrics.k8s.io", version="v1beta1", plural="nodes", name=node_name
            )
            
            # Extract CPU and memory usage information
            cpu_usage = metrics["usage"]["cpu"]
            memory_usage = metrics["usage"]["memory"]

            self.show_output(f"Node {node_name} Metrics:")
            self.show_output(f"CPU Usage: {cpu_usage}")
            self.show_output(f"Memory Usage: {memory_usage}")

        except client.exceptions.ApiException as e:
            self.show_output(f"Error fetching node metrics: {e.reason}")
        except Exception as e:
            self.show_output(f"Error monitoring node metrics: {str(e)}")


    def label_node(self, node_name, label_key, label_value):
        """
        Add a label to the selected node by patching its metadata.
        """
        self.load_kubernetes_config_from_eks()

        try:
            v1 = client.CoreV1Api()
            
            # Define the patch operation to add the label
            body = {
                "metadata": {
                    "labels": {
                        label_key: label_value
                    }
                }
            }
            
            # Patch the node to add the label
            v1.patch_node(node_name, body)
            self.show_output(f"Label '{label_key}: {label_value}' added to node {node_name}.")

        except Exception as e:
            self.show_output(f"Error adding label to node: {str(e)}")
            
            
    def remove_label_from_node(self, node_name, label_key):
        """
        Remove a label from the selected node by patching its metadata.
        """
        self.load_kubernetes_config_from_eks()

        try:
            v1 = client.CoreV1Api()
            
            # Get the node details to check if the label exists
            node = v1.read_node(node_name)
            if label_key not in node.metadata.labels:
                self.show_output(f"Label '{label_key}' does not exist on node {node_name}.")
                return

            # Define the patch operation to remove the label
            body = {
                "metadata": {
                    "labels": {
                        label_key: None  # Setting the label key to `None` removes it
                    }
                }
            }
            
            # Patch the node to remove the label
            v1.patch_node(node_name, body)
            self.show_output(f"Label '{label_key}' removed from node {node_name}.")

        except Exception as e:
            self.show_output(f"Error removing label from node: {str(e)}")


    def uncordon_all_nodes(self):
        """Uncordon all nodes in the selected node group."""
        nodes = self.get_nodes_in_nodegroup()  # A helper function to get all nodes
        for node in nodes:
            self.uncordon_node(node)
        self.show_output(f"All nodes in node group uncordoned successfully.")

    def taint_all_nodes(self, taint_key, taint_value):
        """Taint all nodes in the selected node group."""
        nodes = self.get_nodes_in_nodegroup()
        for node in nodes:
            self.taint_node(node, taint_key, taint_value)
        self.show_output(f"All nodes in node group tainted successfully.")
        
    def cordon_all_nodes(self):
        """Cordon all nodes in the selected node group."""
        nodes = self.get_nodes_in_nodegroup()
        for node in nodes:
            self.cordon_node(node)
        self.show_output(f"All nodes in node group cordoned successfully.")
        
        
    def get_node_resource_utilization(self, node_name):
        """Get CPU/Memory utilization for the selected node."""
        self.load_kubernetes_config_from_eks()
        v1 = client.CoreV1Api()
        metrics = client.CustomObjectsApi().list_namespaced_custom_object(
            group="metrics.k8s.io", version="v1beta1", namespace="", plural="nodes"
        )
        
        for item in metrics['items']:
            if item['metadata']['name'] == node_name:
                cpu_usage = item['usage']['cpu']
                mem_usage = item['usage']['memory']
                self.show_output(f"Node {node_name}: CPU={cpu_usage}, Memory={mem_usage}")
                break

    def reboot_node(self, node_name):
        """Reboot the selected node."""
        # Assuming the node has an EC2 instance ID label 'node.kubernetes.io/instance-id'
        v1 = client.CoreV1Api()
        node = v1.read_node(node_name)
        instance_id = node.metadata.labels['node.kubernetes.io/instance-id']

        ec2_client = boto3.client('ec2', region_name=self.selected_region)
        ec2_client.reboot_instances(InstanceIds=[instance_id])
        self.show_output(f"Node {node_name} with instance ID {instance_id} rebooted.")
        
    def detach_node_from_cluster(self, node_name):
        """Detach a node from the cluster."""
        self.cordon_node(node_name)
        self.drain_node(node_name)
        self.delete_node(node_name)
        self.show_output(f"Node {node_name} detached from the cluster.")
        
    def reattach_node_to_cluster(self, node_name):
        """Reattach a node to the cluster."""
        self.uncordon_node(node_name)
        self.show_output(f"Node {node_name} reattached to the cluster.")
        
    def update_node_labels(self, node_name, label_key, label_value):
        """Update labels on the selected node."""
        self.load_kubernetes_config_from_eks()
        v1 = client.CoreV1Api()
        body = {"metadata": {"labels": {label_key: label_value}}}
        v1.patch_node(node_name, body)
        self.show_output(f"Label {label_key}={label_value} added to node {node_name}.")
        
    def monitor_node_network_health(self, node_name):
        """Monitor the network health of the selected node by pinging its IP."""
        self.show_output(f"Starting network health monitoring for node {node_name}...")
        
        # Load the Kubernetes configuration from EKS
        self.load_kubernetes_config_from_eks()
        
        try:
            # Fetch node details from Kubernetes API
            v1 = client.CoreV1Api()
            node = v1.read_node(name=node_name)
            
            # Get the external or internal IP of the node
            addresses = node.status.addresses
            node_ip = None
            for address in addresses:
                if address.type == "ExternalIP":
                    node_ip = address.address
                    break
            if not node_ip:
                # Fallback to internal IP if external IP isn't available
                for address in addresses:
                    if address.type == "InternalIP":
                        node_ip = address.address
                        break

            # If no IP address is found, display an error and exit
            if not node_ip:
                self.show_output(f"Could not determine IP address for node {node_name}.")
                return

            self.show_output(f"Found IP address for node {node_name}: {node_ip}")
            
            # Ping the node's IP address (4 pings for a quick test)
            self.show_output(f"Pinging node {node_name} at IP {node_ip}...")
            response = subprocess.run(["ping", "-c", "4", node_ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            # If the ping command succeeds
            if response.returncode == 0:
                self.show_output(f"Node {node_name} ({node_ip}) is reachable.\nPing Results:\n{response.stdout}")
            else:
                # If the ping command fails
                self.show_output(f"Failed to reach node {node_name} ({node_ip}).\nError Details:\n{response.stderr}")
        
        # Handle API errors when fetching node details
        except client.exceptions.ApiException as e:
            self.show_output(f"Error fetching node information: {str(e)}")
        
        # Handle general exceptions during network health monitoring
        except Exception as e:
            self.show_output(f"Error monitoring network health: {str(e)}")

        # Final output message
        self.show_output(f"Completed network health monitoring for node {node_name}.")
        
    def get_node_events(self, node_name):
        """Fetch and display events related to the selected node."""
        self.load_kubernetes_config_from_eks()
        v1 = client.CoreV1Api()
        events = v1.list_namespaced_event(namespace="default", field_selector=f"involvedObject.name={node_name}")
        
        for event in events.items:
            self.show_output(f"Event for {node_name}: {event.message}")


    ###### PODS TAB ######
    def create_pod_management_dropdown(self, layout):
        """Pod Management Dropdown and Execute Button."""
        layout.addWidget(QLabel("Pod Management"))
            
        # Create a horizontal layout for the "Pods" label and pods dropdown
        pod_layout = QHBoxLayout()

        # Add the "Pods" label to the horizontal layout
        pod_label = QLabel("Pods:")
        pod_layout.addWidget(pod_label)

        # Add the pods dropdown to the horizontal layout
        self.pods_dropdown = QComboBox()  # New dropdown for displaying pods
        pod_layout.addWidget(self.pods_dropdown)

        # Add the horizontal layout for pods to the main layout
        layout.addLayout(pod_layout)
            
        # Create a horizontal layout for the replicas, local port, and pod port inputs
        ports_layout = QHBoxLayout()
        
        # Input for scaling replicas (3 digits max)
        ports_layout.addWidget(QLabel("Replicas:"))
        self.replicas_input = QLineEdit()
        self.replicas_input.setMaxLength(3)  # Limit to 3 digits
        self.replicas_input.setFixedWidth(50)  # Adjust width
        self.replicas_input.setPlaceholderText("e.g., 3")
        ports_layout.addWidget(self.replicas_input)

        # Input for local port (6 digits max)
        ports_layout.addWidget(QLabel("Local Port:"))
        self.local_port_input = QLineEdit()
        self.local_port_input.setMaxLength(6)  # Limit to 6 digits
        self.local_port_input.setFixedWidth(80)  # Adjust width
        self.local_port_input.setPlaceholderText("8080")
        ports_layout.addWidget(self.local_port_input)

        # Input for pod port (6 digits max)
        ports_layout.addWidget(QLabel("Pod Port:"))
        self.pod_port_input = QLineEdit()
        self.pod_port_input.setMaxLength(6)  # Limit to 6 digits
        self.pod_port_input.setFixedWidth(80)  # Adjust width
        self.pod_port_input.setPlaceholderText("80")
        ports_layout.addWidget(self.pod_port_input)
        
        # Add the horizontal layout containing the inputs to the main layout
        layout.addLayout(ports_layout)
            
            # Automatically load pods when a node is selected
        self.node_dropdown.currentIndexChanged.connect(self.populate_pods_dropdown)

        self.pod_management_dropdown = QComboBox()
        self.pod_management_dropdown.addItems(["Get Pods", "Delete Pod", "Get Pod Logs",
                                                   "Describe Pod","Scale Pods","Exec Into Pod",
                                                   "Forward Pod Ports","Restart Pod",])
        layout.addWidget(self.pod_management_dropdown)

        pod_management_button = QPushButton("Execute")
        pod_management_button.clicked.connect(self.execute_pod_management)
        layout.addWidget(pod_management_button)
            
            
    def populate_pods_dropdown(self):
        """Populate the pods dropdown with pods running on the selected node."""
        selected_node = self.node_dropdown.currentText()

        if not selected_node:
            self.show_output("No node selected.")
            return

        self.show_output(f"Fetching pods for node: {selected_node}")
        self.pods_dropdown.clear()  # Clear the previous list of pods

        # Load Kubernetes config and query pods
        self.load_kubernetes_config_from_eks()

        try:
            # Get the list of pods in the cluster using the Kubernetes client
            v1 = client.CoreV1Api()
            all_pods = v1.list_pod_for_all_namespaces().items

            # Filter pods by the selected node
            node_pods = [pod for pod in all_pods if pod.spec.node_name == selected_node]

            if not node_pods:
                self.show_output(f"No pods found on node {selected_node}.")
                return

            # Populate the dropdown with pod names
            for pod in node_pods:
                self.pods_dropdown.addItem(pod.metadata.name)

            self.show_output(f"Pods on node {selected_node} populated.")

        except Exception as e:
            self.show_output(f"Error populating pods on node {selected_node}: {str(e)}")

            
            
    def execute_pod_management(self):
        """Handle pod management based on selected action."""
        selected_pod = self.pods_dropdown.currentText()
        selected_action = self.pod_management_dropdown.currentText()

        if not selected_pod:
            self.show_output("No pod selected.")
            return
        
        if selected_action == "Get Pods":
            self.get_pods()
        if selected_action == "Get Pod Logs":
            self.get_pod_logs(selected_pod)
        elif selected_action == "Delete Pod":
            self.delete_pod(selected_pod)
        elif selected_action == "Describe Pod":
            self.describe_pod(selected_pod)
        elif selected_action == "Scale Pods":
            replicas = 3  
            self.scale_pods(selected_pod, replicas)
        elif selected_action == "Exec Into Pod":
            self.exec_into_pod(selected_pod)
        elif selected_action == "Forward Pod Ports":
            local_port = self.local_port_input.text()
            pod_port = self.pod_port_input.text()
            if local_port.isdigit() and pod_port.isdigit():
                self.forward_pod_ports(selected_pod, int(local_port), int(pod_port))
            else:
                self.show_output("Invalid port numbers.")
        elif selected_action == "Restart Pod":
            self.restart_pod(selected_pod)


    def get_pods(self):
        """Fetch and display pods in the selected cluster in a user-friendly format."""
        self.selected_cluster = self.cluster_dropdown.currentText()
        
        if not self.selected_cluster:
            self.show_output("No cluster selected.")
            return

        # Load Kubernetes configuration
        self.load_kubernetes_config_from_eks()

        try:
            v1 = client.CoreV1Api()
            pods = v1.list_pod_for_all_namespaces().items

            if not pods:
                self.show_output(f"No pods found in cluster {self.selected_cluster}.")
                return
            
            # Header for the table
            self.show_output(f"Pods in cluster '{self.selected_cluster}':\n")
            self.show_output(f"{'Pod Name':<30} {'Namespace':<20} {'Status':<15} {'Restarts':<10}")
            self.show_output("-" * 75)

            # Display pod information in a formatted table
            for pod in pods:
                pod_name = pod.metadata.name
                pod_namespace = pod.metadata.namespace
                pod_status = pod.status.phase
                restarts = pod.status.container_statuses[0].restart_count if pod.status.container_statuses else 0

                self.show_output(f"{pod_name:<30} {pod_namespace:<20} {pod_status:<15} {restarts:<10}")

        except Exception as e:
            self.show_output(f"Error fetching pods: {str(e)}")
 

    def delete_pod(self):
        """Delete a selected pod."""
        self.selected_cluster = self.cluster_dropdown.currentText()
        if not self.selected_cluster:
            self.show_output("No cluster selected.")
            return

        # Simulate deleting a pod (replace with actual command later)
        self.show_output(f"Deleting pod in cluster: {self.selected_cluster}")
        # Example: subprocess.run(["kubectl", "delete", "pod", "<pod-name>", "-n", "<namespace>"])

    def get_pod_logs(self, pod_name):
        """Fetch and display logs for the selected pod."""
        try:
            v1 = client.CoreV1Api()
            namespace = "default"  # You can dynamically set the namespace or fetch from the dropdown
            logs = v1.read_namespaced_pod_log(name=pod_name, namespace=namespace)
            self.show_output(f"Logs for pod {pod_name}:\n{logs}")
        except Exception as e:
            self.show_output(f"Error fetching logs for pod {pod_name}: {str(e)}")


    def describe_pod(self, pod_name):
        """Describe the details of a specific pod."""
        self.load_kubernetes_config_from_eks()
        try:
            v1 = client.CoreV1Api()
            pod_details = v1.read_namespaced_pod(name=pod_name, namespace="default")
            self.show_output(f"Description of pod {pod_name}:\n{pod_details}")
        except Exception as e:
            self.show_output(f"Error describing pod {pod_name}: {str(e)}")


    def scale_pods(self, deployment_name, replicas):
        """Scale a deployment to the specified number of replicas."""
        self.load_kubernetes_config_from_eks()
        try:
            apps_v1 = client.AppsV1Api()
            body = {'spec': {'replicas': replicas}}
            apps_v1.patch_namespaced_deployment_scale(
                name=deployment_name, 
                namespace="default", 
                body=body
            )
            self.show_output(f"Scaled deployment {deployment_name} to {replicas} replicas.")
        except Exception as e:
            self.show_output(f"Error scaling deployment {deployment_name}: {str(e)}")
            
            
    def exec_into_pod(self, pod_name):
        """Execute a shell command inside the selected pod."""
        self.load_kubernetes_config_from_eks()
        try:
            exec_command = ['/bin/sh']
            resp = stream(client.CoreV1Api().connect_get_namespaced_pod_exec,
                        pod_name,
                        'default',
                        command=exec_command,
                        stderr=True, stdin=False,
                        stdout=True, tty=False)
            self.show_output(f"Executing command in pod {pod_name}:\n{resp}")
        except Exception as e:
            self.show_output(f"Error executing command in pod {pod_name}: {str(e)}")
            
            
            
    def forward_pod_ports(self, pod_name, local_port, pod_port):
        """Forward a port from the pod to localhost."""
        self.show_output(f"Setting up port forwarding for pod {pod_name}: {local_port} -> {pod_port}")
        try:
            # You'd usually use `kubectl port-forward`, but here's an alternative way
            self.show_output(f"Use 'kubectl port-forward {pod_name} {local_port}:{pod_port}' for local port forwarding")
        except Exception as e:
            self.show_output(f"Error setting up port forwarding for pod {pod_name}: {str(e)}")
            
            
    def restart_pod(self, pod_name):
        """Restart a pod by deleting it (Kubernetes will create a new one automatically)."""
        self.load_kubernetes_config_from_eks()
        try:
            v1 = client.CoreV1Api()
            v1.delete_namespaced_pod(name=pod_name, namespace="default")
            self.show_output(f"Restarted pod {pod_name}. A new pod will be created by the deployment.")
        except Exception as e:
            self.show_output(f"Error restarting pod {pod_name}: {str(e)}")





    ###### NAMESPACE TAB ######
    
    def create_namespace_management_dropdown(self, layout):
        """Namespace Management Dropdown and Execute Button."""
        layout.addWidget(QLabel("Namespace Management"))
        
        # Create a horizontal layout for the "Namespaces" label and dropdown
        namespace_layout = QHBoxLayout()

        # Add the "Namespaces" label to the horizontal layout
        namespace_label = QLabel("Namespaces:")
        namespace_layout.addWidget(namespace_label)

        # Add the namespace dropdown to the horizontal layout
        self.namespace_dropdown = QComboBox()  # New dropdown for displaying namespaces
        namespace_layout.addWidget(self.namespace_dropdown)
        
        # Add the horizontal layout to the main layout
        layout.addLayout(namespace_layout)

        
        ### Patch Body, CPU Limit, Memory Limit ###
        patch_quota_layout = QHBoxLayout()
        
        # Patch Body input
        patch_quota_layout.addWidget(QLabel("Patch Body:"))
        self.patch_body_input = QLineEdit()  # Input for patch body
        self.patch_body_input.setMaxLength(10)  # Set a max length of 10
        self.patch_body_input.setFixedWidth(100)  # Adjust the width
        self.patch_body_input.setPlaceholderText("e.g., json")
        patch_quota_layout.addWidget(self.patch_body_input)

        # CPU Limit input
        patch_quota_layout.addWidget(QLabel("CPU Limit:"))
        self.cpu_limit_input = QLineEdit()  # Input for CPU limit
        self.cpu_limit_input.setMaxLength(5)  # Set a max length of 5
        self.cpu_limit_input.setFixedWidth(60)  # Make the input field smaller
        self.cpu_limit_input.setPlaceholderText("e.g., 2")
        patch_quota_layout.addWidget(self.cpu_limit_input)

        # Memory Limit input
        patch_quota_layout.addWidget(QLabel("Memory Limit:"))
        self.memory_limit_input = QLineEdit()  # Input for Memory limit
        self.memory_limit_input.setMaxLength(5)  # Set a max length of 5
        self.memory_limit_input.setFixedWidth(60)  # Make the input field smaller
        self.memory_limit_input.setPlaceholderText("e.g., 4Gi")
        patch_quota_layout.addWidget(self.memory_limit_input)
        
        # Add the horizontal layout for patch body and quotas to the main layout
        layout.addLayout(patch_quota_layout)
        
        
        ### Label Key, Label Value, Annotations ###
        # Create a horizontal layout for Label Key, Label Value, and Annotations inputs
        label_annotation_layout = QHBoxLayout()

        # Label Key input
        label_annotation_layout.addWidget(QLabel("Label Key:"))
        self.label_key_input = QLineEdit()
        self.label_key_input.setMaxLength(15)  # Set max length for the label key
        self.label_key_input.setFixedWidth(100)  # Adjust the width
        self.label_key_input.setPlaceholderText("Key")
        label_annotation_layout.addWidget(self.label_key_input)

        # Label Value input
        label_annotation_layout.addWidget(QLabel("Label Value:"))
        self.label_value_input = QLineEdit()
        self.label_value_input.setMaxLength(15)  # Set max length for the label value
        self.label_value_input.setFixedWidth(100)  # Adjust the width
        self.label_value_input.setPlaceholderText("Value")
        label_annotation_layout.addWidget(self.label_value_input)

        # Annotations input
        label_annotation_layout.addWidget(QLabel("Annotations:"))
        self.annotations_input = QLineEdit()
        self.annotations_input.setMaxLength(20)  # Set max length for annotations
        self.annotations_input.setFixedWidth(120)  # Adjust the width
        self.annotations_input.setPlaceholderText("Annotations")
        label_annotation_layout.addWidget(self.annotations_input)

        # Add the horizontal layout for labels and annotations to the main layout
        layout.addLayout(label_annotation_layout)

        
        self.namespace_management_dropdown = QComboBox()
        self.namespace_management_dropdown.addItems(["Get Namespaces", "Create Namespace","Delete Namespace", 
                                                "Get Namespace Details", "Set Namespace Quotas", "Get Resource Quotas", 
                                                "Update Namespace Labels", "Get Namespace Events", "Patch Namespace",
                                                "Monitor Namespace Usage","Set Namespace Annotations","Get Namespace Annotations",
                                                ])
        layout.addWidget(self.namespace_management_dropdown)

        namespace_management_button = QPushButton("Execute")
        namespace_management_button.clicked.connect(self.execute_namespace_management)
        layout.addWidget(namespace_management_button)
        
        # Populate namespaces when the dropdown is created
        self.populate_namespace_dropdown()
        
        
    def populate_namespace_dropdown(self):
        """Query and populate namespaces in the dropdown."""
        self.show_output("Fetching namespaces...")

        # Ensure Kubernetes config is loaded
        self.load_kubernetes_config_from_eks()

        try:
            # Create a Kubernetes API client
            v1 = client.CoreV1Api()

            # List all namespaces in the cluster
            namespaces = v1.list_namespace().items

            if not namespaces:
                self.show_output("No namespaces found.")
                return

            # Clear any previous namespaces in the dropdown
            self.namespace_dropdown.clear()

            # Populate the dropdown with namespace names
            for ns in namespaces:
                self.namespace_dropdown.addItem(ns.metadata.name)

            self.show_output("Namespaces populated successfully.")

        except Exception as e:
            self.show_output(f"Error fetching namespaces: {str(e)}")


    def execute_namespace_management(self):
        """Handle namespace management based on selected action."""
        action = self.namespace_management_dropdown.currentText()
        
        # Get values from the UI inputs
        selected_namespace = self.namespace_dropdown.currentText()
        cpu_limit = self.cpu_limit_input.text().strip()
        memory_limit = self.memory_limit_input.text().strip()
        label_key = self.label_key_input.text().strip()
        label_value = self.label_value_input.text().strip()
        annotations = self.annotations_input.text().strip()
        patch_body = self.patch_body_input.text().strip()

        if not selected_namespace:
            self.show_output("No namespace selected.")
            return

        # Handle different namespace actions based on the dropdown selection
        if action == "Get Namespaces":
            self.get_namespaces()
            
        elif action == "Create Namespace":
            self.create_namespace(selected_namespace)
            
        elif action == "Delete Namespace":
            self.delete_namespace(selected_namespace)
            
        elif action == "Get Namespace Details":
            self.get_namespace_details(selected_namespace)
            
        elif action == "Set Namespace Quotas":
            if not cpu_limit or not memory_limit:
                self.show_output("Please enter valid CPU and memory limits.")
                return
            self.set_namespace_quotas(selected_namespace, cpu_limit, memory_limit)
            
        elif action == "Get Resource Quotas":
            self.get_resource_quotas(selected_namespace)
            
        elif action == "Update Namespace Labels":
            if not label_key or not label_value:
                self.show_output("Please enter valid label key and value.")
                return
            self.update_namespace_labels(selected_namespace, label_key, label_value)
            
        elif action == "Get Namespace Events":
            self.get_namespace_events(selected_namespace)
            
        elif action == "Patch Namespace":
            if not patch_body:
                self.show_output("Please enter a valid patch body.")
                return
            self.patch_namespace(selected_namespace, patch_body)
            
        elif action == "Monitor Namespace Usage":
            self.monitor_namespace_usage(selected_namespace)
            
        elif action == "Set Namespace Annotations":
            if not annotations:
                self.show_output("Please enter valid annotations.")
                return
            self.set_namespace_annotations(selected_namespace, annotations)
            
        elif action == "Get Namespace Annotations":
            self.get_namespace_annotations(selected_namespace)

            
            
            
    def get_namespaces(self):
        """Fetch and display namespaces in the selected cluster in a user-friendly format."""
        self.selected_cluster = self.cluster_dropdown.currentText()
        
        if not self.selected_cluster:
            self.show_output("No cluster selected.")
            return

        # Load Kubernetes configuration
        self.load_kubernetes_config_from_eks()

        try:
            v1 = client.CoreV1Api()
            namespaces = v1.list_namespace().items

            if not namespaces:
                self.show_output(f"No namespaces found in cluster {self.selected_cluster}.")
                return
            
            # Header for the table
            self.show_output(f"Namespaces in cluster '{self.selected_cluster}':\n")
            self.show_output(f"{'Namespace Name':<30} {'Status':<15}")
            self.show_output("-" * 45)

            # Display namespace information in a formatted table
            for ns in namespaces:
                namespace_name = ns.metadata.name
                namespace_status = ns.status.phase

                self.show_output(f"{namespace_name:<30} {namespace_status:<15}")

        except Exception as e:
            self.show_output(f"Error fetching namespaces: {str(e)}")



    def create_namespace(self):
        """Create a new namespace in the selected cluster."""
        # Get the selected cluster and namespace from the UI
        self.selected_cluster = self.cluster_dropdown.currentText()
        new_namespace = self.namespace_dropdown.currentText()  # Get the namespace name from the dropdown or input

        if not self.selected_cluster:
            self.show_output("No cluster selected.")
            return

        if not new_namespace:
            self.show_output("No namespace name provided.")
            return

        # Load Kubernetes configuration
        self.load_kubernetes_config_from_eks()

        # Create the namespace using the Kubernetes API
        try:
            v1 = client.CoreV1Api()

            # Define the namespace body
            namespace_body = client.V1Namespace(
                metadata=client.V1ObjectMeta(name=new_namespace)
            )

            # Create the namespace
            v1.create_namespace(body=namespace_body)
            self.show_output(f"Namespace '{new_namespace}' created successfully in cluster '{self.selected_cluster}'.")

        except client.exceptions.ApiException as e:
            self.show_output(f"Error creating namespace '{new_namespace}': {e}")


    
            
    def delete_namespace(self, namespace):
        """Delete a selected namespace."""
        try:
            v1 = client.CoreV1Api()
            v1.delete_namespace(name=namespace)
            self.show_output(f"Namespace {namespace} deleted successfully.")
        except Exception as e:
            self.show_output(f"Error deleting namespace {namespace}: {str(e)}")
            
    def get_namespace_details(self, namespace):
        """
        Get and display details of the selected namespace.
        """
        v1 = client.CoreV1Api()

        try:
            # Fetch namespace details using Kubernetes API
            namespace_details = v1.read_namespace(name=namespace)

            # Prepare the details in a user-friendly format
            details = f"Namespace: {namespace_details.metadata.name}\n"
            details += f"Status: {namespace_details.status.phase}\n"
            details += f"Labels: {namespace_details.metadata.labels}\n"
            details += f"Annotations: {namespace_details.metadata.annotations}\n"
            details += f"Creation Timestamp: {namespace_details.metadata.creation_timestamp}\n"

            # Display the namespace details
            self.show_output(f"Namespace Details:\n{details}")

        except Exception as e:
            self.show_output(f"Error fetching namespace details: {str(e)}")
        
    
    def get_namespace_resource_quotas(self, namespace):
        """Retrieve the resource quotas for the selected namespace."""
        v1 = client.CoreV1Api()
        try:
            quotas = v1.list_namespaced_resource_quota(namespace=namespace).items
            for quota in quotas:
                self.show_output(f"Resource Quota: {quota.metadata.name}, CPU: {quota.spec.hard.get('limits.cpu')}, Memory: {quota.spec.hard.get('limits.memory')}")
        except Exception as e:
            self.show_output(f"Error fetching resource quotas for namespace {namespace}: {str(e)}")

    def get_resource_quotas(self, namespace):
        """
        Get and display resource quotas for the selected namespace.
        """
        v1 = client.CoreV1Api()

        try:
            # Fetch resource quotas for the selected namespace
            resource_quotas = v1.list_namespaced_resource_quota(namespace=namespace).items

            if not resource_quotas:
                self.show_output(f"No resource quotas found for namespace {namespace}.")
                return

            # Prepare resource quotas in a user-friendly format
            quotas_info = f"Resource Quotas for namespace {namespace}:\n"
            quotas_info += f"{'Quota Name':<30} {'Hard Limits':<40} {'Used':<40}\n"
            quotas_info += "-" * 110 + "\n"

            # Iterate through each quota and display its details
            for quota in resource_quotas:
                quota_name = quota.metadata.name
                hard_limits = quota.status.hard
                used = quota.status.used

                # Format the hard and used resource information
                hard_limits_str = ', '.join([f"{k}: {v}" for k, v in hard_limits.items()])
                used_str = ', '.join([f"{k}: {v}" for k, v in used.items()])

                quotas_info += f"{quota_name:<30} {hard_limits_str:<40} {used_str:<40}\n"

            # Display the formatted resource quotas information
            self.show_output(quotas_info)

        except Exception as e:
            self.show_output(f"Error fetching resource quotas for namespace {namespace}: {str(e)}")


    def set_namespace_quotas(self, namespace, cpu_limit, memory_limit):
        """Set resource quotas for the selected namespace."""
        v1 = client.CoreV1Api()
        quota_body = {
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": {"name": "namespace-quota"},
            "spec": {
                "hard": {
                    "limits.cpu": cpu_limit,
                    "limits.memory": memory_limit,
                }
            }
        }
        try:
            v1.create_namespaced_resource_quota(namespace=namespace, body=quota_body)
            self.show_output(f"Resource quotas set for namespace {namespace}.")
        except Exception as e:
            self.show_output(f"Error setting resource quotas for namespace {namespace}: {str(e)}")


    def get_namespace_events(self, namespace):
        """Fetch recent events for the selected namespace."""
        v1 = client.CoreV1Api()
        try:
            events = v1.list_namespaced_event(namespace).items
            for event in events:
                self.show_output(f"Event: {event.message}, Type: {event.type}, Reason: {event.reason}, Timestamp: {event.last_timestamp}")
        except Exception as e:
            self.show_output(f"Error fetching events for namespace {namespace}: {str(e)}")
            
    def patch_namespace(self, namespace, patch_body):
        """
        Patch the selected namespace with the provided patch body.
        
        Example patch_body: 
        {
            "metadata": {
                "annotations": {
                    "example-annotation-key": "example-annotation-value"
                }
            }
        }
        """
        v1 = client.CoreV1Api()
        
        try:
            # Perform the patch on the namespace
            v1.patch_namespace(name=namespace, body=patch_body)
            self.show_output(f"Namespace {namespace} patched successfully with {patch_body}.")
        except Exception as e:
            self.show_output(f"Error patching namespace {namespace}: {str(e)}")



    def update_namespace_labels(self, namespace, label_key, label_value):
        """Add or update labels for the selected namespace."""
        v1 = client.CoreV1Api()
        try:
            body = {"metadata": {"labels": {label_key: label_value}}}
            v1.patch_namespace(name=namespace, body=body)
            self.show_output(f"Label {label_key}:{label_value} added to namespace {namespace}.")
        except Exception as e:
            self.show_output(f"Error updating labels for namespace {namespace}: {str(e)}")


    def monitor_namespace_usage(self, namespace):
        """Monitor the resource usage (e.g., CPU, memory) of the selected namespace."""
        v1 = client.CoreV1Api()
        try:
            pods = v1.list_namespaced_pod(namespace=namespace).items
            for pod in pods:
                usage = pod.status.container_statuses[0].resources
                self.show_output(f"Pod: {pod.metadata.name}, CPU: {usage.requests.cpu}, Memory: {usage.requests.memory}")
        except Exception as e:
            self.show_output(f"Error monitoring resource usage for namespace {namespace}: {str(e)}")
            
    
    def set_namespace_annotations(self, namespace, annotations):
        """
        Set annotations for the selected namespace.
        
        :param namespace: The namespace to set annotations for.
        :param annotations: A dictionary of annotations to add/update.
        """
        v1 = client.CoreV1Api()

        try:
            # Create the patch body to set annotations
            patch_body = {
                "metadata": {
                    "annotations": annotations
                }
            }

            # Patch the namespace with the new annotations
            v1.patch_namespace(name=namespace, body=patch_body)
            self.show_output(f"Annotations for namespace {namespace} set successfully: {annotations}")

        except Exception as e:
            self.show_output(f"Error setting annotations for namespace {namespace}: {str(e)}")
            
            
            
    def get_namespace_annotations(self, namespace):
        """
        Get and display the annotations of the selected namespace.
        
        :param namespace: The namespace to retrieve annotations from.
        """
        v1 = client.CoreV1Api()

        try:
            # Get the details of the namespace
            ns = v1.read_namespace(name=namespace)

            # Retrieve annotations
            annotations = ns.metadata.annotations

            if annotations:
                # Display annotations in a user-friendly format
                annotations_info = f"Annotations for namespace {namespace}:\n"
                annotations_info += "-" * 40 + "\n"
                for key, value in annotations.items():
                    annotations_info += f"{key}: {value}\n"

                self.show_output(annotations_info)
            else:
                self.show_output(f"No annotations found for namespace {namespace}.")

        except Exception as e:
            self.show_output(f"Error retrieving annotations for namespace {namespace}: {str(e)}")

