terraform {
  required_providers {
    linode = {
      source  = "linode/linode"
      version = "1.24.0"
    }
  }
  required_version = ">= 0.14"
}

provider "linode" {
  token = var.linode_api_token
}

# Variables
variable "linode_api_token" {
  description = "Linode API Token"
  sensitive   = true
}

variable "linode_count" {
  description = "Number of Linode instances to create"
  default     = 1
}

variable "region" {
  description = "Linode region for the instances"
  default     = "us-east"
}

variable "image" {
  description = "Image to use for Linode instances"
  default     = "linode/ubuntu20.04"
}

variable "instance_type" {
  description = "Linode instance type"
  default     = "g6-standard-1"
}

variable "ssh_username" {
  description = "Admin username for SSH access"
  default     = "linodeuser"
}

# Generating SSH key pair
resource "tls_private_key" "ssh_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "local_file" "private_key" {
  content  = tls_private_key.ssh_key.private_key_pem
  filename = "${path.module}/linode_private_key.pem"
}

# Linode Instances
resource "linode_instance" "nodes" {
  count   = var.linode_count
  label   = "${var.ssh_username}-linode-${count.index}"
  region  = var.region
  image   = var.image
  type    = var.instance_type
  root_pass = tls_private_key.ssh_key.private_key_pem
  
  authorized_keys = [
    tls_private_key.ssh_key.public_key_openssh
  ]

  tags = ["terraform", "linode"]

  # Optional configuration options
  backups {
    enabled = true
  }

  # Linode instance settings
  private_ip = false

  # Set the default SSH username
  ssh {
    username = var.ssh_username
  }
}

# Outputs
output "ssh_private_key_path" {
  value       = local_file.private_key.filename
  description = "Path to the private SSH key for Linode instances"
}

output "linode_ips" {
  value       = [for node in linode_instance.nodes[*] : node.ip_address]
  description = "Public IP addresses of Linode instances"
}

output "ssh_command" {
  value       = "ssh -i ${local_file.private_key.filename} ${var.ssh_username}@<IP_ADDRESS>"
  description = "Command to SSH into the Linode instance"
}
