
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}


provider "aws" {
  region = "us-east-1"
}

# Variables
variable "vpc_cidr_block" {}
variable "subnet_1_cidr_block" {}
variable "avail_zone" {}
variable "env_prefix" {}
variable "instance_type" {}
variable "my_ip" {}
variable "playbook_name" {
  description = "The name of the Ansible playbook to run"
  type        = string
}
variable "inventory_file" {
  description = "Path to the Ansible inventory file"
  type        = string
}
variable "project_folder" {
  description = "Path to the project folder containing playbook_runner.py"
  type        = string
}
variable "playbook_runner_path" {
  description = "Path to the playbook runner script"
  type        = string
}
variable "env_path" {
  description = "The path to the Python virtual environment"
  default     = "/Users/moses/Documents/documents/dvp/env"
}

# Fetch the latest Amazon Linux 2 AMI
data "aws_ami" "amazon-linux-image" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Generate an SSH private key
resource "tls_private_key" "ssh_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# Create the AWS Key Pair using the generated public key
resource "aws_key_pair" "ssh_key" {
  key_name   = "myapp-key"
  public_key = tls_private_key.ssh_key.public_key_openssh
}

# Output the private key for use in Ansible or elsewhere
output "private_key_pem" {
  value     = tls_private_key.ssh_key.private_key_pem
  sensitive = true
}

# Output the AMI ID
output "ami_id" {
  value = data.aws_ami.amazon-linux-image.id
}

# VPC Configuration
resource "aws_vpc" "myapp-vpc" {
  cidr_block           = var.vpc_cidr_block
  enable_dns_hostnames = true
  tags = {
    Name = "${var.env_prefix}-vpc"
  }
}

# Subnet Configuration
resource "aws_subnet" "myapp-subnet-1" {
  vpc_id            = aws_vpc.myapp-vpc.id
  cidr_block        = var.subnet_1_cidr_block
  availability_zone = var.avail_zone
  tags = {
    Name = "${var.env_prefix}-subnet-1"
  }
}

# Security Group
resource "aws_security_group" "myapp-sg" {
  name   = "myapp-sg"
  vpc_id = aws_vpc.myapp-vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.my_ip]
  }

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
    prefix_list_ids = []
  }

  tags = {
    Name = "${var.env_prefix}-sg"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "myapp-igw" {
  vpc_id = aws_vpc.myapp-vpc.id
  tags = {
    Name = "${var.env_prefix}-internet-gateway"
  }
}

# Route Table
resource "aws_route_table" "myapp-route-table" {
  vpc_id = aws_vpc.myapp-vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.myapp-igw.id
  }

  tags = {
    Name = "${var.env_prefix}-route-table"
  }
}

# Route Table Association
resource "aws_route_table_association" "a-rtb-subnet" {
  subnet_id      = aws_subnet.myapp-subnet-1.id
  route_table_id = aws_route_table.myapp-route-table.id
}


# Output the OS
output "instance_os" {
  value = data.aws_ami.amazon-linux-image.name  # This will contain information like "amzn2-ami-hvm"
}

# Output server IP address
output "server-ip" {
  value = aws_instance.myapp-server.public_ip
}

# AWS EC2 Instance
resource "aws_instance" "myapp-server" {
  ami                         = data.aws_ami.amazon-linux-image.id
  instance_type               = var.instance_type
  key_name                    = "myapp-key"
  associate_public_ip_address = true
  subnet_id                   = aws_subnet.myapp-subnet-1.id
  vpc_security_group_ids      = [aws_security_group.myapp-sg.id]
  availability_zone           = var.avail_zone

  tags = {
    Name = "${var.env_prefix}-server"
  }
}

# Additional AWS EC2 Instance
resource "aws_instance" "myapp-server-two" {
  ami                         = data.aws_ami.amazon-linux-image.id
  instance_type               = var.instance_type
  key_name                    = "myapp-key"
  associate_public_ip_address = true
  subnet_id                   = aws_subnet.myapp-subnet-1.id
  vpc_security_group_ids      = [aws_security_group.myapp-sg.id]
  availability_zone           = var.avail_zone

  tags = {
    Name = "${var.env_prefix}-server-two"
  }
}
