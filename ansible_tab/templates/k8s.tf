# main.tf

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}


# Provider Configuration
provider "aws" {
  region = var.region
}

# Variables

variable "region" {
  description = "AWS region"
}

variable "vpc_cidr_block" {
  description = "CIDR block for the VPC"
}

variable "private_subnet_cidr_blocks" {
  description = "List of CIDR blocks for private subnets"
  type        = list(string)
}

variable "public_subnet_cidr_blocks" {
  description = "List of CIDR blocks for public subnets"
  type        = list(string)
}

variable "availability_zones" {
  description = "List of availability zones to use"
  type        = list(string)
}

variable "environment_prefix" {
  description = "Prefix for resource names"
}

variable "instance_type" {
  description = "EC2 instance type"
}

variable "my_ip" {
  description = "Your public IP address with CIDR suffix"
}

variable "worker_count" {
  description = "Number of worker nodes"
  default     = 2
}

variable "create_nat_gateway" {
  description = "Whether to create a NAT Gateway"
  type        = bool
  default     = false
}

# Generate SSH Key Pair
resource "tls_private_key" "kubernetes_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "kubernetes" {
  key_name   = "${var.environment_prefix}-key"
  public_key = tls_private_key.kubernetes_key.public_key_openssh
}


# Output the private key for use in Ansible or elsewhere
output "private_key_pem" {
  value = tls_private_key.kubernetes_key.private_key_pem
  sensitive = true
}


# VPC Configuration
resource "aws_vpc" "kubernetes_vpc" {
  cidr_block = var.vpc_cidr_block

  tags = {
    Name = "${var.environment_prefix}-vpc"
  }
}

# Public Subnets
resource "aws_subnet" "public_subnets" {
  count                   = length(var.public_subnet_cidr_blocks)
  vpc_id                  = aws_vpc.kubernetes_vpc.id
  cidr_block              = var.public_subnet_cidr_blocks[count.index]
  availability_zone       = element(var.availability_zones, count.index % length(var.availability_zones))
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.environment_prefix}-public-subnet-${count.index + 1}"
  }
}

# Private Subnets
resource "aws_subnet" "private_subnets" {
  count             = length(var.private_subnet_cidr_blocks)
  vpc_id            = aws_vpc.kubernetes_vpc.id
  cidr_block        = var.private_subnet_cidr_blocks[count.index]
  availability_zone = element(var.availability_zones, count.index % length(var.availability_zones))

  tags = {
    Name = "${var.environment_prefix}-private-subnet-${count.index + 1}"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "kubernetes_igw" {
  vpc_id = aws_vpc.kubernetes_vpc.id

  tags = {
    Name = "${var.environment_prefix}-igw"
  }
}

# NAT Gateway (optional, for private subnets to access the internet)
resource "aws_eip" "nat_eip" {
  count = var.create_nat_gateway ? 1 : 0
  
}

resource "aws_nat_gateway" "nat_gw" {
  count         = var.create_nat_gateway ? 1 : 0
  allocation_id = aws_eip.nat_eip[0].id
  subnet_id     = aws_subnet.public_subnets[0].id

  tags = {
    Name = "${var.environment_prefix}-nat-gw"
  }
}

# Route Tables
## Public Route Table
resource "aws_route_table" "public_route_table" {
  vpc_id = aws_vpc.kubernetes_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.kubernetes_igw.id
  }

  tags = {
    Name = "${var.environment_prefix}-public-route-table"
  }
}

## Private Route Table
resource "aws_route_table" "private_route_table" {
  vpc_id = aws_vpc.kubernetes_vpc.id

  # Route through NAT Gateway if created
  dynamic "route" {
    for_each = var.create_nat_gateway ? [1] : []
    content {
      cidr_block     = "0.0.0.0/0"
      nat_gateway_id = aws_nat_gateway.nat_gw[0].id
    }
  }

  tags = {
    Name = "${var.environment_prefix}-private-route-table"
  }
}

# Route Table Associations
## Associate Public Subnets
resource "aws_route_table_association" "public_subnet_associations" {
  count          = length(aws_subnet.public_subnets)
  subnet_id      = aws_subnet.public_subnets[count.index].id
  route_table_id = aws_route_table.public_route_table.id
}

## Associate Private Subnets
resource "aws_route_table_association" "private_subnet_associations" {
  count          = length(aws_subnet.private_subnets)
  subnet_id      = aws_subnet.private_subnets[count.index].id
  route_table_id = aws_route_table.private_route_table.id
}

# Security Group
resource "aws_security_group" "kubernetes_sg" {
  name        = "${var.environment_prefix}-sg"
  description = "Security group for Kubernetes cluster"
  vpc_id      = aws_vpc.kubernetes_vpc.id

  # Allow SSH from your IP
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.my_ip]
  }

  # Kubernetes Ports
  ingress {
    from_port   = 6443
    to_port     = 6443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Kubernetes API server
  }

  # Allow all traffic within the VPC (for cluster communication)
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [aws_vpc.kubernetes_vpc.cidr_block]
    description = "Allow all within VPC"
  }

  # Kubernetes NodePort Range
  ingress {
    from_port   = 30000
    to_port     = 32767
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "NodePort Services"
  }

  # Kubernetes Etcd Ports (Master Nodes)
  ingress {
    from_port   = 2379
    to_port     = 2380
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.kubernetes_vpc.cidr_block]
    description = "Etcd Server Client API"
  }

  # Kubernetes Scheduler Ports (Master Nodes)
  ingress {
    from_port   = 10251
    to_port     = 10251
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.kubernetes_vpc.cidr_block]
    description = "Kube-scheduler"
  }

  # Kubernetes Controller Manager Ports (Master Nodes)
  ingress {
    from_port   = 10252
    to_port     = 10252
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.kubernetes_vpc.cidr_block]
    description = "Kube-controller-manager"
  }

  # Kubernetes Kubelet API
  ingress {
    from_port   = 10250
    to_port     = 10250
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.kubernetes_vpc.cidr_block]
    description = "Kubelet API"
  }

  # Egress Rules
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.environment_prefix}-sg"
  }
}



# Data source for Ubuntu Server 20.04 LTS AMI
# Data source for Ubuntu Server 20.04 LTS AMI (simplified)
data "aws_ami" "ubuntu_20_04" {
  most_recent = true
  owners      = ["099720109477"]  # Canonical's AWS account ID

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Fallback to a specific AMI ID (if query fails)
locals {
  default_ami = "ami-05f7491af5eef733a"
}

# Master Node
resource "aws_instance" "master" {
  ami                         = coalesce(data.aws_ami.ubuntu_20_04.id, local.default_ami)  # Fallback to a specific AMI
  instance_type               = "t2.medium"
  key_name                    = aws_key_pair.kubernetes.key_name
  subnet_id                   = aws_subnet.public_subnets[0].id
  vpc_security_group_ids      = [aws_security_group.kubernetes_sg.id]
  associate_public_ip_address = true
  availability_zone           = aws_subnet.public_subnets[0].availability_zone

  tags = {
    Name = "${var.environment_prefix}-master"
    Role = "master"
  }
}

# Worker Nodes
resource "aws_instance" "worker" {
  count                       = var.worker_count
  ami                         = coalesce(data.aws_ami.ubuntu_20_04.id, local.default_ami)  # Fallback to a specific AMI
  instance_type               = "t2.large"
  key_name                    = aws_key_pair.kubernetes.key_name
  subnet_id                   = aws_subnet.public_subnets[(count.index + 1) % length(aws_subnet.public_subnets)].id
  vpc_security_group_ids      = [aws_security_group.kubernetes_sg.id]
  associate_public_ip_address = true
  availability_zone           = aws_subnet.public_subnets[(count.index + 1) % length(aws_subnet.public_subnets)].availability_zone

  tags = {
    Name = "${var.environment_prefix}-worker-${count.index + 1}"
    Role = "worker"
  }
}


# Outputs
output "master_public_ip" {
  value = aws_instance.master.public_ip
}

output "worker_public_ips" {
  value = [for instance in aws_instance.worker : instance.public_ip]
}

output "ami_used" {
  value = data.aws_ami.ubuntu_20_04.id
}