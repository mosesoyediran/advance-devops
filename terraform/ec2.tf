# Variables
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}


variable "region" {
  default = "us-east-1"
}

variable "vpc_cidr_block" {}
variable "subnet_1_cidr_block" {}
variable "subnet_2_cidr_block" {}
variable "avail_zone" {}
variable "env_prefix" {}
variable "instance_type" {}
variable "ssh_key" {}
variable "my_ip" {}
variable "server_count" {
  default = 1
}


variable "public_ip_enabled" {
  default = true
}

variable "server_name_suffix" {
  default = "server"
}

variable "ingress_ports" {
  type = list
  default = [8080]
}

variable "egress_cidr_blocks" {
  default = ["0.0.0.0/0"]
}

# Provider
provider "aws" {
  region = var.region
}

# Data source for Amazon Linux AMI
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

output "ami_id" {
  value = data.aws_ami.amazon-linux-image.id
}

# VPC
resource "aws_vpc" "myapp-vpc" {
  cidr_block = var.vpc_cidr_block
  tags = {
      Name = "${var.env_prefix}-vpc"
  }
}

# Subnets
resource "aws_subnet" "myapp-subnet-1" {
  vpc_id = aws_vpc.myapp-vpc.id
  cidr_block = var.subnet_1_cidr_block
  availability_zone = var.avail_zone
  tags = {
      Name = "${var.env_prefix}-subnet-1"
  }
}

resource "aws_subnet" "myapp-subnet-2" {
  vpc_id = aws_vpc.myapp-vpc.id
  cidr_block = var.subnet_2_cidr_block
  availability_zone = var.avail_zone
  tags = {
      Name = "${var.env_prefix}-subnet-2"
  }
}

# Security Group with Dynamic Ingress
resource "aws_security_group" "myapp-sg" {
  name   = "myapp-sg"
  vpc_id = aws_vpc.myapp-vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.my_ip]
  }

  dynamic "ingress" {
    for_each = var.ingress_ports
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = var.egress_cidr_blocks
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

# Route Table and Association
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

resource "aws_route_table_association" "a-rtb-subnet" {
  subnet_id      = aws_subnet.myapp-subnet-1.id
  route_table_id = aws_route_table.myapp-route-table.id
}

# Key Pair
resource "aws_key_pair" "ssh-key" {
  key_name   = "aws-web"
  public_key = file(var.ssh_key)
}

# EC2 Instances with Dynamic Configuration
resource "aws_instance" "myapp-server" {
  count                      = var.server_count
  ami                        = data.aws_ami.amazon-linux-image.id
  instance_type              = var.instance_type
  key_name                   = "aws-web"
  associate_public_ip_address = var.public_ip_enabled
  subnet_id                  = aws_subnet.myapp-subnet-1.id
  vpc_security_group_ids      = [aws_security_group.myapp-sg.id]
  availability_zone           = var.avail_zone

  tags = {
    Name = "${var.env_prefix}-${var.server_name_suffix}-${count.index + 1}"
  }


}

# Outputs
output "server-ip" {
  value = aws_instance.myapp-server.*.public_ip
}

