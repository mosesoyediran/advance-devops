##########################
# Terraform Configuration #
##########################

# ---------------------------
# Terraform Settings
# ---------------------------
terraform {
  # Specify the required Terraform version
  required_version = ">= 1.3.0"

  # Define the required providers and their versions
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.61.0"  # AWS Provider Version
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.0.0"  # Kubernetes Provider Version
    }
  }
}

# ---------------------------
# Provider Configurations
# ---------------------------

# AWS Provider
provider "aws" {
  region = "us-east-1"  # AWS Region
}

# Kubernetes Provider for communication with EKS cluster
provider "kubernetes" {
  load_config_file       = false
  host                   = data.aws_eks_cluster.myapp-cluster.endpoint
  token                  = data.aws_eks_cluster_auth.myapp-cluster.token
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.myapp-cluster.certificate_authority.0.data)
}

# ---------------------------
# Variable Definitions
# ---------------------------

# Define variables for VPC
variable "vpc_cidr_block" {
  description = "CIDR block for the VPC"
  type        = string
}

variable "private_subnet_cidr_blocks" {
  description = "List of CIDR blocks for private subnets"
  type        = list(string)
}

variable "public_subnet_cidr_blocks" {
  description = "List of CIDR blocks for public subnets"
  type        = list(string)
}

variable "ssh_key" {}

# ---------------------------
# Data Sources
# ---------------------------

# Availability Zones
data "aws_availability_zones" "available" {}

# EKS Cluster Data
data "aws_eks_cluster" "myapp-cluster" {
  name = module.eks.cluster_id
}

# EKS Cluster Authentication Data
data "aws_eks_cluster_auth" "myapp-cluster" {
  name = module.eks.cluster_id
}

# ---------------------------
# VPC Module
# ---------------------------

module "myapp-vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.13.0"  # Updated to the latest VPC Module Version

  name            = "myapp-vpc"
  cidr            = var.vpc_cidr_block
  private_subnets = var.private_subnet_cidr_blocks
  public_subnets  = var.public_subnet_cidr_blocks
  azs             = data.aws_availability_zones.available.names

  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true

  tags = {
    "kubernetes.io/cluster/myapp-eks-cluster" = "shared"
  }

  public_subnet_tags = {
    "kubernetes.io/cluster/myapp-eks-cluster" = "shared"
    "kubernetes.io/role/elb"                  = 1
  }

  private_subnet_tags = {
    "kubernetes.io/cluster/myapp-eks-cluster" = "shared"
    "kubernetes.io/role/internal-elb"         = 1
  }
}

# ---------------------------
# EKS Cluster Module
# ---------------------------

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "20.24.1"  # Updated to the latest EKS Module Version

  cluster_name    = "myapp-eks-cluster"  # Ensure this is sufficiently long
  cluster_version = "1.31"

  vpc_id     = module.myapp-vpc.vpc_id
  subnet_ids = module.myapp-vpc.private_subnets

  tags = {
    environment = "development"
    application = "myapp"
  }

  # Managed Node Groups - Switch to Self-Managed Node Groups
  eks_managed_node_groups = {
    worker_group_1 = {
      desired_capacity = 2
      max_capacity     = 3
      min_capacity     = 1

      instance_type = "t2.small"
      key_name      = var.ssh_key 
      

      additional_security_group_ids = [module.myapp-vpc.default_security_group_id]
      additional_tags = {
        "Name" = "worker-group-1"
      }
    }

    worker_group_2 = {
      desired_capacity = 1
      max_capacity     = 2
      min_capacity     = 1

      instance_type = "t2.medium"
      key_name      = var.ssh_key 
      

      additional_security_group_ids = [module.myapp-vpc.default_security_group_id]
      additional_tags = {
        "Name" = "worker-group-2"
      }
    }
  }
}

# ---------------------------
# Outputs
# ---------------------------


# Outputs for VPC module
output "vpc_id" {
  description = "The ID of the created VPC"
  value       = module.myapp-vpc.vpc_id
}

output "private_subnets" {
  description = "List of private subnet IDs created in the VPC"
  value       = module.myapp-vpc.private_subnets
}

output "public_subnets" {
  description = "List of public subnet IDs created in the VPC"
  value       = module.myapp-vpc.public_subnets
}

# Outputs for EKS cluster and nodes
output "eks_cluster_name" {
  description = "Name of the EKS cluster"
  value       = module.eks.cluster_name
}

output "eks_cluster_endpoint" {
  description = "EKS cluster endpoint"
  value       = data.aws_eks_cluster.myapp-cluster.endpoint
}

output "eks_cluster_ca_certificate" {
  description = "Cluster certificate authority data"
  value       = data.aws_eks_cluster.myapp-cluster.certificate_authority.0.data
}


# Marking eks_cluster_token as sensitive
output "eks_cluster_token" {
  description = "Authentication token for the EKS cluster"
  value       = data.aws_eks_cluster_auth.myapp-cluster.token
  sensitive   = true  # Explicitly marking as sensitive
}
