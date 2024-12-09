terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "2.66.0"
    }
  }
  required_version = ">= 0.14"
}

provider "azurerm" {
  features {}
  skip_provider_registration = true
}

# Variables
variable "resource_group_name" {
  description = "Name of the Azure resource group"
}

variable "location" {
  description = "Azure location/region for the resource group"
}

variable "aks_cluster_name" {
  description = "Name of the AKS cluster"
}

variable "node_count" {
  default     = 2
  description = "Number of nodes in the AKS cluster node pool"
}

variable "vm_size" {
  default     = "Standard_B2s"
  description = "VM size for the AKS node pool"
}

variable "os_disk_size_gb" {
  default     = 30
  description = "OS Disk size in GB for AKS nodes"
}

variable "app_id" {
  description = "Service principal client ID for AKS"
}

variable "client_secret" {
  description = "Service principal client secret for AKS"
}

# Resource Group
resource "azurerm_resource_group" "guru" {
  name     = var.resource_group_name
  location = var.location

  tags = {
    environment = "Demo"
  }
}

# AKS Cluster
resource "azurerm_kubernetes_cluster" "guru" {
  name                = var.aks_cluster_name
  location            = azurerm_resource_group.guru.location
  resource_group_name = azurerm_resource_group.guru.name
  dns_prefix          = "${var.aks_cluster_name}-dns"

  default_node_pool {
    name            = "nodepool"
    node_count      = var.node_count
    vm_size         = var.vm_size
    os_disk_size_gb = var.os_disk_size_gb
  }

  service_principal {
    client_id     = var.app_id
    client_secret = var.client_secret
  }

  role_based_access_control {
    enabled = true
  }

  tags = {
    environment = "Demo"
  }
}

# Outputs
output "resource_group_name" {
  value       = azurerm_resource_group.guru.name
  description = "Name of the created resource group"
}

output "aks_cluster_name" {
  value       = azurerm_kubernetes_cluster.guru.name
  description = "Name of the AKS cluster"
}
