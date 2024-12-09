# # variables.tf

# variable "region" {
#   description = "AWS region"
# }

# variable "vpc_cidr_block" {
#   description = "CIDR block for the VPC"
# }

# variable "private_subnet_cidr_blocks" {
#   description = "List of CIDR blocks for private subnets"
#   type        = list(string)
# }

# variable "public_subnet_cidr_blocks" {
#   description = "List of CIDR blocks for public subnets"
#   type        = list(string)
# }

# variable "availability_zones" {
#   description = "List of availability zones to use"
#   type        = list(string)
# }

# variable "environment_prefix" {
#   description = "Prefix for resource names"
# }

# variable "instance_type" {
#   description = "EC2 instance type"
# }

# variable "my_ip" {
#   description = "Your public IP address with CIDR suffix"
# }

# variable "worker_count" {
#   description = "Number of worker nodes"
#   default     = 2
# }

# variable "create_nat_gateway" {
#   description = "Whether to create a NAT Gateway"
#   type        = bool
#   default     = false
# }
