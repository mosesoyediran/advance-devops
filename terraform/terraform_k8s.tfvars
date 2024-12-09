# terraform.tfvars

region = "us-east-1"

vpc_cidr_block = "10.0.0.0/16"

private_subnet_cidr_blocks = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
public_subnet_cidr_blocks  = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]

availability_zones = ["us-east-1a", "us-east-1b", "us-east-1c"]

environment_prefix = "k8s"

instance_type = "t2.medium"

my_ip = "88.88.90.132/32" # Replace with your actual public IP

worker_count = 2

create_nat_gateway = false
