#!/bin/bash

# Usage: ./force_delete_vpc.sh <VPC_ID>

# Exit immediately if a command exits with a non-zero status
set -e

# Function to display usage instructions
usage() {
    echo "Usage: $0 <VPC_ID>"
    exit 1
}

# Check if VPC_ID is provided
if [ -z "$1" ]; then
    usage
fi

VPC_ID="$1"

echo "==============================="
echo "Force Deleting VPC: $VPC_ID"
echo "==============================="

# Function to delete subnets
delete_subnets() {
    echo "Deleting Subnets..."
    SUBNETS=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID" --query "Subnets[*].SubnetId" --output text)
    for subnet in $SUBNETS; do
        echo "Deleting Subnet: $subnet"
        aws ec2 delete-subnet --subnet-id "$subnet"
    done
}

# Function to detach and delete internet gateways
delete_internet_gateways() {
    echo "Deleting Internet Gateways..."
    IGWS=$(aws ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=$VPC_ID" --query "InternetGateways[*].InternetGatewayId" --output text)
    for igw in $IGWS; do
        echo "Detaching and Deleting Internet Gateway: $igw"
        aws ec2 detach-internet-gateway --internet-gateway-id "$igw" --vpc-id "$VPC_ID"
        aws ec2 delete-internet-gateway --internet-gateway-id "$igw"
    done
}

# Function to delete route tables (excluding main)
delete_route_tables() {
    echo "Deleting Route Tables (excluding main)..."
    ROUTE_TABLES=$(aws ec2 describe-route-tables \
        --filters "Name=vpc-id,Values=$VPC_ID" \
        --query "RouteTables[?Associations[0].Main!=\`true\`].RouteTableId" \
        --output text)
    for rtb in $ROUTE_TABLES; do
        echo "Deleting Route Table: $rtb"
        aws ec2 delete-route-table --route-table-id "$rtb"
    done
}

# Function to delete network ACLs (excluding default)
delete_network_acls() {
    echo "Deleting Network ACLs (excluding default)..."
    NACLs=$(aws ec2 describe-network-acls \
        --filters "Name=vpc-id,Values=$VPC_ID" \
        --query "NetworkAcls[?IsDefault!=\`true\`].NetworkAclId" \
        --output text)
    for nacl in $NACLs; do
        echo "Deleting Network ACL: $nacl"
        aws ec2 delete-network-acl --network-acl-id "$nacl"
    done
}

# Function to delete security groups (excluding default)
delete_security_groups() {
    echo "Deleting Security Groups (excluding default)..."
    SGS=$(aws ec2 describe-security-groups \
        --filters "Name=vpc-id,Values=$VPC_ID" \
        --query "SecurityGroups[?GroupName!='default'].GroupId" \
        --output text)
    for sg in $SGS; do
        echo "Deleting Security Group: $sg"
        aws ec2 delete-security-group --group-id "$sg"
    done
}

# Function to delete NAT gateways
delete_nat_gateways() {
    echo "Deleting NAT Gateways..."
    NAT_GWS=$(aws ec2 describe-nat-gateways \
        --filter "Name=vpc-id,Values=$VPC_ID" \
        --query "NatGateways[*].NatGatewayId" \
        --output text)
    for nat in $NAT_GWS; do
        echo "Deleting NAT Gateway: $nat"
        aws ec2 delete-nat-gateway --nat-gateway-id "$nat"
        # Wait until NAT gateway is deleted
        echo "Waiting for NAT Gateway $nat to be deleted..."
        aws ec2 wait nat-gateway-deleted --nat-gateway-ids "$nat"
        echo "NAT Gateway $nat deleted."
    done
}

# Function to delete VPC endpoints
delete_vpc_endpoints() {
    echo "Deleting VPC Endpoints..."
    VPC_ENDPOINTS=$(aws ec2 describe-vpc-endpoints \
        --filters "Name=vpc-id,Values=$VPC_ID" \
        --query "VpcEndpoints[*].VpcEndpointId" \
        --output text)
    for endpoint in $VPC_ENDPOINTS; do
        echo "Deleting VPC Endpoint: $endpoint"
        aws ec2 delete-vpc-endpoints --vpc-endpoint-ids "$endpoint"
    done
}

# Function to delete network interfaces
delete_network_interfaces() {
    echo "Deleting Network Interfaces..."
    ENIs=$(aws ec2 describe-network-interfaces \
        --filters "Name=vpc-id,Values=$VPC_ID" \
        --query "NetworkInterfaces[*].NetworkInterfaceId" \
        --output text)
    for eni in $ENIs; do
        echo "Deleting Network Interface: $eni"
        aws ec2 delete-network-interface --network-interface-id "$eni"
    done
}

# Function to delete VPC peering connections
delete_vpc_peering_connections() {
    echo "Deleting VPC Peering Connections..."
    PEERINGS=$(aws ec2 describe-vpc-peering-connections \
        --filters "Name=requester-vpc-info.vpc-id,Values=$VPC_ID" "Name=accepter-vpc-info.vpc-id,Values=$VPC_ID" \
        --query "VpcPeeringConnections[*].VpcPeeringConnectionId" \
        --output text)
    for peering in $PEERINGS; do
        echo "Deleting VPC Peering Connection: $peering"
        aws ec2 delete-vpc-peering-connection --vpc-peering-connection-id "$peering"
    done
}

# Function to detach and delete VPN gateways
delete_vpn_gateways() {
    echo "Deleting VPN Gateways..."
    VPN_GWS=$(aws ec2 describe-vpn-gateways \
        --filters "Name=attachment.vpc-id,Values=$VPC_ID" \
        --query "VpnGateways[*].VpnGatewayId" \
        --output text)
    for vpn in $VPN_GWS; do
        echo "Detaching and Deleting VPN Gateway: $vpn"
        aws ec2 detach-vpn-gateway --vpn-gateway-id "$vpn" --vpc-id "$VPC_ID" || echo "VPN Gateway $vpn might not be attached."
        aws ec2 delete-vpn-gateway --vpn-gateway-id "$vpn"
    done
}

# Function to delete load balancers (Classic, Application, Network)
delete_load_balancers() {
    echo "Deleting Load Balancers..."
    
    # Classic Load Balancers
    CLB_NAMES=$(aws elb describe-load-balancers --query "LoadBalancerDescriptions[?VpcId=='$VPC_ID'].LoadBalancerName" --output text)
    for clb in $CLB_NAMES; do
        echo "Deleting Classic Load Balancer: $clb"
        aws elb delete-load-balancer --load-balancer-name "$clb"
    done
    
    # Application and Network Load Balancers
    ALB_ARNS=$(aws elbv2 describe-load-balancers --query "LoadBalancers[?VpcId=='$VPC_ID'].LoadBalancerArn" --output text)
    for alb in $ALB_ARNS; do
        echo "Deleting Application/Network Load Balancer: $alb"
        aws elbv2 delete-load-balancer --load-balancer-arn "$alb"
        # Wait until ALB is deleted
        echo "Waiting for Load Balancer $alb to be deleted..."
        aws elbv2 wait load-balancers-deleted --load-balancer-arns "$alb"
        echo "Load Balancer $alb deleted."
    done
}

# Function to delete EFS file systems
delete_efs_file_systems() {
    echo "Deleting EFS File Systems..."
    EFS_FS_IDS=$(aws efs describe-file-systems --query "FileSystems[?VpcId=='$VPC_ID'].FileSystemId" --output text)
    for fs in $EFS_FS_IDS; do
        echo "Deleting EFS File System: $fs"
        aws efs delete-file-system --file-system-id "$fs"
    done
}

# Function to delete RDS instances
delete_rds_instances() {
    echo "Deleting RDS Instances..."
    RDS_IDS=$(aws rds describe-db-instances --query "DBInstances[?DBSubnetGroup.SubnetIds[*] | contains(@, '$VPC_ID')].DBInstanceIdentifier" --output text)
    for rds in $RDS_IDS; do
        echo "Deleting RDS Instance: $rds"
        aws rds delete-db-instance --db-instance-identifier "$rds" --skip-final-snapshot
        # Wait until RDS instance is deleted
        echo "Waiting for RDS Instance $rds to be deleted..."
        aws rds wait db-instance-deleted --db-instance-identifier "$rds"
        echo "RDS Instance $rds deleted."
    done
}

# Function to delete EKS clusters
delete_eks_clusters() {
    echo "Deleting EKS Clusters..."
    EKS_CLUSTERS=$(aws eks list-clusters --query "clusters[?starts_with(@, '')]" --output text)
    for cluster in $EKS_CLUSTERS; do
        # Check if the cluster is in the specified VPC
        VPC_OF_CLUSTER=$(aws eks describe-cluster --name "$cluster" --query "cluster.resourcesVpcConfig.vpcId" --output text)
        if [ "$VPC_OF_CLUSTER" == "$VPC_ID" ]; then
            echo "Deleting EKS Cluster: $cluster"
            aws eks delete-cluster --name "$cluster"
            # Wait until EKS cluster is deleted
            echo "Waiting for EKS Cluster $cluster to be deleted..."
            aws eks wait cluster-deleted --name "$cluster"
            echo "EKS Cluster $cluster deleted."
        fi
    done
}

# Function to delete DynamoDB VPC endpoints (if any)
delete_dynamodb_endpoints() {
    echo "Deleting DynamoDB VPC Endpoints..."
    DYNAMODB_ENDPOINTS=$(aws ec2 describe-vpc-endpoints \
        --filters "Name=vpc-id,Values=$VPC_ID" "Name=service-name,Values=*.dynamodb.*" \
        --query "VpcEndpoints[*].VpcEndpointId" \
        --output text)
    for endpoint in $DYNAMODB_ENDPOINTS; do
        echo "Deleting DynamoDB VPC Endpoint: $endpoint"
        aws ec2 delete-vpc-endpoints --vpc-endpoint-ids "$endpoint"
    done
}

# Function to delete any remaining resources
delete_remaining_resources() {
    echo "Checking for any remaining resources..."
    
    # VPC Peering Connections
    delete_vpc_peering_connections
    
    # VPN Gateways
    delete_vpn_gateways
    
    # Load Balancers
    delete_load_balancers
    
    # EFS File Systems
    delete_efs_file_systems
    
    # RDS Instances
    delete_rds_instances
    
    # DynamoDB VPC Endpoints
    delete_dynamodb_endpoints
}

# Execute deletion functions
delete_subnets
delete_internet_gateways
delete_route_tables
delete_network_acls
delete_security_groups
delete_nat_gateways
delete_vpc_endpoints
delete_network_interfaces
delete_load_balancers
delete_efs_file_systems
delete_rds_instances
delete_dynamodb_endpoints
delete_vpc_peering_connections
delete_vpn_gateways

# Final check for any remaining resources
delete_remaining_resources

# Attempt to delete the VPC again
echo "Attempting to delete VPC: $VPC_ID"
aws ec2 delete-vpc --vpc-id "$VPC_ID" && echo "VPC $VPC_ID deleted successfully." || echo "Failed to delete VPC $VPC_ID. There might still be dependencies."

echo "=========================================="
echo "Deletion Process Completed for VPC: $VPC_ID"
echo "=========================================="
