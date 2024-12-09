#!/bin/bash

VPC_ID="vpc-0891b193d7d290651"

echo "Deleting resources associated with VPC: $VPC_ID"

# Delete subnets
echo "Deleting subnets..."
SUBNETS=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID" --query "Subnets[*].SubnetId" --output text)
for subnet in $SUBNETS; do
    echo "Deleting subnet: $subnet"
    aws ec2 delete-subnet --subnet-id $subnet
done

# Detach and delete internet gateways
echo "Deleting internet gateways..."
IGWS=$(aws ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=$VPC_ID" --query "InternetGateways[*].InternetGatewayId" --output text)
for igw in $IGWS; do
    echo "Detaching and deleting internet gateway: $igw"
    aws ec2 detach-internet-gateway --internet-gateway-id $igw --vpc-id $VPC_ID
    aws ec2 delete-internet-gateway --internet-gateway-id $igw
done

# Delete route tables (except the main route table)
echo "Deleting route tables..."
ROUTE_TABLES=$(aws ec2 describe-route-tables --filters "Name=vpc-id,Values=$VPC_ID" --query "RouteTables[?Associations[0].Main==\`false\`].RouteTableId" --output text)
for rtb in $ROUTE_TABLES; do
    echo "Deleting route table: $rtb"
    aws ec2 delete-route-table --route-table-id $rtb
done

# Delete network ACLs (except the default one)
echo "Deleting network ACLs..."
NACLs=$(aws ec2 describe-network-acls --filters "Name=vpc-id,Values=$VPC_ID" --query "NetworkAcls[?IsDefault==\`false\`].NetworkAclId" --output text)
for nacl in $NACLs; do
    echo "Deleting network ACL: $nacl"
    aws ec2 delete-network-acl --network-acl-id $nacl
done

# Delete security groups (except the default security group)
echo "Deleting security groups..."
SGS=$(aws ec2 describe-security-groups --filters "Name=vpc-id,Values=$VPC_ID" --query "SecurityGroups[?GroupName!='default'].GroupId" --output text)
for sg in $SGS; do
    echo "Deleting security group: $sg"
    aws ec2 delete-security-group --group-id $sg
done

# Delete NAT gateways
echo "Deleting NAT gateways..."
NAT_GWS=$(aws ec2 describe-nat-gateways --filter "Name=vpc-id,Values=$VPC_ID" --query "NatGateways[*].NatGatewayId" --output text)
for nat in $NAT_GWS; do
    echo "Deleting NAT gateway: $nat"
    aws ec2 delete-nat-gateway --nat-gateway-id $nat
done

# Delete network interfaces
echo "Deleting network interfaces..."
ENIs=$(aws ec2 describe-network-interfaces --filters "Name=vpc-id,Values=$VPC_ID" --query "NetworkInterfaces[*].NetworkInterfaceId" --output text)
for eni in $ENIs; do
    echo "Deleting network interface: $eni"
    aws ec2 delete-network-interface --network-interface-id $eni
done

# Delete VPC endpoints
echo "Deleting VPC endpoints..."
VPC_ENDPOINTS=$(aws ec2 describe-vpc-endpoints --filters "Name=vpc-id,Values=$VPC_ID" --query "VpcEndpoints[*].VpcEndpointId" --output text)
for endpoint in $VPC_ENDPOINTS; do
    echo "Deleting VPC endpoint: $endpoint"
    aws ec2 delete-vpc-endpoints --vpc-endpoint-ids $endpoint
done

# Finally, delete the VPC
echo "Deleting VPC: $VPC_ID"
aws ec2 delete-vpc --vpc-id $VPC_ID

echo "VPC and all its resources deleted successfully."
