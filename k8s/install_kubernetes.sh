#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

echo "Starting Kubernetes installation..."

# Update the package list and install dependencies
echo "Updating package list and installing dependencies..."
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl gnupg

# Create the directory for apt keyrings if it does not exist
echo "Creating apt keyrings directory..."
sudo mkdir -p /etc/apt/keyrings

# Download and add the Kubernetes GPG key
echo "Adding Kubernetes GPG key..."
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.31/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg

# Add the Kubernetes repository
echo "Adding Kubernetes repository..."
echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.31/deb/ /' | sudo tee /etc/apt/sources.list.d/kubernetes.list

# Update the package list again
echo "Updating package list with Kubernetes repository..."
sudo apt-get update

# Install kubeadm, kubectl, and kubelet
echo "Installing kubeadm, kubectl, and kubelet..."
sudo apt-get install -y kubelet kubeadm kubectl

# Mark kubeadm, kubectl, and kubelet to avoid automatic upgrades
echo "Marking Kubernetes packages to avoid automatic upgrades..."
sudo apt-mark hold kubelet kubeadm kubectl

echo "Kubernetes installation completed successfully!"
