#!/bin/bash

# The public key content to be added to authorized_keys
PUB_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCweTe+dC8j+74qLfXHkEs7bZNX17QvMduRiQ+3dTjc08nJjim1hwmVktnfFDnigmGbsqEZ73YnDPHr1IErV6vlVuu2+YkCo8WCfo1PToWlXXK5sEn03AaF9p/OC23iiViUuK1wvVhezfndusVI/IvJhYCB4y9PNnpDhrdIdC3aGNEJ8fOzX7kIckzjxp3yLbEMFpii6y1At0fNHcNR9zGQ2fEY13HO5teb91i/e8wtEspUogcTpKYdQljWmFsYUBS4/Dl5QXWFK5wOWj1nZh5D9jyxqahESpPym4eT2thhmtwlKBND2lsHMvVVZxcTYkQoiktpcM6rOWZLo+UfDplP moses@mosess-mbp.lan"

# Path to the authorized_keys file
AUTHORIZED_KEYS="/home/ubuntu/.ssh/authorized_keys"

echo "Adding public key to $AUTHORIZED_KEYS"

# Make sure the .ssh directory exists
mkdir -p /home/ubuntu/.ssh

# Append the public key to authorized_keys
echo "$PUB_KEY" >> "$AUTHORIZED_KEYS"

# Set the correct permissions
chown -R ubuntu:ubuntu /home/ubuntu/.ssh
chmod 700 /home/ubuntu/.ssh
chmod 600 "$AUTHORIZED_KEYS"

echo "Public key added successfully to $AUTHORIZED_KEYS"
