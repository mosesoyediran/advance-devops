import os
import site
import sys


def get_ansible_env_path():
    """Generate the dynamic path to the environment's ansible package."""
    # Get the base path for the current Python environment
    base_env_path = sys.prefix
    
    # Get the site-packages path for the current environment
    site_packages = site.getsitepackages() if hasattr(site, 'getsitepackages') else []
    
    # Construct the ansible path inside site-packages
    for path in site_packages:
        ansible_path = os.path.join(path, 'ansible')
        if os.path.exists(ansible_path):
            return ansible_path
    
    # If no path is found, use a fallback (sysconfig can be another option)
    return os.path.join(base_env_path, 'lib', f'python{sys.version_info.major}.{sys.version_info.minor}', 'site-packages', 'ansible')