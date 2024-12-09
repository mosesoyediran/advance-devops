# mock_fcntl.py
# Mock module for fcntl on Windows

def flock(fd, operation):
    pass

def fcntl(*args, **kwargs):
    pass

# Add any other necessary mock functions or classes that 'ansible_runner' may use
