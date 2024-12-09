import socket


def get_server_ip_address():
    """
    Fetches the primary IP address of the server.
    """
    try:
        # This will get the server's primary IP address.
        hostname = socket.gethostname()
        ip_addresses = socket.gethostbyname_ex(hostname)[2]
        for ip in ip_addresses:
            if not ip.startswith("127."):  # Exclude loopback addresses
                return ip
    except Exception:
        return "127.0.0.1"  # Fallback to localhost if unable to fetch
    return "127.0.0.1"