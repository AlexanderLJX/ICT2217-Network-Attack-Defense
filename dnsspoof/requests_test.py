class Response:
    def __init__(self, status_code, headers, text):
        self.status_code = status_code
        self.headers = headers
        self.text = text
        self.content = text.encode()  # To mimic the `content` attribute of `requests.Response`


import socket

def http_get(host, path):
    # Create a socket object
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)  # Set timeout

    try:
        # Connect to the server
        sock.connect((host, 80))

        # Create and send the HTTP GET request
        request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        sock.sendall(request.encode())

        # Receive the response from the server
        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
    except socket.error as e:
        print(f"Socket error: {e}")
        return None
    finally:
        sock.close()

    # Decode the response
    response_text = response.decode()

    # Split headers and body
    headers_text, body = response_text.split("\r\n\r\n", 1)
    headers_lines = headers_text.split("\r\n")
    
    # Extract status code
    status_line = headers_lines[0]
    status_code = int(status_line.split()[1])
    
    # Extract headers
    headers = {}
    for header_line in headers_lines[1:]:
        key, value = header_line.split(": ", 1)
        headers[key] = value
    
    return Response(status_code, headers, body)


import ssl

def https_get(host, path):
    # Create a socket object
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)  # Set timeout

    # Wrap the socket with SSL
    context = ssl.create_default_context()
    ssock = context.wrap_socket(sock, server_hostname=host)

    try:
        # Connect to the server
        ssock.connect((host, 443))

        # Create and send the HTTP GET request
        request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        ssock.sendall(request.encode())

        # Receive the response from the server
        response = b""
        while True:
            data = ssock.recv(4096)
            if not data:
                break
            response += data
    except socket.error as e:
        print(f"Socket error: {e}")
        return None
    finally:
        ssock.close()

    # Decode the response
    response_text = response.decode()

    # Split headers and body
    headers_text, body = response_text.split("\r\n\r\n", 1)
    headers_lines = headers_text.split("\r\n")
    
    # Extract status code
    status_line = headers_lines[0]
    status_code = int(status_line.split()[1])
    
    # Extract headers
    headers = {}
    for header_line in headers_lines[1:]:
        key, value = header_line.split(": ", 1)
        headers[key] = value
    
    return Response(status_code, headers, body)
