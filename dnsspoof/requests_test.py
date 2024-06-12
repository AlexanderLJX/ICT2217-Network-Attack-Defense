import socket

def simple_http_get(host, path):
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
    headers, body = response_text.split("\r\n\r\n", 1)
    return headers, body

# # Usage example
# host = 'example.com'
# path = '/'
# headers, body = simple_http_get(host, path)
# print('Headers:', headers)
# print('Body:', body[:500])  # Print the first 500 characters of the body
