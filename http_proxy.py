import socket
import threading

BUFFER_SIZE = 8192


# Optional filter logic
def should_block_request(request_data):
    try:
        request_line = request_data.split(b"\r\n")[0]
        method, path, _ = request_line.decode().split()
        print(f"[>] Method: {method}, Path: {path}")

        # Example: block requests to Facebook
        if b"facebook.com" in request_data:
            return True
    except Exception as e:
        print(f"[!] Filter error: {e}")
    return False


def handle_client(client_socket):
    try:
        request_data = client_socket.recv(BUFFER_SIZE)
        if not request_data:
            client_socket.close()
            return

        if should_block_request(request_data):
            print("[X] Blocking request")
            client_socket.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked by proxydssd")
            client_socket.close()
            return

        # Parse destination from request
        host = None
        for line in request_data.split(b"\r\n"):
            if line.lower().startswith(b"host:"):
                host = line.split(b":", 1)[1].strip().decode()
                break

        if not host:
            print("[!] No Host header found.")
            client_socket.close()
            return
        print(f"[+] Forwarding to: {host}")

        # Connect to remote server
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.connect((host, 80))  # HTTP only for now

        # Forward request
        remote_socket.sendall(request_data)

        while True:
            data = remote_socket.recv(BUFFER_SIZE)
            if not data:
                break
            client_socket.sendall(data)

        remote_socket.close()
        client_socket.close()

    except Exception as e:
        print(f"[!] Error: {e}")
        client_socket.close()


def start_proxy_server(listen_port=8080):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", listen_port))
    server.listen(100)

    print(f"[+] Proxy server listening on port {listen_port}...")

    while True:
        client_socket, addr = server.accept()
        print(f"[+] Connection from {addr}")
        thread = threading.Thread(target=handle_client, args=(client_socket,))
        thread.start()


if __name__ == "__main__":
    start_proxy_server()
