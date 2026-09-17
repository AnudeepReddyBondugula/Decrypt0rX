import socket
import threading

BUFFER_SIZE = 8192


def handle_client(client_socket):
    request_line = client_socket.recv(BUFFER_SIZE).decode(errors="ignore")
    print(f"[+] Request: {request_line.strip()}")

    if not request_line.startswith("CONNECT"):
        client_socket.send(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
        client_socket.close()
        return

    # Parse the host and port
    try:
        target_host_port = request_line.split()[1]
        target_host, target_port = target_host_port.split(":")
        target_port = int(target_port)
    except Exception as e:
        print(f"[-] Failed to parse CONNECT line: {e}")
        client_socket.close()
        return

    # Connect to remote server
    try:
        server_socket = socket.create_connection((target_host, target_port))
        client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    except Exception as e:
        print(f"[-] Failed to connect to target: {e}")
        client_socket.send(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        client_socket.close()
        return

    # Relay data
    def relay(src, dst):
        try:
            while True:
                data = src.recv(BUFFER_SIZE)
                if not data:
                    break
                dst.sendall(data)
        except:
            pass
        finally:
            src.close()
            dst.close()

    # Bidirectional tunnel
    threading.Thread(target=relay, args=(client_socket, server_socket)).start()
    threading.Thread(target=relay, args=(server_socket, client_socket)).start()


def start_proxy(host="0.0.0.0", port=8080):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)
    print(f"[+] HTTPS Proxy listening on {host}:{port}")

    while True:
        client_socket, addr = server.accept()
        print(f"[+] Accepted connection from {addr}")
        threading.Thread(target=handle_client, args=(client_socket,)).start()


if __name__ == "__main__":
    start_proxy()
