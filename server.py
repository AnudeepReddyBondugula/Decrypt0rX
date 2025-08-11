import socket
import threading
import ipaddress
import fqdn
import time

from exceptions.validation_exceptions import *

import logging
import logging.config

from logging_config import LOGGING_CONFIG

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger(__name__)


class MITM_Server:
    BUFFER_SIZE = 8192
    connection_counter = 0

    def __init__(self, hostname="0.0.0.0", port=8080, buffer_size=8192, backlog=10):
        self.hostname = hostname
        self.port = port
        self.buffer_size = buffer_size
        self.backlog = backlog

    def start(self):
        logger.debug("In MITM_Server.start() function...")

        logger.info("Starting the MITM Server...")

        try:
            logger.debug("Creating TCP socket: AF_INET, SOCK_STREAM")
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            logger.debug("Setting socket option: SO_REUSEADDR = 1")
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            logger.debug(
                "Created a TCP server socket AF_INET (IPV4) SOCK_STREAM (TCP), SO_REUSEADDR = 1"
            )

            logger.debug(f"Trying to bind to {self.hostname} : {self.port}")
            self.server.bind((self.hostname, self.port))

            logger.debug(f"Trying to listen for {self.backlog}")
            self.server.listen(self.backlog)

            logger.info(f"✅ HTTPS Proxy listening on {self.hostname}:{self.port}")
        except Exception:
            logger.error(
                "❌ Unknown Error occured during creation of the Server socket",
                exc_info=True,
            )
            self.server.close()
            logger.info("🛑 Shutting down the server...")
            return

        try:
            while True:
                client_socket, addr = self.server.accept()
                logger.info(f"[+] Accepted connection from {addr}")
                logger.debug(
                    f"Creating & Starting a new thread for this client : {addr}"
                )
                threading.Thread(
                    target=self.handle_client,
                    args=(client_socket,),
                    name=f"ClientConnectionHandler-{self.connection_counter}",
                ).start()
                self.connection_counter += 1

        except KeyboardInterrupt:
            logger.warning("Keyboard Interruption occured...")

        except Exception:
            logger.error("❌ Unknown Error at Starting the Server", exc_info=True)

        finally:
            self.server.close()
            logger.info("🛑 Shutting down the server...")

    def handle_client(self, client_socket):
        logger.debug(f"In handle client function {client_socket}")

        try:
            request_line = client_socket.recv(self.BUFFER_SIZE).decode()
            if not request_line:
                logger.warning("No data received, Closing connection...")
                return

            logger.info(f"Request: {request_line.strip()}")
            if not request_line.startswith("CONNECT"):
                logger.warning("Sending: HTTP/1.1 405 Method Not Allowed")
                client_socket.send(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                return

            # Parse the host and port
            logger.debug("Trying to parse hostname and port from Request line")
            try:
                target_host_port = request_line.split()[1]
                target_host, target_port = target_host_port.split(":")
                target_port = int(target_port)

                try:
                    _ = ipaddress.ip_address(target_host)
                except ValueError:
                    logger.debug("Trying to check for valid domain")
                    if not fqdn.FQDN(target_host).is_valid:
                        logger.debug("Invalid host or port number")
                        raise InvalidConnectRequest("Invalid host or port number")

                logger.info(f"Target host: {target_host} port : {target_port}")

            except Exception as e:
                logger.error(f"Failed to parse CONNECT line: {e}", exc_info=True)
                client_socket.send(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                return

            # Connect to remote server
            try:
                logger.debug(
                    f"Trying to connect to the remote server {target_host} on {target_port}"
                )
                server_socket = socket.create_connection((target_host, target_port))
                logger.debug("HTTP/1.1 200 Connection Established")
                client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            except Exception as e:
                logger.error(f"❌ Failed to connect to target: {e}")
                client_socket.send(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                return

            # Bidirectional tunnel
            #! There is a bug here, we are creating the threads but not waiting for them to complete which is triggering the finally block which is closing the client_socket, temporarily I have added a sleep of 10 seconds but need a permanent solution
            logger.debug("Creating threads")
            threading.Thread(
                target=self.relay, args=(client_socket, server_socket)
            ).start()
            threading.Thread(
                target=self.relay, args=(server_socket, client_socket)
            ).start()

        except Exception:
            client_socket.send(b"HTTP/1.1 500 Internal Server Error\r\n\r\n")
            logger.error(f"Unknown Error :(")

        finally:
            logger.debug("Closing Client socket")
            time.sleep(10)
            client_socket.close()

    # Relay data
    def relay(self, src, dst):
        try:
            while True:
                data = src.recv(self.BUFFER_SIZE)
                if not data:
                    break
                dst.sendall(data)
        except:
            pass
        finally:
            src.close()
            dst.close()


MITM_Server().start()
