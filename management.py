import socket
import time
import threading
from typing import NoReturn
import schedule

MONITORING_SERVICES = {
    'service1': {'ip': '192.168.1.10', 'port': 65432},
    'service2': {'ip': '192.168.1.11', 'port': 65433},
    
}

# Configuration for DNS checks
dns_server = "8.8.8.8"  # Google's public DNS server
dns_queries = [
    ('google.com', 'A'),        # IPv4 Address
    ('google.com', 'MX'),       # Mail Exchange
    ('google.com', 'AAAA'),     # IPv6 Address
    ('google.com', 'CNAME'),    # Canonical Name
    ('yahoo.com', 'A'),         # IPv4 Address
]

# Class for the client that connects to the server and sends commands
class PingControlClient:
    """
    This class represents a client that connects to a network server to send
    commands for controlling a ping task.
    """

    def __init__(self, host: str = '127.0.0.1', port: int = 65432) -> NoReturn:
        self.host: str = host # The server's host address
        self.port: int = port # The server's port number

    def send_command(self, command: str) -> NoReturn:
        """
        Connects to the server, sends a command, and prints the server's response.

        Parameters:
        - command (str): The command to send to the server ('PAUSE', 'RESUME', 'SHUTDOWN')
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            s.sendall(command.encode('ascii'))
            response = s.recv(1024)
            print(f"Server response: {response.decode('ascii')}")

    def start(self) -> NoReturn:
        """
        Starts the client interface, prompting the user for commands to send to the server.
        """

        valid_actions = ["PAUSE", "RESUME", "SHUTDOWN"]
        valid_targets = ["HTTP", "PING", "HTTPS", "DNS", "NTP", "TCP", "UDP"]
        while True:
            action = input("Enter action (PAUSE, RESUME, SHUTDOWN, or EXIT to quit): ").upper()
            if action == "EXIT":
                print("Exiting client.")
                break
            elif action in valid_actions:
                targets_input = input(f"Enter target(s) ({', '.join(valid_targets)}), separated by space, or ALL for both: ").upper()
                targets = targets_input.split() if targets_input != "ALL" else valid_targets
                # Validate targets
                if all(target in valid_targets for target in targets):
                    full_command = f"{action} {' '.join(targets)}"
                    self.send_command(full_command)
                else:
                    print(f"Invalid target(s). Valid targets are: {', '.join(valid_targets)}")
            else:
                print(f"Invalid action. Please enter one of {', '.join(valid_actions)}, or EXIT.")

if __name__ == "__main__":
    client = PingControlClient()
    client.start()