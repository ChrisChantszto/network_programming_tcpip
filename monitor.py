import socket
import threading
import time
from typing import NoReturn
import os
import platform
import subprocess
import string
import requests
import ntplib
import dns.resolver
from time import ctime
import dns.exception
from socket import gaierror
from management import dns_server, dns_queries

# Placeholder function for the ping oepration
def ping(host="8.8.8.8") -> NoReturn:
    """
    Simulates a ping operation. In a real application, this function would
    execute a network ping to a specified address.
    """

    # Cross-platform compatibility (different ping command arguments)
    param = '-n' if platform.system().lower() == 'windows' else '-c'

    # Building the command. Ex: "ping -c 1 google.com"
    command = ['ping', param, '1', host]

    try:
        # Pinging
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
        print(output)
    except subprocess.CalledProcessError as e:
        # If the ping command fails
        print(f'Ping request failed: {e.output}')

def check_server_http(url="http://www.google.com") -> NoReturn:
    """
    Check if an HTTP server is up by making a request to the provided URL.

    This function attempts to connect to a web server using the specified URL.
    It returns a tuple containing a boolean indicating whether the server is up,
    and the HTTP status code returned by the server.

    :param url: URL of the server (including http://)
    :return: Tuple (True/False, status code)
             True if server is up (status code < 400), False otherwise
    """
    try:
        # Making a GET request to the server
        response: requests.Response = requests.get(url)

        # The HTTP status code is a number that indicates the outcome of the request.
        # Here, we consider status codes less than 400 as successful,
        # meaning the server is up and reachable.
        # Common successful status codes are 200 (OK), 301 (Moved Permanently), etc.
        is_up: bool = response.status_code < 400

        if is_up:
            print(f"Server at {url} is up. Status Code: {response.status_code}")
        else:
            print(f"Server at {url} might be down. Status Code: {response.status_code}")

    except requests.RequestException as e:
        # This block catches any exception that might occur during the request.
        print(f"Failed to reach the server at {url}. Exception: {e}")

def check_server_https(url="https://oregonstate.edu/", timeout: int = 5) -> NoReturn:
    """
    Check if an HTTPS server is up by making a request to the provided URL.

    This function attempts to connect to a web server using the specified URL with HTTPS.
    It returns a tuple containing a boolean indicating whether the server is up,
    the HTTP status code returned by the server, and a descriptive message.

    :param url: URL of the server (including https://)
    :param timeout: Timeout for the request in seconds. Default is 5 seconds.
    :return: Tuple (True/False for server status, status code, description)
    """
    try:
        # Setting custom headers for the request. Here, 'User-Agent' is set to mimic a web browser.
        headers: dict = {'User-Agent': 'Mozilla/5.0'}

        # Making a GET request to the server with the specified URL and timeout.
        # The timeout ensures that the request does not hang indefinitely.
        response: requests.Response = requests.get(url, headers=headers, timeout=timeout)

        # Checking if the status code is less than 400. Status codes in the 200-399 range generally indicate success.
        is_up: bool = response.status_code < 400

        # Returning a tuple: (server status, status code, descriptive message)
        if is_up:
            print(f"(HTTPS) Server at {url} is up. Status Code: {response.status_code}")
        else:
            print(f"(HTTPS) Server at {url} might be down. Status Code: {response.status_code}")

    except requests.ConnectionError:
        # This exception is raised for network-related errors, like DNS failure or refused connection.
        return False, None, "Connection error"

    except requests.Timeout:
        # This exception is raised if the server does not send any data in the allotted time (specified by timeout).
        return False, None, "Timeout occurred"

    except requests.RequestException as e:
        # A catch-all exception for any error not covered by the specific exceptions above.
        # 'e' contains the details of the exception.
        return False, None, f"Error during request: {e}"

def check_dns_server_status(server, query, record_type) -> (bool, str):
    """
    Check if a DNS server is up and return the DNS query results for a specified domain and record type.

    :param server: DNS server name or IP address
    :param query: Domain name to query
    :param record_type: Type of DNS record (e.g., 'A', 'AAAA', 'MX', 'CNAME')
    :return: Tuple (status, query_results)
    """
    for query, record_type in dns_queries:
        try:
            # Set the DNS resolver to use the specified server
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [socket.gethostbyname(server)]

            # Perform a DNS query for the specified domain and record type
            query_results = resolver.resolve(query, record_type)
            results = [str(rdata) for rdata in query_results]

            print(f"DNS status for {query} {record_type}: {results}")
            return True, results

        except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.resolver.NoAnswer, socket.gaierror) as e:
            # Return False if there's an exception (server down, query failed, or record type not found)
            print(f"Failed DNS query for {query} {record_type}: {e}")
            return False, str(e)
        
def check_ntp_server(server="pool.ntp.org"):
    """
    Checks if an NTP server is up and returns its status and time.

    Args:
    server (str): The hostname or IP address of the NTP server to check.

    Returns:
    Tuple[bool, Optional[str]]: A tuple containing a boolean indicating the server status
                                 (True if up, False if down) and the current time as a string
                                 if the server is up, or None if it's down.
    """
    # Create an NTP client instance
    client = ntplib.NTPClient()

    try:
        # Request time from the NTP server
        # 'version=3' specifies the NTP version to use for the request
        response = client.request(server, version=3)

        # If request is successful, return True and the server time
        # 'ctime' converts the time in seconds since the epoch to a readable format
        print(f"NTP status for {server} : {response.tx_time}")
        return True, ctime(response.tx_time)
    except (ntplib.NTPException, gaierror):
        # If an exception occurs (server is down or unreachable), return False and None
        return False, None
    
def check_tcp_port(ip_address="google.com", port=80) -> (bool, str):
    """
    Checks the status of a specific TCP port on a given IP address.

    Args:
    ip_address (str): The IP address of the target server.
    port (int): The TCP port number to check.

    Returns:
    tuple: A tuple containing a boolean and a string.
           The boolean is True if the port is open, False otherwise.
           The string provides a description of the port status.

    Description:
    This function attempts to establish a TCP connection to the specified port on the given IP address.
    If the connection is successful, it means the port is open; otherwise, the port is considered closed or unreachable.
    """

    try:
        # Create a socket object using the AF_INET address family (IPv4) and SOCK_STREAM socket type (TCP).
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Set a timeout for the socket to avoid waiting indefinitely. Here, 3 seconds is used as a reasonable timeout duration.
            s.settimeout(3)

            # Attempt to connect to the specified IP address and port.
            # If the connection is successful, the port is open.
            s.connect((ip_address, port))
            print(f"TCP status for {port} on {ip_address} is online")
            return True, f"Port {port} on {ip_address} is open."

    except socket.timeout:
        # If a timeout occurs, it means the connection attempt took too long, implying the port might be filtered or the server is slow to respond.
        print(f"TCP status for {port} on {ip_address} timed out")
        return False, f"Port {port} on {ip_address} timed out."

    except socket.error:
        # If a socket error occurs, it generally means the port is closed or not reachable.
        print(f"TCP status for {port} on {ip_address} is not online")
        return False, f"Port {port} on {ip_address} is closed or not reachable."

    except Exception as e:
        # Catch any other exceptions and return a general failure message along with the exception raised.
        print(f"Failed to check port {port} on {ip_address} due to an error: {e}")
        return False, f"Failed to check port {port} on {ip_address} due to an error: {e}"

def check_udp_port(ip_address="8.8.8.8", port=53, timeout: int = 3) -> (bool, str):
    """
    Checks the status of a specific UDP port on a given IP address.

    Args:
    ip_address (str): The IP address of the target server.
    port (int): The UDP port number to check.
    timeout (int): The timeout duration in seconds for the socket operation. Default is 3 seconds.

    Returns:
    tuple: A tuple containing a boolean and a string.
           The boolean is True if the port is open (or if the status is uncertain), False if the port is definitely closed.
           The string provides a description of the port status.

    Description:
    This function attempts to send a UDP packet to the specified port on the given IP address.
    Since UDP is a connectionless protocol, the function can't definitively determine if the port is open.
    It can only confirm if the port is closed, typically indicated by an ICMP 'Destination Unreachable' response.
    """

    try:
        # Create a socket object using the AF_INET address family (IPv4) and SOCK_DGRAM socket type (UDP).
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Set a timeout for the socket to avoid waiting indefinitely.
            s.settimeout(timeout)

            # Send a dummy packet to the specified IP address and port.
            # As UDP is connectionless, this does not establish a connection but merely sends the packet.
            s.sendto(b'', (ip_address, port))

            try:
                # Try to receive data from the socket.
                # If an ICMP 'Destination Unreachable' message is received, the port is considered closed.
                s.recvfrom(1024)
                print(f"UDP status for {port} on {ip_address} is online")
                return False, f"Port {port} on {ip_address} is closed."

            except socket.timeout:
                # If a timeout occurs, it's uncertain whether the port is open or closed, as no response is received.
                print(f"UDP status for {port} on {ip_address} is not online")
                return True, f"Port {port} on {ip_address} is open or no response received."

    except Exception as e:
        # Catch any other exceptions and return a general failure message along with the exception raised.
        return False, f"Failed to check UDP port {port} on {ip_address} due to an error: {e}"

class PingTask(threading.Thread):
    """
    This class represents a task that performs a ping operation at regular intervals.
    It runs in a separate thread to allow concurrent execution with the server's
    command handling.
    """
    def __init__(self) -> NoReturn:
        super().__init__()
        self.paused: bool = False # Indicates if the ping task is paused
        self.stopped: bool = False # Indicates if the ping task is stopped
        self.condition: threading.Condition = threading.Condition() # Condition variable for pausing/resuming

    def run(self) -> NoReturn:
        """
        The main logic of the thread, which executes the ping operation at
        one-minute intervals, unless paused or stopped.
        """
        while not self.stopped:
            with self.condition:
                if self.paused:
                    self.condition.wait() # Wait until the task is resumed
                else:
                    ping()
            time.sleep(1) # Wait for one second

    def pause(self) -> NoReturn:
        """Pauses the ping task."""
        self.paused = True
    
    def resume(self) -> NoReturn:
        """Resumes the ping task if it was paused."""
        with self.condition:
            self.paused = False
            self.condition.notify() # Notify the thread to resume

    def stop(self) -> NoReturn:
        """Stops the ping task and the thread."""
        self.stopped = True
        if self.paused:
            self.resume() # Ensure the thread is not waiting to be resumed

class HttpTask(threading.Thread):
    """
    This class represents a task that performs a ping operation at regular intervals.
    It runs in a separate thread to allow concurrent execution with the server's
    command handling.
    """
    def __init__(self) -> NoReturn:
        super().__init__()
        self.paused: bool = False # Indicates if the ping task is paused
        self.stopped: bool = False # Indicates if the ping task is stopped
        self.condition: threading.Condition = threading.Condition() # Condition variable for pausing/resuming

    def run(self) -> NoReturn:
        """
        The main logic of the thread, which executes the ping operation at
        one-minute intervals, unless paused or stopped.
        """
        while not self.stopped:
            with self.condition:
                if self.paused:
                    self.condition.wait() # Wait until the task is resumed
                else:
                    # Call the function to print the result to the console
                    check_server_http()
            time.sleep(6) # Wait for six seconds

    def pause(self) -> NoReturn:
        """Pauses the ping task."""
        self.paused = True
    
    def resume(self) -> NoReturn:
        """Resumes the ping task if it was paused."""
        with self.condition:
            self.paused = False
            self.condition.notify() # Notify the thread to resume

    def stop(self) -> NoReturn:
        """Stops the ping task and the thread."""
        self.stopped = True
        if self.paused:
            self.resume() # Ensure the thread is not waiting to be resumed

class HttpsTask(threading.Thread):
    """
    This class represents a task that performs a ping operation at regular intervals.
    It runs in a separate thread to allow concurrent execution with the server's
    command handling.
    """
    def __init__(self) -> NoReturn:
        super().__init__()
        self.paused: bool = False # Indicates if the ping task is paused
        self.stopped: bool = False # Indicates if the ping task is stopped
        self.condition: threading.Condition = threading.Condition() # Condition variable for pausing/resuming

    def run(self) -> NoReturn:
        """
        The main logic of the thread, which executes the ping operation at
        one-minute intervals, unless paused or stopped.
        """
        while not self.stopped:
            with self.condition:
                if self.paused:
                    self.condition.wait() # Wait until the task is resumed
                else:
                    # Call the function to print the result to the console
                    check_server_https()
            time.sleep(6) # Wait for six seconds

    def pause(self) -> NoReturn:
        """Pauses the ping task."""
        self.paused = True
    
    def resume(self) -> NoReturn:
        """Resumes the ping task if it was paused."""
        with self.condition:
            self.paused = False
            self.condition.notify() # Notify the thread to resume

    def stop(self) -> NoReturn:
        """Stops the ping task and the thread."""
        self.stopped = True
        if self.paused:
            self.resume() # Ensure the thread is not waiting to be resumed

class DnsTask(threading.Thread):
    """
    This class represents a task that performs a ping operation at regular intervals.
    It runs in a separate thread to allow concurrent execution with the server's
    command handling.
    """
    def __init__(self) -> NoReturn:
        super().__init__()
        self.paused: bool = False # Indicates if the ping task is paused
        self.stopped: bool = False # Indicates if the ping task is stopped
        self.condition: threading.Condition = threading.Condition() # Condition variable for pausing/resuming

    def run(self) -> NoReturn:
        """
        The main logic of the thread, which executes the DNS check operation at
        one-minute intervals, unless paused or stopped.
        """
        while not self.stopped:
            with self.condition:
                if self.paused:
                    self.condition.wait() # Wait until the task is resumed
                else:
                    # Loop through each server and query in dns_queries
                    for query, record_type in dns_queries:
                        server = dns_server
                        check_dns_server_status(server, query, record_type)
            time.sleep(6)  # Wait for six seconds

    def pause(self) -> NoReturn:
        """Pauses the ping task."""
        self.paused = True
    
    def resume(self) -> NoReturn:
        """Resumes the ping task if it was paused."""
        with self.condition:
            self.paused = False
            self.condition.notify() # Notify the thread to resume

    def stop(self) -> NoReturn:
        """Stops the ping task and the thread."""
        self.stopped = True
        if self.paused:
            self.resume() # Ensure the thread is not waiting to be resumed

class NtpTask(threading.Thread):
    """
    This class represents a task that performs a ping operation at regular intervals.
    It runs in a separate thread to allow concurrent execution with the server's
    command handling.
    """
    def __init__(self) -> NoReturn:
        super().__init__()
        self.paused: bool = False # Indicates if the ping task is paused
        self.stopped: bool = False # Indicates if the ping task is stopped
        self.condition: threading.Condition = threading.Condition() # Condition variable for pausing/resuming

    def run(self) -> NoReturn:
        """
        The main logic of the thread, which executes the DNS check operation at
        one-minute intervals, unless paused or stopped.
        """
        while not self.stopped:
            with self.condition:
                if self.paused:
                    self.condition.wait() # Wait until the task is resumed
                else:
                    # Loop through each server and query in dns_queries
                    check_ntp_server()
            time.sleep(6)  # Wait for six seconds

    def pause(self) -> NoReturn:
        """Pauses the ping task."""
        self.paused = True
    
    def resume(self) -> NoReturn:
        """Resumes the ping task if it was paused."""
        with self.condition:
            self.paused = False
            self.condition.notify() # Notify the thread to resume

    def stop(self) -> NoReturn:
        """Stops the ping task and the thread."""
        self.stopped = True
        if self.paused:
            self.resume() # Ensure the thread is not waiting to be resumed

class TcpTask(threading.Thread):
    """
    This class represents a task that performs a ping operation at regular intervals.
    It runs in a separate thread to allow concurrent execution with the server's
    command handling.
    """
    def __init__(self) -> NoReturn:
        super().__init__()
        self.paused: bool = False # Indicates if the ping task is paused
        self.stopped: bool = False # Indicates if the ping task is stopped
        self.condition: threading.Condition = threading.Condition() # Condition variable for pausing/resuming

    def run(self) -> NoReturn:
        """
        The main logic of the thread, which executes the DNS check operation at
        one-minute intervals, unless paused or stopped.
        """
        while not self.stopped:
            with self.condition:
                if self.paused:
                    self.condition.wait() # Wait until the task is resumed
                else:
                    # Loop through each server and query in dns_queries
                    check_tcp_port()
            time.sleep(6)  # Wait for six seconds

    def pause(self) -> NoReturn:
        """Pauses the ping task."""
        self.paused = True
    
    def resume(self) -> NoReturn:
        """Resumes the ping task if it was paused."""
        with self.condition:
            self.paused = False
            self.condition.notify() # Notify the thread to resume

    def stop(self) -> NoReturn:
        """Stops the ping task and the thread."""
        self.stopped = True
        if self.paused:
            self.resume() # Ensure the thread is not waiting to be resumed

class UdpTask(threading.Thread):
    """
    This class represents a task that performs a ping operation at regular intervals.
    It runs in a separate thread to allow concurrent execution with the server's
    command handling.
    """
    def __init__(self) -> NoReturn:
        super().__init__()
        self.paused: bool = False # Indicates if the ping task is paused
        self.stopped: bool = False # Indicates if the ping task is stopped
        self.condition: threading.Condition = threading.Condition() # Condition variable for pausing/resuming

    def run(self) -> NoReturn:
        """
        The main logic of the thread, which executes the DNS check operation at
        one-minute intervals, unless paused or stopped.
        """
        while not self.stopped:
            with self.condition:
                if self.paused:
                    self.condition.wait() # Wait until the task is resumed
                else:
                    # Loop through each server and query in dns_queries
                    check_udp_port()
            time.sleep(6)  # Wait for six seconds

    def pause(self) -> NoReturn:
        """Pauses the ping task."""
        self.paused = True
    
    def resume(self) -> NoReturn:
        """Resumes the ping task if it was paused."""
        with self.condition:
            self.paused = False
            self.condition.notify() # Notify the thread to resume

    def stop(self) -> NoReturn:
        """Stops the ping task and the thread."""
        self.stopped = True
        if self.paused:
            self.resume() # Ensure the thread is not waiting to be resumed

# Class for the network server that handles client connections and commands
class Server:
    """
    This class represents a network server that listenss for incoming connections
    and handles client commands to control a ping task
    """
    def __init__(self, host: str = '127.0.0.1', port: int = 65432) -> NoReturn:
        self.host: str = host # Server host address
        self.port: int = port # Server port number
        self.ping_task: PingTask = PingTask() # The ping task managed by the server
        self.http_task: HttpTask = HttpTask()
        self.https_task: HttpsTask = HttpsTask()
        self.dns_task: DnsTask = DnsTask()
        self.ntp_task: NtpTask = NtpTask()
        self.tcp_task: TcpTask = TcpTask()
        self.udp_task: UdpTask = UdpTask()

    def start(self) -> NoReturn:
        """
        Starts the server and the ping task, then listens for incoming connections.
        Processing client commands to control the ping task
        """
        self.ping_task.start()
        self.http_task.start()
        self.https_task.start()
        self.dns_task.start()
        self.ntp_task.start()
        self.tcp_task.start()
        self.udp_task.start()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()
            print(f"Server listening on {self.host}:{self.port}")
            
            while True:
                conn, addr = s.accept()
                with conn:
                    print(f"Connected by {addr}")
                    while True:
                        data: str = conn.recv(1024).decode('ascii').upper()
                        if not data:
                            break

                        command_parts = data.split()

                        if len(command_parts) >= 2:
                            action = command_parts[0]
                            targets = command_parts[1:]

                            if action == 'PAUSE':
                                if 'HTTP' in targets:
                                    self.http_task.pause()
                                if 'PING' in targets:
                                    self.ping_task.pause()
                                if 'HTTPS' in targets:
                                    self.https_task.pasue()
                                if 'DNS' in targets:
                                    self.dns_task.pause()
                                if 'NTP' in targets:
                                    self.ntp_task.pause()
                                if 'TCP' in targets:
                                    self.tcp_task.pause()
                                if 'UDP' in targets:
                                    self.udp_task.pause()
                                conn.sendall(b'Command executed')
                                
                            elif action == 'RESUME':
                                if 'HTTP' in targets:
                                    self.http_task.resume()
                                if 'PING' in targets:
                                    self.ping_task.resume()
                                if 'HTTPS' in targets:
                                    self.https_task.resume()
                                if 'DNS' in targets:
                                    self.dns_task.resume()
                                if 'NTP' in targets:
                                    self.ntp_task.resume()
                                if 'TCP' in targets:
                                    self.tcp_task.resume()
                                if 'UDP' in targets:
                                    self.udp_task.resume()
                                conn.sendall(b'Command executed')
                                
                            elif action == 'SHUTDOWN':
                                self.ping_task.stop()
                                self.http_task.stop()
                                self.https_task.stop()
                                self.dns_task.stop()
                                self.ntp_task.stop()
                                self.tcp_task.stop()
                                self.udp_task.stop()
                                conn.sendall(b'Server shutting down')
                                return
                        
                        else:
                            conn.sendall(b'Invalid command')

if __name__ == "__main__":
    server = Server()
    server.start()