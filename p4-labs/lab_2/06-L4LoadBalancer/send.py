import argparse
import threading
import socket
import random
import time


def parse_args():
    parser = argparse.ArgumentParser(description='Establish multiple TCP connections to a given server.')
    parser.add_argument('--host', type=str, default='10.0.1.2', help='the hostname or IP address of the server')
    parser.add_argument('--port', type=int, default=3000, help='the port number of the server')
    parser.add_argument('--max-connections', type=int, default=10, help='the maximum number of connections to establish')
    parser.add_argument('--connection-timeout', type=float, default=5.0, help='the timeout for establishing a connection (in seconds)')
    parser.add_argument('--runtime', type=float, default=30.0, help='the total runtime of the program (in seconds)')
    parser.add_argument('--num-threads', type=int, default=1, help='the number of connection threads to spawn')
    return parser.parse_args()


def connect(host, port, timeout):
    """Establish a TCP connection to the server."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        print(f"Connection established: {s.getsockname()} -> {s.getpeername()}")
        return s
    except socket.error as e:
        print(f"Connection failed: {e}")
        return None


def disconnect(s):
    """Close the TCP connection to the server."""
    if s:
        print(f"Closing connection: {s.getsockname()} -> {s.getpeername()}")
        s.close()


def connection_thread(host, port, max_connections, timeout, runtime, stop_event):
    """Thread that establishes and destroys connections to the server."""
    connections = []
    num_initial_connections = random.randint(1, max_connections)
    for i in range(num_initial_connections):
        s = connect(host, port, timeout)
        if s:
            connections.append(s)
    print(f"{num_initial_connections} initial connections established.")

    start_time = time.monotonic()
    while not stop_event.is_set() and time.monotonic() < start_time + runtime:
        # Create new connections randomly
        if len(connections) < max_connections:
            num_new_connections = random.randint(1, max_connections - len(connections))
            for i in range(num_new_connections):
                s = connect(host, port, timeout)
                if s:
                    connections.append(s)

        time.sleep(random.uniform(2.0, 5.0))

        # Destroy connections randomly
        if len(connections) > 0:
            num_to_remove = random.randint(1, min(3, len(connections)))
            for i in range(num_to_remove):
                s = random.choice(connections)
                connections.remove(s)
                disconnect(s)

        # Sleep for a random period of time
        time.sleep(random.uniform(0.1, 2.0))

    # Close all remaining connections
    for s in connections:
        disconnect(s)

def main():
    # Parse command line arguments
    args = parse_args()

    # Start the connection threads
    threads = []
    stop_event = threading.Event()
    for i in range(args.num_threads):
        t = threading.Thread(target=connection_thread,
                             args=(args.host, args.port, args.max_connections, args.connection_timeout, args.runtime, stop_event))
        t.start()
        threads.append(t)

    # Wait for the program to run for a certain period of time
    try:
        time.sleep(args.runtime)
    except KeyboardInterrupt:
        print("Keyboard interrupt received. Stopping...")

    # Stop the connection threads
    stop_event.set()
    for t in threads:
        t.join()


if __name__ == '__main__':
    main()