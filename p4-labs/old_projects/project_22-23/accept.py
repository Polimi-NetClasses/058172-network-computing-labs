import socket
import threading
import argparse

def handle_client(conn, addr):
    """
    Thread function to handle each client connection
    """
    print(f"New client connected: {addr}")
    
    while True:
        data = conn.recv(args.buffer_size)
        if not data:
            break
        # process the data here
        
    conn.close()
    print(f"Client disconnected: {addr}")

    # remove this thread from the client threads list
    client_threads.remove(threading.current_thread())
    print(f"Active connections: {len(client_threads)}")


if __name__ == '__main__':
    # parse command-line arguments
    parser = argparse.ArgumentParser(description='Multithreaded TCP server')
    parser.add_argument('--host', metavar='HOST', type=str, default='0.0.0.0',
                        help='the host address to bind to (default: 127.0.0.1)')
    parser.add_argument('--port', metavar='PORT', type=int, default=8000,
                        help='the port to listen on (default: 8000)')
    parser.add_argument('--buffer-size', metavar='BUFFER_SIZE', type=int, default=1024,
                        help='the buffer size for receiving data (default: 1024)')
    parser.add_argument('--max-threads', metavar='MAX_THREADS', type=int, default=100,
                        help='the maximum number of threads to create (default: 10)')
    args = parser.parse_args()

    # create a TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # bind the socket to a specific address and port
    server_socket.bind((args.host, args.port))

    # listen for incoming connections
    server_socket.listen()

    # create a list to store the client threads
    client_threads = []

    while True:
        # check if the maximum number of threads has been reached
        if len(client_threads) >= args.max_threads:
            continue
        
        print("Accepting new connection...")
        # accept a new connection
        conn, addr = server_socket.accept()
        
        # create a new thread to handle the connection
        client_thread = threading.Thread(target=handle_client, args=(conn, addr))
        
        # add the new thread to the client threads list
        client_threads.append(client_thread)
        
        # start the new thread
        client_thread.start()
        
        # print the number of active connections
        print(f"Active connections: {len(client_threads)}")