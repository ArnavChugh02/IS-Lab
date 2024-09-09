import socket
import hashlib

def compute_hash(data):
    """Compute and return the hash of the given data."""
    hash_object = hashlib.sha256()  
    hash_object.update(data)
    return hash_object.hexdigest()

def client_program():
    """Client-side program to send data, receive hash, and verify integrity."""
    host = 'localhost'
    port = 12345

    client_socket = socket.socket()
    client_socket.connect((host, port))

    data = b"Secure Data Transmission"
    print(f"Data sent: {data.decode()}")

    client_socket.sendall(data)

    server_hash = client_socket.recv(1024).decode()
    print(f"Hash received from server: {server_hash}")

    computed_hash = compute_hash(data)
    print(f"Hash computed locally: {computed_hash}")

    if server_hash == computed_hash:
        print("Data integrity verified.")
    else:
        print("Data integrity verification failed!")

    client_socket.close()

if __name__ == '__main__':
    client_program()
