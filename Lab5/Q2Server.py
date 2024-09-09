import socket
import hashlib

def compute_hash(data):
    """Compute and return the hash of the given data."""
    hash_object = hashlib.sha256()
    hash_object.update(data)
    return hash_object.hexdigest()

def server_program():
    """Server-side program to receive data, compute hash, and send hash back."""
    host = 'localhost'
    port = 12345

    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"Server listening on {host}:{port}...")

    conn, addr = server_socket.accept()
    print(f"Connection from {addr}")

    data = conn.recv(1024)
    if not data:
        print("No data received.")
        conn.close()
        return

    data_hash = compute_hash(data)

    conn.sendall(data_hash.encode())

    print(f"Data received: {data.decode()}")
    print(f"Hash sent: {data_hash}")

    conn.close()

if __name__ == '__main__':
    server_program()
