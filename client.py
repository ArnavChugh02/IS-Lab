import socket


def client_program():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Server details
    host = '127.0.0.1'
    port = 65432

    client_socket.connect((host, port))

    # Ask user to enter a message
    message = input("Enter the message: ")

    # Ask user what operation they want to perform
    operation = input("Choose an operation (encrypt, decrypt, sign, hash): ")

    if operation == "encrypt" or operation == "sign" or operation == "hash":
        client_socket.sendall(message.encode())

        # Receive the result from the server
        result = client_socket.recv(1024).decode()
        print("Server Response:\n", result)

    elif operation == "decrypt":
        print("Decryption not implemented in client. Server side handles encryption.")

    client_socket.close()


if __name__ == '__main__':
    client_program()
