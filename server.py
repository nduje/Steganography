import socket

IP = socket.gethostname()
PORT = 1234

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((IP, PORT))
    server_socket.listen()

    print(f"Server is listening on port {PORT}\n")

    client_socket, client_address = server_socket.accept()

    print(f"Connection from {client_address} has been established.\n")

    data = client_socket.recv(1024)
    print(f"Received from client: {data.decode()}")

    message = "Hello, client!"

    client_socket.send(message.encode())

    server_socket.close()

if __name__ == "__main__":
    main()