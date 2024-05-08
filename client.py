import socket

IP = socket.gethostname()
PORT = 1234

def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((IP, PORT))

    message = "Hello, server!"

    client_socket.send(message.encode())

    data = client_socket.recv(1024)
    print(f"Received from server: {data.decode()}")

    client_socket.close()

if __name__ == "__main__":
    main()