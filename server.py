import socket
import threading

# Server configuration
HOST = '192.168.1.31'
PORT = 55555

# Lists to store connected clients and their usernames
clients = []
usernames = []

# Create a socket for the server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))


def broadcast(message, sender):
    """Send a message to all clients except the sender."""
    for client in clients:
        if client != sender:
            try:
                client.send(f"[{usernames[clients.index(sender)]}] ".encode('utf-8') + message)
            except:
                # Remove the client if unable to send a message
                index = clients.index(client)
                clients.remove(client)
                client.close()
                username = usernames[index]
                broadcast(f"{username} has left the chat.".encode('utf-8'), server)
                usernames.remove(username)


def handle_client(client):
    """Handle individual client connections."""
    while True:
        try:
            message = client.recv(1024)
            broadcast(message, client)
        except:
            # Remove the client if an error occurs (e.g., client disconnects)
            index = clients.index(client)
            clients.remove(client)
            client.close()
            username = usernames[index]
            broadcast(f"{username} has left the chat.".encode('utf-8'), server)
            usernames.remove(username)
            break


def start_server():
    """Start the chat server."""
    server.listen()
    print(f"Server is listening on {HOST}:{PORT}")

    while True:
        # Accept a new client connection
        client, address = server.accept()
        print(f"New connection from {address}")

        # Prompt the client for a username
        client.send("Enter your username: ".encode('utf-8'))
        username = client.recv(1024).decode('utf-8')

        # Add the new client and username to the lists
        clients.append(client)
        usernames.append(username)

        # Broadcast the new user joining the chat
        broadcast(f"{username} has joined the chat.".encode('utf-8'), client)

        # Start a new thread to handle the client
        thread = threading.Thread(target=handle_client, args=(client,))
        thread.start()


if __name__ == "__main__":
    start_server()