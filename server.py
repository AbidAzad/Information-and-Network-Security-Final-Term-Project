import socket
import threading

# Agreed Upon Values
primeNumber = 102188617217178804476387977160129334431745945009730065519337094992129677228373
primitiveRoot = 2

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


def handle_client(client, username):
    """Handle individual client connections."""
    try:
        # Broadcast the new user joining the chat
        broadcast(f"{username} has joined the chat.".encode('utf-8'), client)
        current_users = ', '.join(usernames)
        client.send(f"Current users: {current_users}".encode('utf-8'))

        while True:
            message = client.recv(1024).decode('utf-8')

            # Announce all current users to the new client
            
            
            # Check if the message is a special command to send a private message
            if message.startswith('./sendToUser'):
                # Extract the target username and the private message from the command
                parts = message.split(' ', 2)
                if len(parts) == 3:
                    target_username = parts[1]
                    private_message = parts[2]

                    # Find the target client based on the username
                    target_client = next((c for c, u in zip(clients, usernames) if u == target_username), None)

                    # Send the private message to the target user
                    if target_client:
                        # Remove the command and username, leaving only the private message
                        cleaned_message = private_message
                        target_client.send(f"[Private from {username}] ".encode('utf-8') + cleaned_message.encode('utf-8'))
                    else:
                        print(f"User {target_username} not found.")
                else:
                    print("Invalid private message format.")

            else:
                # Broadcast the message to all clients
                broadcast(message.encode('utf-8'), client)

    except:
        # Remove the client if an error occurs (e.g., client disconnects)
        index = clients.index(client)
        clients.remove(client)
        client.close()
        broadcast(f"{username} has left the chat.".encode('utf-8'), server)
        usernames.remove(username)


def start_server():
    """Start the chat server."""
    server.listen()
    print(f"Server is listening on {HOST}:{PORT}")

    while True:
        # Accept a new client connection
        client, address = server.accept()
        print(f"New connection from {address}")

        # Receive the username from the client
        username = client.recv(1024).decode('utf-8')

        # Add the new client and username to the lists
        clients.append(client)
        usernames.append(username)

        # Start a new thread to handle the client
        thread = threading.Thread(target=handle_client, args=(client, username))
        thread.start()


if __name__ == "__main__":
    start_server()