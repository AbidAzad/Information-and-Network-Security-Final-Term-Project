import socket
import threading
import random
import time
from base64 import b64encode, b64decode


# Server configuration
HOST = '192.168.1.31'
PORT = 55555

# Lists to store connected clients, their usernames
clients = []
usernames = []

# Create a socket for the server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))

public_keys_dict = {}

RECIVINGIVs = False

if(RECIVINGIVs):
    public_ivs_dict = {}
def broadcast(message, sender, publicKey=False):
    """Send a message to all clients except the sender."""
    for client in clients:
        try:
            if(not publicKey):
                client.send(f"[{usernames[clients.index(sender)]}] ".encode('utf-8') + message)
            else:
                client.send(message)
        except:
            # Remove the client if unable to send a message
            handle_disconnect(client)


def handle_disconnect(client):
    """Handle client disconnection."""
    index = clients.index(client)
    client.close()
    username = usernames[index]
    broadcast(f"{username} has left the chat.".encode('utf-8'), client)  # Call broadcast directly here
    usernames.remove(username)
    clients.remove(client)
    
def broadcast_public_keys(client):
    """Send public keys to the newly joined client."""
    for username, public_key in public_keys_dict.items():
        key_message = f"Public key of {username}: {public_key}"
        time.sleep(0.2)
        client.send(key_message.encode('utf-8'))

def broadcast_public_IVs(client):
    """Send public keys to the newly joined client."""
    for username, public_iv in public_ivs_dict.items():
        key_message = f"Public IV of {username}: {public_iv}"
        time.sleep(0.2)
        client.send(key_message.encode('utf-8'))

def handle_client(client, username):
    """Handle individual client connections."""
    try:
        # Broadcast the new user joining the chat
        broadcast(f"{username} has joined the chat.".encode('utf-8'), client)
        current_users = ', '.join(user for user in usernames if user != username)
        client.send(f"Other users in the Room: {current_users}".encode('utf-8'))
        time.sleep(0.1)
        broadcast_public_keys(client)
        if(RECIVINGIVs):
            broadcast_public_IVs(client)

        # Broadcast the public key of the new user to all clients
        public_key_message = client.recv(1024).decode('utf-8')
        if public_key_message.startswith("Public key: "):
            public_key = int(public_key_message[12:])
            public_keys_dict[username] = public_key
            broadcast(f"Public key of {username}: {public_key}".encode('utf-8'), client, True)

        else:
            print("Invalid public key format.")
            handle_disconnect(client)
        
        if(RECIVINGIVs):
            time.sleep(0.1)
            public_iv_message = client.recv(1024).decode('utf-8');
            if public_iv_message.startswith("Public IV: "):
                public_iv = b64decode(public_iv_message[11:])
                public_ivs_dict[username] = public_iv_message
                broadcast(f"Public IV of {username}: {public_iv}".encode('utf-8'), client, True)

            else:
                print("Invalid public key format.")
                handle_disconnect(client)

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
                        broadcast(cleaned_message.encode('utf-8'), client)
                        target_client.send(f"./decrypt {username} {cleaned_message}".encode('utf-8'))
                    else:
                        print(f"User not found.")
                else:
                    print("Invalid private message format.")
            
            elif message.startswith('./sendLFSRkey'):
                # Extract the target username and the private message from the command
                parts = message.split(' ', 4)
                if len(parts) == 5:
                    target_username = parts[1]

                    # Find the target client based on the username
                    target_client = next((c for c, u in zip(clients, usernames) if u == target_username), None)

                    # Send the private message to the target user
                    if target_client:
                        target_client.send(f"{message} {username}".encode('utf-8'))
                        response = f'./success {target_username}'
                    else:
                        print(f"User not found.")
                        response = f'./fail {target_username}'

                    # Send the response to the client initiating the command
                    sender_index = clients.index(client)
                    sender_username = usernames[sender_index]
                    sender_client = clients[sender_index]
                    time.sleep(0.1)
                    sender_client.send(response.encode('utf-8'))

                else:
                    print("Invalid private message format.")
                    time.sleep(0.1)
                    client.send(f'./fail {target_username}'.encode('utf-8'))


            else:
                # Broadcast the message to all clients
                broadcast(message.encode('utf-8'), client)

    except (socket.error, ConnectionResetError):
        # Handle client disconnection
        handle_disconnect(client)



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
