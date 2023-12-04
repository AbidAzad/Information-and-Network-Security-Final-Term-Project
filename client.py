import socket
import threading

# Client configuration
HOST = '192.168.1.31'
PORT = 55555

# Create a socket for the client
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

def receive_messages():
    """Receive and display messages from the server."""
    while True:
        try:
            message = client.recv(1024).decode('utf-8')
            print(message)
        except:
            print("An error occurred while receiving messages.")
            client.close()
            break

# Start a thread to receive messages
receive_thread = threading.Thread(target=receive_messages)
receive_thread.start()

# Send messages to the server
while True:
    message = input()
    client.send(message.encode('utf-8'))
