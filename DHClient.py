import socket
import threading
import random
from tkinter import Tk, Scrollbar, Listbox, Entry, Button, StringVar, DISABLED, NORMAL, Toplevel, Label

ENCRYPTIONTYPE = 'STREAMCIPHER'

if(ENCRYPTIONTYPE == 'STREAMCIPHER'):
    from streamCipher import *

# Client configuration
HOST = '192.168.1.31'
PORT = 55555

# Agreed Upon Values
primeNumber = 102188617217178804476387977160129334431745945009730065519337094992129677228373
primitiveRoot = 2

# Create a socket for the client
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))


class UsernameGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Enter Username")

        # Label and entry widget for entering the username
        self.username_label = Label(root, text="Enter your username:")
        self.username_label.pack(pady=10)
        self.username_entry = Entry(root, width=30)
        self.username_entry.pack(pady=10)
        
        # Button to submit the username
        submit_button = Button(root, text="Submit", command=self.submit_username)
        submit_button.pack(pady=10)


    def submit_username(self):
        username = self.username_entry.get()
        if username:
            self.root.destroy()  # Close the username entry GUI
            # Start the chat GUI with the entered username
            chat_root = Tk()
            chat_gui = ChatGUI(chat_root, username)
            chat_root.mainloop()
        else:
            # Display an error message if the username is empty
            error_label = Label(self.root, text="Please enter a valid username.")
            error_label.pack(pady=5)


class ChatGUI:
    def __init__(self, root, username):
        self.root = root
        self.root.title("Chat Application")

        # Create a listbox to display messages
        self.message_listbox = Listbox(root, height=20, width=50, selectbackground="white", exportselection=False)
        self.message_listbox.pack(padx=10, pady=10)

        # Create a scrollbar for the listbox
        scrollbar = Scrollbar(root)
        scrollbar.pack(side="right", fill="y")

        # Attach the listbox to the scrollbar
        self.message_listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.message_listbox.yview)

        # Create an entry widget for typing messages
        self.message_entry = Entry(root, width=50)
        self.message_entry.pack(padx=10, pady=10)

        # Create a Send button to send messages
        send_button = Button(root, text="Send", command=self.send_message)
        send_button.pack(pady=10)
        
        # Generate a secret integer for the client
        self.secret_integer = random.randint(2, primeNumber - 2)
        message = f'Your secret integer:{self.secret_integer}'
        self.message_listbox.config(state=NORMAL)  # Enable listbox for modification
        self.message_listbox.insert('end', message)
        self.message_listbox.config(state=DISABLED)  # Disable listbox after modification
        self.public_keys = {}

                
        # Start a thread to receive messages
        receive_thread = threading.Thread(target=self.receive_messages)
        receive_thread.start()
        
        # Send the username to the server
        client.send(username.encode('utf-8'))
        client.send(f"Public key: {pow(primitiveRoot, self.secret_integer, primeNumber)}".encode('utf-8'))
        
        
        
    def send_message(self):
        message = self.message_entry.get()
        self.message_entry.delete(0, 'end')

        # Check if the message is a special command to send a private message
        if message.startswith('./checkSharedKey'):
            self.check_shared_key(message)
        elif message.startswith('./sendToUser'):
            self.send_private_message(message)
        else:
            client.send(message.encode('utf-8'))

    def receive_messages(self):
        """Receive and display messages from the server."""
        while True:
            try:
                message = client.recv(1024).decode('utf-8')
                if message.startswith("Public key of "):
                    self.handle_public_key(message)
                elif message.startswith("./decrypt"):
                    parts = message.split(' ', 2)
                    target_username = parts[1]
                    private_message = parts[2]
                    
                    message = f'The encrypted message was sent for you by {target_username}.'
                    # Handle regular messages
                    self.message_listbox.config(state=NORMAL)  # Enable listbox for modification
                    self.message_listbox.insert('end', message)
                    self.message_listbox.config(state=DISABLED)  # Disable listbox after modification
                    shared_secret_key = pow(self.public_keys[target_username] , self.secret_integer, primeNumber)
                    print(bin(shared_secret_key)[2:])
                    message = f'Decrypted Message using associated Key: {decrypt(private_message, str(bin(shared_secret_key)[2:]))}'
                    self.message_listbox.config(state=NORMAL)  # Enable listbox for modification
                    self.message_listbox.insert('end', message)
                    self.message_listbox.config(state=DISABLED)  # Disable listbox after modification
                else:
                    # Handle regular messages
                    self.message_listbox.config(state=NORMAL)  # Enable listbox for modification
                    self.message_listbox.insert('end', message)
                    self.message_listbox.config(state=DISABLED)  # Disable listbox after modification
            except Exception as e:
                print(f"An error occurred while receiving messages: {e}")
                client.close()
                break
    def handle_public_key(self, message):
            # Parse the public key message
            parts = message.split(": ")
            if len(parts) == 2:
                username = parts[0][14:]
                public_key = int(parts[1])
                
                # Store the public key in the dictionary
                self.public_keys[username] = public_key

                # Calculate the shared secret key
                shared_secret_key = pow(public_key, self.secret_integer, primeNumber)

                # Store the shared secret key and associated username for later use
                # You may want to store this information securely in your application
                # For simplicity, we'll print it here
                print(f"Shared secret key with {username}: {shared_secret_key}")
    
    def check_shared_key(self, message):
        """Check and output the shared key for a specific user."""
        parts = message.split(' ')
        if len(parts) == 2:
            target_username = parts[1]

            # Check if we have the public key for the target user
            if target_username in self.public_keys:
                # Calculate the shared secret key
                shared_secret_key = pow(self.public_keys[target_username], self.secret_integer, primeNumber)

                # Output the
                # shared key for the specific user
                print(f"Shared secret key with {target_username}: {shared_secret_key}")
            else:
                print(f"Public key for {target_username} not available.")
        
                
    def send_private_message(self, message):
        """Send a private message to a specific user."""
        parts = message.split(' ', 2)
        target_username = parts[1]
        message = parts[2]
        shared_secret_key = pow(self.public_keys[target_username], self.secret_integer, primeNumber)
        print(bin(shared_secret_key)[2:])
        message = f'./sendToUser {target_username} {encrypt(message, str(bin(shared_secret_key)[2:]))}'
        client.send(message.encode('utf-8'))


if __name__ == "__main__":
    # Start with the username entry GUI
    username_root = Tk()
    username_gui = UsernameGUI(username_root)
    username_root.mainloop()
