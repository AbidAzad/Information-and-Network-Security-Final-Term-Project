import socket
import threading
from tkinter import Tk, Scrollbar, Listbox, Entry, Button, StringVar, DISABLED, NORMAL, Toplevel, Label

# Client configuration
HOST = '192.168.1.31'
PORT = 55555

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

        # Start a thread to receive messages
        receive_thread = threading.Thread(target=self.receive_messages)
        receive_thread.start()

        # Send the username to the server
        client.send(username.encode('utf-8'))

    def send_message(self):
        message = self.message_entry.get()
        self.message_entry.delete(0, 'end')

        # Check if the message is a special command to send a private message
        if message.startswith('./sendToUser'):
            self.send_private_message(message)
        else:
            client.send(message.encode('utf-8'))

    def receive_messages(self):
        """Receive and display messages from the server."""
        while True:
            try:
                message = client.recv(1024).decode('utf-8')
                self.message_listbox.config(state=NORMAL)  # Enable listbox for modification
                self.message_listbox.insert('end', message)
                self.message_listbox.config(state=DISABLED)  # Disable listbox after modification
            except:
                print("An error occurred while receiving messages.")
                client.close()
                break

    def send_private_message(self, message):
        """Send a private message to a specific user."""
        client.send(message.encode('utf-8'))


if __name__ == "__main__":
    # Start with the username entry GUI
    username_root = Tk()
    username_gui = UsernameGUI(username_root)
    username_root.mainloop()
