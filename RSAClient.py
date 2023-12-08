import socket
import threading
import random
from tkinter import Tk, Scrollbar, Listbox, Entry, Button, StringVar, DISABLED, NORMAL, Toplevel, Label
from sympy import isprime
from gmpy2 import powmod
import os
import time

ENCRYPTIONTYPE = 'DES_CBC'

if(ENCRYPTIONTYPE == 'STREAMCIPHER'):
    from streamCipher import *

elif(ENCRYPTIONTYPE == 'AES_ECB' or ENCRYPTIONTYPE == 'AES_CBC'):
    from AES import *
elif(ENCRYPTIONTYPE == 'DES_ECB' or ENCRYPTIONTYPE == 'DES_CBC'):
    from DES import *

# Client configuration
HOST = '192.168.1.31'
PORT = 55555

# Agreed Upon Values
primeNumber = 102188617217178804476387977160129334431745945009730065519337094992129677228373
primitiveRoot = 2

# Create a socket for the client
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

class LFSR:
    def __init__(self, seed, taps):
        self.state = seed
        self.taps = taps

    def shift(self):
        feedback = sum(self.state[tap] for tap in self.taps) % 2
        self.state = [feedback] + self.state[:-1]
        return feedback

    def generate_key(self, length):
        key = []
        for _ in range(length):
            key.append(self.shift())
        binary_string = ''.join(map(str, key))
        generated_key = int(binary_string, 2)
        return generated_key

seed = [1, 0, 1, 0]  
shiftFeedbackPositions = [0, 2, 3]       
lfsr = LFSR(seed, shiftFeedbackPositions)

#RSA Functions#

'''Calculates the modular exponetiation of a given message, power, and basis using the 'powmod' function from the gmpy2 library'''
def exponentiation(message, power, basis):
    return powmod(message, power, basis)

'''Helper function that incorporates the extended euclidean algorithm to help determine the inverse value within the inverse_finder function.'''
def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, x, y = extended_gcd(b % a, a)
        return g, y - (b // a) * x, x

'''Finds the modular inverse of a given number a modulo n using the extended euclidean algorithm.'''
def inverse_finder(a, n):
    g, x, _ = extended_gcd(a, n)
    if g != 1:
        raise ValueError(f"The modular inverse does not exist for {a} modulo {n}")
    else:
        return x % n
'''A function that generates RSA public and private keys. It takes an optional parameter e for the rsaKeyInput; if not provided, it defaults to 3.'''
def RSA_key_generate():
    e = 65537
    p = primitiveRoot
    q = primeNumber
    
    n = p * q    
    euler = (p-1) * (q-1)  
    d = inverse_finder(e, euler)
    publicKey = [e, n]
    privateKey = [d, n]
    return publicKey, privateKey

'''A function encrypts a numeric message or a string using RSA encryption with a given key.'''
def RSA_encrypt(message, key):
    if not isinstance(message, str):
        return exponentiation(message, key[0], key[1])
    elif isinstance(message, str):
        ciphertext = []
        for element in range(0, len(message)): 
            ciphertext.append(int(exponentiation(ord(message[element]), key[0], key[1])))
        return ciphertext

'''A function decrypts a numeric message or a list of numeric values using RSA decryption with a given key.'''
def RSA_decrypt(message, key):
    if not isinstance(message, str) and not isinstance(message, list):
        return RSA_encrypt(message, key)
    elif isinstance(message, list):
        decrpyted = ''
        for element in range(0, len(message)): 
            decrpyted+= chr(exponentiation(message[element], key[0], key[1]))
        return decrpyted

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
        

        self.public_key, self.private_key = RSA_key_generate()
        self.recievedLSFRKeys = {}
        self.sentLSFRKeys = []
        self.public_keys = {}
        if(ENCRYPTIONTYPE == "AES_CBC"):
            self.public_IVs = {}
            self.IV = os.urandom(16)
        elif(ENCRYPTIONTYPE == "DES_CBC"):
            self.public_IVs = {}
            self.IV = os.urandom(8)
        random_seed_length = random.randint(4, 15)  
        seed = [random.randint(0, 1) for _ in range(random_seed_length)]
        shiftFeedbackPositions = random.sample(range(len(seed)), k=random.randint(1, len(seed)))
        shiftFeedbackPositions.sort()
        lfsr = LFSR(seed, shiftFeedbackPositions)
        key_length = 256
        if(ENCRYPTIONTYPE == 'DES_ECB' or ENCRYPTIONTYPE == 'DES_CBC'):
            key_length = 64
        generated_key = lfsr.generate_key(key_length)
        self.LSFRKey = generated_key
        message = f"Your generated LFSR Key: {self.LSFRKey}"
        self.message_listbox.config(state=NORMAL)  # Enable listbox for modification
        self.message_listbox.insert('end', message)
        self.message_listbox.config(state=DISABLED)  # Disable listbox after modification
                
        # Start a thread to receive messages
        receive_thread = threading.Thread(target=self.receive_messages)
        receive_thread.start()
        
        # Send the username to the server
        client.send(username.encode('utf-8'))
        if(ENCRYPTIONTYPE == "AES_CBC" or ENCRYPTIONTYPE == "DES_CBC"):
            client.send(f"Public key: {self.public_key[1]} Public IV: {b64encode(self.IV).decode()}".encode('utf-8'))
        else:
            client.send(f"Public key: {self.public_key[1]}".encode('utf-8'))

    def send_message(self):
        message = self.message_entry.get()
        self.message_entry.delete(0, 'end')

        # Check if the message is a special command to send a private message
        if message.startswith('./checkSharedKey'):
            self.check_shared_key(message)
        elif message.startswith('./sendToUser'):
            self.send_private_message(message)
        elif message.startswith('./sendLFSRKey'):
            self.send_LSFR_key(message)
        else:
            client.send(message.encode('utf-8'))

    def receive_messages(self):
        """Receive and display messages from the server."""
        while True:
            try:
                message = client.recv(1024).decode('utf-8')
                if message.startswith('./sendLFSRkey'):
                    parts = message.split(' ', 5)
                    encryptedLSFRKey = int(parts[2])
                    decryptionKey = [int(parts[3]), int(parts[4])]
                    fromUser = parts[5]
                    sentLSFR = RSA_decrypt(encryptedLSFRKey, decryptionKey)
                    message = f'Recieved from {fromUser}: {sentLSFR}'
                    self.recievedLSFRKeys[fromUser] = int(sentLSFR)
                    print(fromUser)
                    print(self.recievedLSFRKeys[fromUser])
                    self.message_listbox.config(state=NORMAL)  # Enable listbox for modification
                    self.message_listbox.insert('end', message)
                    self.message_listbox.config(state=DISABLED)
                elif message.startswith('./success'):
                    parts = message.split(' ', 1)
                    target_username = parts[1]
                    message = f"LSFR key successfully sent to {target_username}."
                    self.message_listbox.config(state=NORMAL)  # Enable listbox for modification
                    self.message_listbox.insert('end', message)
                    self.message_listbox.config(state=DISABLED)
                    # Mark the LSFR key as sent to the target user
                    self.sentLSFRKeys.append(target_username)
                elif message.startswith("Public key of "):
                    self.handle_public_key(message)
                elif message.startswith("Public IV of "):
                    self.handle_public_IV(message)
                elif message.startswith('./fail'):
                    parts = message.split(' ', 1)
                    target_username = parts[1]
                    message = f"Failed to send LSFR key to {target_username}."
                    self.message_listbox.config(state=NORMAL)  # Enable listbox for modification
                    self.message_listbox.insert('end', message)
                    self.message_listbox.config(state=DISABLED)
                elif message.startswith("./decrypt"):
                    parts = message.split(' ', 2)
                    target_username = parts[1]
                    private_message = parts[2]
                    message = f'The encrypted message was sent for you by {target_username}.'
                    # Handle regular messages
                    self.message_listbox.config(state=NORMAL)  # Enable listbox for modification
                    self.message_listbox.insert('end', message)
                    self.message_listbox.config(state=DISABLED)  # Disable listbox after modification
                    if(ENCRYPTIONTYPE == "STREAMCIPHER"):
                        DecryptedMessage = decrypt(private_message, str(bin(self.recievedLSFRKeys[target_username])[2:]))
                    elif(ENCRYPTIONTYPE == "AES_ECB"):
                        key_bytes = self.recievedLSFRKeys[target_username].to_bytes((self.recievedLSFRKeys[target_username].bit_length() + 7) // 8, 'little')
                        print(private_message)
                        DecryptedMessage = decrypt(str(private_message), key_bytes, modes.ECB()).decode('utf-8')
                    elif(ENCRYPTIONTYPE == "AES_CBC"):
                        key_bytes = self.recievedLSFRKeys[target_username].to_bytes((self.recievedLSFRKeys[target_username].bit_length() + 7) // 8, 'little')
                        DecryptedMessage = decrypt(private_message, key_bytes, modes.CBC(self.public_IVs[target_username]))
                    elif(ENCRYPTIONTYPE == "DES_ECB"):
                        key_bytes = self.recievedLSFRKeys[target_username].to_bytes((self.recievedLSFRKeys[target_username].bit_length() + 7) // 8, 'little')
                        DecryptedMessage = decrypt(private_message, key_bytes, DES.MODE_ECB)     
                    elif(ENCRYPTIONTYPE == "DES_CBC"):
                        key_bytes = self.recievedLSFRKeys[target_username].to_bytes((self.recievedLSFRKeys[target_username].bit_length() + 7) // 8, 'little')
                        DecryptedMessage = decrypt(private_message, key_bytes, DES.MODE_CBC, self.public_IVs[target_username])                      
                    message = f'Decrypted Message using associated Key: {DecryptedMessage}'
                    self.message_listbox.config(state=NORMAL)  # Enable listbox for modification
                    self.message_listbox.insert('end', message)
                    self.message_listbox.config(state=DISABLED)  # Disable listbox after modification                    
                else:
                    self.message_listbox.config(state=NORMAL)  # Enable listbox for modification
                    self.message_listbox.insert('end', message)
                    self.message_listbox.config(state=DISABLED)  # Disable listbox after modification
            except Exception as e:
                print(f"An error occurred while receiving messages: {e}")
                client.close()
                break

                
    def send_private_message(self, message):
        # Extract username and private message from the message
        _, target_username, private_message = message.split(' ', 2)

        # Check if the target username is in the list of users
        if target_username not in self.sentLSFRKeys:
            print(f"User {target_username} not found in the list.")
            # Handle the error case as needed (e.g., display an error message)
            return

        # Send the private message to the target user
        if(ENCRYPTIONTYPE == "STREAMCIPHER"):
            message = f'./sendToUser {target_username} {encrypt(private_message, str(bin(self.LSFRKey)[2:]))}'
        elif(ENCRYPTIONTYPE == "AES_ECB"):
            key_bytes = self.LSFRKey.to_bytes((self.LSFRKey.bit_length() + 7) // 8, 'little')
            message = f'./sendToUser {target_username} {encrypt(str(private_message), key_bytes, modes.ECB()).decode()}'
        elif(ENCRYPTIONTYPE == "AES_CBC"):
            key_bytes = self.LSFRKey.to_bytes((self.LSFRKey.bit_length() + 7) // 8, 'little')
            message = f'./sendToUser {target_username} {encrypt(str(private_message), key_bytes, modes.CBC(self.IV)).decode()}'
        elif(ENCRYPTIONTYPE == "DES_ECB"):
            key_bytes = self.LSFRKey.to_bytes((self.LSFRKey.bit_length() + 7) // 8, 'little')
            message = f'./sendToUser {target_username} {encrypt(str(private_message), key_bytes, DES.MODE_ECB).decode()}'
        elif(ENCRYPTIONTYPE == "DES_CBC"):
            key_bytes = self.LSFRKey.to_bytes((self.LSFRKey.bit_length() + 7) // 8, 'little')
            message = f'./sendToUser {target_username} {encrypt(str(private_message), key_bytes, DES.MODE_CBC, self.IV).decode()}'            
        client.send(message.encode('utf-8'))

    def send_LSFR_key(self, message):
        _, target_username = message.split(' ', 2)

        # Check if the LSFR key has already been sent to the target user
        if target_username in self.sentLSFRKeys:
            print(f"LSFR key already sent to {target_username}.")
            return

        # Send the LSFR key to the target user
        encrypted_lsfr_key = RSA_encrypt(self.LSFRKey, self.public_key)
        client.send(f"./sendLFSRkey {target_username} {encrypted_lsfr_key} {self.private_key[0]} {self.private_key[1]}".encode('utf-8'))
    
    def handle_public_key(self, message):
        # Parse the public key message
        parts = message.split(": ")
        if len(parts) == 2:
            username = parts[0][14:]
            public_key = int(parts[1])
            
            self.public_keys[username] = public_key
            print(f'Recieved {username}\'s public key: {public_key}')

    def handle_public_IV(self, message):
        # Parse the public key message
        parts = message.split(": ")
        if len(parts) == 2:
            username = parts[0][13:]
            IV = b64decode(parts[1])
            
            self.public_IVs[username] = IV
            print(f'Recieved {username}\'s public IV: {IV}')         



if __name__ == "__main__":
    # Start with the username entry GUI
    username_root = Tk()
    username_gui = UsernameGUI(username_root)
    username_root.mainloop()
