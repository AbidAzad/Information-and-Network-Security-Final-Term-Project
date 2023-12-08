import socket
import threading
import random
from tkinter import Tk, Scrollbar, Listbox, Entry, Button, StringVar, DISABLED, NORMAL, Toplevel, Label
from sympy import isprime
from gmpy2 import powmod
import math
import os
import hashlib

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

'''Helper function that generates a large prime number with the specified number of bits, in which for this assignment is 512.'''
def generate_large_prime(bits):
    while True:
        num = random.randrange(0, 2**bits - 1)
        if isprime(num):
            return num
def exponentiation(message, power, basis):
    return powmod(message, power, basis)
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
    while(True):
        p = generate_large_prime(512)
        q = p
        
        while(p == q):
            q = generate_large_prime(512)
        n = p * q    
        euler = (p-1) * (q-1)
        
        if(math.gcd(euler, e) == 1):
            break
    d = inverse_finder(e, euler)
    publicKey = [e, n]
    privateKey = [d, n]
    return publicKey, privateKey
def hash_message(message):
    # Hash the message using SHA-256
    sha256 = hashlib.sha256()
    sha256.update(str(message).encode('utf-8'))
    return int(sha256.hexdigest(), 16)

def RSA_sign(message, private_key):
    hashed_message = hash_message(message)
    signature = exponentiation(hashed_message, private_key[0], private_key[1])
    return signature

def RSA_verify(message, signature, public_key):
    hashed_message = hash_message(message)
    decrypted_signature = exponentiation(signature, public_key[0], public_key[1])
    
    if hashed_message == decrypted_signature:
        print("YESSSSSSSSSSSSSSSSSSSS!")
        return True
    else:
        print("NOOOOOOOOOOOOOOO!")
        return False
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
        self.secret_integer = random.getrandbits(64)
        message = f'Your secret integer:{self.secret_integer}'
        self.message_listbox.config(state=NORMAL)  # Enable listbox for modification
        self.message_listbox.insert('end', message)
        self.message_listbox.config(state=DISABLED)  # Disable listbox after modification
        self.public_keys = {}

        self.public_signature_keys = {}

        self.publicSignKey, self.privateSignKey = RSA_key_generate()

        if(ENCRYPTIONTYPE == "AES_CBC"):
            self.public_IVs = {}
            self.IV = os.urandom(16)
        elif(ENCRYPTIONTYPE == "DES_CBC"):
            self.public_IVs = {}
            self.IV = os.urandom(8)        

                
        # Start a thread to receive messages
        receive_thread = threading.Thread(target=self.receive_messages)
        receive_thread.start()
        
        # Send the username to the server
        client.send(username.encode('utf-8'))
        if(ENCRYPTIONTYPE == "AES_CBC" or ENCRYPTIONTYPE == "DES_CBC"):
            client.send(f"Public key: {pow(primitiveRoot, self.secret_integer, primeNumber)} Public Signature Key: ({self.publicSignKey[0]},{self.publicSignKey[1]}) Public IV: {b64encode(self.IV).decode()}".encode('utf-8'))
        else:
            client.send(f"Public key: {pow(primitiveRoot, self.secret_integer, primeNumber)} Public Signature Key: ({self.publicSignKey[0]},{self.publicSignKey[1]})".encode('utf-8'))        
        
        
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
                elif message.startswith("Public IV of "):
                    self.handle_public_IV(message)
                elif message.startswith("Signature key of "):
                    self.handle_public_signature(message)                    
                elif message.startswith("./decrypt"):
                    parts = message.split(' ', 3)
                    target_username = parts[1]
                    private_message = parts[2]
                    signature = int(parts[3])    
                    message = f'The encrypted message was sent for you by {target_username}.'
                    # Handle regular messages
                    self.message_listbox.config(state=NORMAL)  # Enable listbox for modification
                    self.message_listbox.insert('end', message)
                    self.message_listbox.config(state=DISABLED)  # Disable listbox after modification
                    shared_secret_key = pow(self.public_keys[target_username] , self.secret_integer, primeNumber)
                    print(bin(shared_secret_key)[2:])
                    if(ENCRYPTIONTYPE == "STREAMCIPHER"):
                        DecryptedMessage = decrypt(private_message, str(bin(shared_secret_key)[2:]))
                    elif(ENCRYPTIONTYPE == "AES_ECB"):
                        key_bytes = shared_secret_key.to_bytes((shared_secret_key.bit_length() + 7) // 8, 'little')
                        print(private_message)
                        DecryptedMessage = decrypt(str(private_message), key_bytes, modes.ECB()).decode('utf-8')
                    elif(ENCRYPTIONTYPE == "AES_CBC"):
                        key_bytes = shared_secret_key.to_bytes((shared_secret_key.bit_length() + 7) // 8, 'little')
                        DecryptedMessage = decrypt(private_message, key_bytes, modes.CBC(self.public_IVs[target_username]))
                    elif(ENCRYPTIONTYPE == "DES_ECB"):
                        key_bytes = shared_secret_key.to_bytes((shared_secret_key.bit_length() + 7) // 8, byteorder='big')
                        key_bytes = hashlib.sha256(key_bytes).digest()[:8]
                        DecryptedMessage = decrypt(private_message, key_bytes, DES.MODE_ECB)     
                    elif(ENCRYPTIONTYPE == "DES_CBC"):
                        key_bytes = shared_secret_key.to_bytes((shared_secret_key.bit_length() + 7) // 8, byteorder='big')
                        key_bytes = hashlib.sha256(key_bytes).digest()[:8]
                        DecryptedMessage = decrypt(private_message, key_bytes, DES.MODE_CBC, self.public_IVs[target_username])                      
                    message = f'Decrypted Message using associated Key: {DecryptedMessage}'
                    
                    self.message_listbox.config(state=NORMAL)  # Enable listbox for modification
                    self.message_listbox.insert('end', message)
                    self.message_listbox.config(state=DISABLED)  # Disable listbox after modification
                    if(RSA_verify(DecryptedMessage, signature, self.public_signature_keys[target_username])):
                        message = f'This message has been verified from its Digital Signature!'
                        self.message_listbox.config(state=NORMAL)  # Enable listbox for modification
                        self.message_listbox.insert('end', message)
                        self.message_listbox.config(state=DISABLED)  # Disable listbox after modification
                    else:
                        message = f'This message has been verified from its Digital Signature!'
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
    
    def handle_public_IV(self, message):
        # Parse the public key message
        parts = message.split(": ")
        if len(parts) == 2:
            username = parts[0][13:]
            IV = b64decode(parts[1])
            
            self.public_IVs[username] = IV
            print(f'Recieved {username}\'s public IV: {IV}')
    
    def handle_public_signature(self, message):
        # Parse the public key message
        parts = message.split(": ")
        if len(parts) == 2:
            username = parts[0][17:]
            signature_key_str = parts[1]
            signature_key_str = signature_key_str.replace("(", "").replace(")", "")
            signature_key = list(map(int, signature_key_str.replace("(", "").replace(")", "").split(',')))
            
            self.public_signature_keys[username] = signature_key
            print(f'Recieved {username}\'s public signature key: {signature_key}')            
    
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
        if(ENCRYPTIONTYPE == "STREAMCIPHER"):
            ciphertext = encrypt(message, str(bin(shared_secret_key)[2:]))
            message = f'./sendToUser {target_username} {ciphertext} {RSA_sign(message, self.privateSignKey)}'
        elif(ENCRYPTIONTYPE == "AES_ECB"):
            key_bytes = shared_secret_key.to_bytes((shared_secret_key.bit_length() + 7) // 8, 'little')
            ciphertext = encrypt(str(message), key_bytes, modes.ECB()).decode()
            message = f'./sendToUser {target_username} {ciphertext} {RSA_sign(message, self.privateSignKey)}'
        elif(ENCRYPTIONTYPE == "AES_CBC"):
            key_bytes = shared_secret_key.to_bytes((shared_secret_key.bit_length() + 7) // 8, 'little')
            ciphertext = encrypt(str(message), key_bytes, modes.CBC(self.IV)).decode()
            message = f'./sendToUser {target_username} {ciphertext} {RSA_sign(message, self.privateSignKey)}'
        elif(ENCRYPTIONTYPE == "DES_ECB"):
            key_bytes = shared_secret_key.to_bytes((shared_secret_key.bit_length() + 7) // 8, byteorder='big')
            key_bytes = hashlib.sha256(key_bytes).digest()[:8]
            ciphertext = encrypt(str(message), key_bytes, DES.MODE_ECB).decode()
            message = f'./sendToUser {target_username} {ciphertext} {RSA_sign(message, self.privateSignKey)}'
        elif(ENCRYPTIONTYPE == "DES_CBC"):
            key_bytes = shared_secret_key.to_bytes((shared_secret_key.bit_length() + 7) // 8, byteorder='big')
            key_bytes = hashlib.sha256(key_bytes).digest()[:8]
            ciphertext = encrypt(str(message), key_bytes, DES.MODE_CBC, self.IV).decode()
            message = f'./sendToUser {target_username} {ciphertext} {RSA_sign(message, self.privateSignKey)}'   
        client.send(message.encode('utf-8'))


if __name__ == "__main__":
    # Start with the username entry GUI
    username_root = Tk()
    username_gui = UsernameGUI(username_root)
    username_root.mainloop()
