# Part (a) - Stream Cipher
def text_to_bits(text):
    return ''.join(format(ord(char), '08b') for char in text)

def bits_to_text(bits):
    return ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))

# Stream Cipher
def encrypt(text, key):
    bits = text_to_bits(text)
    encrypted_bits = [int(bit) ^ int(key[i % len(key)]) for i, bit in enumerate(bits)]
    return ''.join(map(str, encrypted_bits))

def decrypt(ciphertext, key):
    decrypted_bits = [int(bit) ^ int(key[i % len(key)]) for i, bit in enumerate(ciphertext)]
    return bits_to_text(''.join(map(str, decrypted_bits)))

# Example Usage
key = "10101011"
message = "Hello, secure messaging!"

encrypted_message = encrypt(message, key)
decrypted_message = decrypt(encrypted_message, key)

print("Original Message:", message)
print("Encrypted Message:", encrypted_message)
print("Decrypted Message:", decrypted_message)