#!/usr/bin/env python
# coding: utf-8

# In[11]:


from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes as hash_module
from os import urandom
import hashlib
import os

# Generation of RSA Key Pair for Boby
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    with open("private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    return private_key, public_key

# plaintext file created by Alice  
def create_plaintext_file():
    message = b"Hi Boby I am Alice"
    with open("alice_message.txt", "wb") as f:
        f.write(message)
    return message

# encryption of file with AES by Alice 
def encrypt_file(public_key):
    key = urandom(32)  # AES-256
    iv = urandom(16)

    with open("alice_message.txt", "rb") as f:
        plaintext = f.read()

    padder = sym_padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    with open("encrypted_file.bin", "wb") as f:
        f.write(iv + ciphertext)

    # encryption of AES key with Bob's RSA public key
    encrypted_key = public_key.encrypt(
        key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open("aes_key_encrypted.bin", "wb") as f:
        f.write(encrypted_key)

    return key, iv

# decryption of AES key
def decrypt_file(private_key):
    with open("aes_key_encrypted.bin", "rb") as f:
        encrypted_key = f.read()
    key = private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open("encrypted_file.bin", "rb") as f:
        data = f.read()
    iv = data[:16]
    ciphertext = data[16:]
    
# decryption of file message.txt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    with open("decrypted_message.txt", "wb") as f:
        f.write(plaintext)

    # comparison of Hash to check integrity
    original_hash = hashlib.sha256(open("alice_message.txt", "rb").read()).hexdigest()
    decrypted_hash = hashlib.sha256(open("decrypted_message.txt", "rb").read()).hexdigest()

    print("Hash Match:", original_hash == decrypted_hash)
    print("Original SHA-256:", original_hash)
    print("Decrypted SHA-256:", decrypted_hash)

if __name__ == "__main__":
    priv, pub = generate_rsa_keys()
    create_plaintext_file()
    encrypt_file(pub)
    decrypt_file(priv)
    print("Secure file exchange complete.")


# In[ ]:




