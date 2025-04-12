import streamlit as st
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import base64

# Function to encrypt text
def encrypt_text(plain_text, key):
    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)
    
    # Pad the plain text to make it a multiple of block size (AES block size is 128 bits = 16 bytes)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plain_text.encode()) + padder.finalize()

    # Create AES cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Return the encrypted data and IV, encoded as base64 to make it readable
    return base64.b64encode(encrypted_data).decode(), base64.b64encode(iv).decode()

# Function to decrypt text
def decrypt_text(encrypted_text, key, iv):
    # Decode base64 encoded encrypted data and IV
    encrypted_data = base64.b64decode(encrypted_text)
    iv = base64.b64decode(iv)
    
    # Create AES cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(128).unpadder()
    original_data = unpadder.update(decrypted_data) + unpadder.finalize()
    
    return original_data.decode()

# Streamlit UI
st.title("Secure Data Encryption with AES")

# Input text for encryption
plain_text = st.text_area("Enter text to encrypt")

# Generate random key (128 bits)
key = os.urandom(16)

# Encrypting the text
if st.button("Encrypt Text"):
    if plain_text:
        encrypted_data, iv = encrypt_text(plain_text, key)
        st.write("Encrypted Data (Base64):")
        st.text(encrypted_data)
        st.write("IV (Base64):")
        st.text(iv)
    else:
        st.warning("Please enter some text to encrypt.")

# Decrypting the text
encrypted_text = st.text_area("Enter encrypted text (Base64) for decryption")
iv_input = st.text_input("Enter IV (Base64)")

if st.button("Decrypt Text"):
    if encrypted_text and iv_input:
        try:
            decrypted_text = decrypt_text(encrypted_text, key, iv_input)
            st.write("Decrypted Text:")
            st.text(decrypted_text)
        except Exception as e:
            st.error(f"Error in decryption: {str(e)}")
    else:
        st.warning("Please enter encrypted text and IV.")
