from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def generate_session_key():
    #Membuat AES-256 Session Key (32 byte)

    return get_random_bytes(32)

def encrypt_message(plaintext, session_key):
    #Mengenkripsi plaintext menggunakan AES-256 GCM

    cipher = AES.new(session_key, AES.MODE_GCM)

    ciphertext, tag = cipher.encrypt_and_digest(
        plaintext.encode("utf-8")
    )

    return cipher.nonce, ciphertext, tag

def decrypt_message(nonce, ciphertext, tag, session_key):
    #Mendekripsi ciphertext menggunakan AES-256 GCM

    cipher = AES.new(
        session_key,
        AES.MODE_GCM,
        nonce=nonce
    )

    plaintext = cipher.decrypt_and_verify(
        ciphertext,
        tag
    )

    return plaintext.decode('utf-8')