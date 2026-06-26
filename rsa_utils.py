from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_rsa_keys():
    # Membuat pasangan RSA Key (2048-bit)

    key = RSA.generate(2048)

    private_key = key.export_key()
    public_key = key.public_key().export_key()

    return public_key, private_key

def encrypt_session_key(session_key, public_key):
    #Mengenkripsi AES Session Key menggunakan RSA-OAEP

    rsa_key = RSA.import_key(public_key)

    cipher = PKCS1_OAEP.new(rsa_key)

    encrypt_session_key = cipher.encrypt(session_key)

    return encrypt_session_key

def decrypt_session_key(encrypted_session_key, private_key):
    #Mendekripsi AES Session Key menggunakan RSA-OAEP

    rsa_key = RSA.import_key(private_key)

    cipher = PKCS1_OAEP.new(rsa_key)

    session_key = cipher.decrypt(encrypted_session_key)

    return session_key



