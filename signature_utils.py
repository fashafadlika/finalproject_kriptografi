from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15


def sign_data(data, private_key):
    #Menandatangani data (bytes) menggunakan RSA + SHA-256

    rsa_key = RSA.import_key(private_key)

    data_hash = SHA256.new(data)

    signature = pkcs1_15.new(rsa_key).sign(data_hash)

    return signature

def verify_signature(data, signature, public_key):
    #Verifikasi digital signature

    rsa_key = RSA.import_key(public_key)

    data_hash = SHA256.new(data)

    try:
        pkcs1_15.new(rsa_key).verify(
            data_hash,
            signature
        )
        return True
    
    except(ValueError, TypeError):
        return False
    
