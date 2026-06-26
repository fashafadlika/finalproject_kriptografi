from rsa_utils import *
from Crypto.Random import get_random_bytes

public_key, private_key = generate_rsa_keys()

session_key = get_random_bytes(32)

encrypted = encrypt_session_key(
    session_key,
    public_key
)

decrypted = decrypt_session_key(
    encrypted,
    private_key
)

print(encrypted)
print(session_key == decrypted)