from crypto.aes_utils import *

session_key = generate_session_key()

plaintext = "Halo, ini pesan rahasia."

nonce, ciphertext, tag = encrypt_message(
    plaintext,
    session_key
)

#ciphertext = bytearray(ciphertext)
#ciphertext[0] ^= 1
#ciphertext = bytes(ciphertext)

#print(ciphertext)

hasil = decrypt_message(
    nonce,
    ciphertext,
    tag,
    session_key
)

print(hasil)