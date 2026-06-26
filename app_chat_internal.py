# KERENTANAN: Kunci sangat pendek dan dipakai berulang-ulang
SHARED_KEY = "kunci"

def custom_xor_encrypt(plaintext, key):
    ciphertext = ""
    for i in range(len(plaintext)):
        # KERENTANAN: Algoritma XOR sederhana tanpa mode stream standar (seperti RC4/ChaCha20)
        char = plaintext[i]
        key_char = key[i % len(key)]
        encrypted_char = chr(ord(char) ^ ord(key_char))
        ciphertext += encrypted_char
    return ciphertext

def send_message(message):
    encrypted_msg = custom_xor_encrypt(message, SHARED_KEY)
    print(f"Pesan terenkripsi dikirim: {repr(encrypted_msg)}")

# Contoh Penggunaan:
# send_message("Halo bos, ini laporan keuangan bulan ini.")

send_message("halo, saya admin")