from crypto.rsa_utils import (
    generate_rsa_keys,
    encrypt_session_key,
    decrypt_session_key
)

from crypto.aes_utils import (
    generate_session_key,
    encrypt_message,
    decrypt_message
)

from crypto.signature_utils import (
    sign_data,
    verify_signature
)


def main():

    print("=== PEMBANGKITAN RSA KEY ===")

    public_key, private_key = generate_rsa_keys()

    print("RSA Key Pair berhasil dibuat.\n")


    print("=== PEMBANGKITAN AES SESSION KEY ===")

    session_key = generate_session_key()

    print("Session Key berhasil dibuat.\n")


    plaintext = "Halo, ini pesan rahasia."


    print("=== ENKRIPSI PESAN (AES-GCM) ===")

    nonce, ciphertext, tag = encrypt_message(
        plaintext,
        session_key
    )

    print("Pesan berhasil dienkripsi.\n")


    print("=== ENKRIPSI SESSION KEY (RSA-OAEP) ===")

    encrypted_session_key = encrypt_session_key(
        session_key,
        public_key
    )

    print("Session Key berhasil dienkripsi.\n")


    print("=== MEMBUAT PAKET DATA ===")

    packet = (
        encrypted_session_key +
        nonce +
        ciphertext +
        tag
    )

    print("Packet berhasil dibuat.\n")


    print("=== DIGITAL SIGNATURE ===")

    signature = sign_data(
        packet,
        private_key
    )

    print("Packet berhasil ditandatangani.\n")


    print("=========== DATA DIKIRIM ===========")

    print(f"Encrypted Session Key : {encrypted_session_key.hex()}")
    print(f"Nonce                 : {nonce.hex()}")
    print(f"Ciphertext            : {ciphertext.hex()}")
    print(f"Authentication Tag    : {tag.hex()}")
    print(f"Digital Signature     : {signature.hex()}")



    print("\n=========== RECEIVER ===========")

    received_packet = (
        encrypted_session_key +
        nonce +
        ciphertext +
        tag
    )


    print("\nVerifikasi Digital Signature...")

    if not verify_signature(
        received_packet,
        signature,
        public_key
    ):
        print("Signature tidak valid!")
        return

    print("Signature valid.\n")


    print("Mendekripsi Session Key...")

    recovered_session_key = decrypt_session_key(
        encrypted_session_key,
        private_key
    )


    print("Mendekripsi Ciphertext...")

    recovered_plaintext = decrypt_message(
        nonce,
        ciphertext,
        tag,
        recovered_session_key
    )


    print("\n=========== HASIL ===========")

    print("Plaintext :", recovered_plaintext)


if __name__ == "__main__":
    main()