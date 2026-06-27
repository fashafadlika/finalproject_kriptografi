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


def send_message(message, receiver_public_key, sender_private_key):
    """
    Simulasi sisi pengirim.
    """

    # Generate AES Session Key
    session_key = generate_session_key()

    # Encrypt Message
    nonce, ciphertext, tag = encrypt_message(
        message,
        session_key
    )

    # Encrypt Session Key
    encrypted_session_key = encrypt_session_key(
        session_key,
        receiver_public_key
    )

    # Buat packet
    packet = (
        encrypted_session_key +
        nonce +
        ciphertext +
        tag
    )

    # Digital Signature
    signature = sign_data(
        packet,
        sender_private_key
    )

    return {
        "encrypted_session_key": encrypted_session_key,
        "nonce": nonce,
        "ciphertext": ciphertext,
        "tag": tag,
        "signature": signature
    }


def receive_message(packet, receiver_private_key, sender_public_key):
    """
    Simulasi sisi penerima.
    """

    encrypted_session_key = packet["encrypted_session_key"]
    nonce = packet["nonce"]
    ciphertext = packet["ciphertext"]
    tag = packet["tag"]
    signature = packet["signature"]

    data = (
        encrypted_session_key +
        nonce +
        ciphertext +
        tag
    )

    # Verifikasi Signature
    if not verify_signature(
        data,
        signature,
        sender_public_key
    ):
        raise Exception("Digital Signature tidak valid!")

    # Recover AES Session Key
    session_key = decrypt_session_key(
        encrypted_session_key,
        receiver_private_key
    )

    # Decrypt Message
    plaintext = decrypt_message(
        nonce,
        ciphertext,
        tag,
        session_key
    )

    return plaintext


def main():

    # Key milik sender
    sender_public_key, sender_private_key = generate_rsa_keys()

    # Key milik receiver
    receiver_public_key, receiver_private_key = generate_rsa_keys()

    message = "Halo, ini pesan rahasia."

    print("===== SENDER =====")

    packet = send_message(
        message,
        receiver_public_key,
        sender_private_key
    )
    print(packet)
    #print("Pesan terenkripsi berhasil dikirim.\n")

    print("===== RECEIVER =====")

    plaintext = receive_message(
        packet,
        receiver_private_key,
        sender_public_key
    )

    print(f"Pesan diterima: {plaintext}")


if __name__ == "__main__":
    main()