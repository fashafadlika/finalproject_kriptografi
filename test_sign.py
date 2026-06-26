from crypto.rsa_utils import generate_rsa_keys
from crypto.signature_utils import sign_data, verify_signature

public_key, private_key = generate_rsa_keys()

data = b"Ini adalah data!!!"

signature = sign_data(data, private_key)

print(
    verify_signature(
        data,
        signature,
        public_key
    )
)