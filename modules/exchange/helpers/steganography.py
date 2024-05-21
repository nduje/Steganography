from key_exchange import *

if __name__ == "__main__":
    RSA_private_key = generate_RSA_private_key()
    RSA_public_key = generate_RSA_public_key(RSA_private_key=RSA_private_key)
    DH_parameters = generate_DH_parameters()
    DH_private_key = generate_DH_private_key(DH_parameters=DH_parameters)
    DH_public_key = generate_DH_public_key(DH_private_key=DH_private_key)
    client_signature = sign_key_client_to_server(RSA_private_key=RSA_private_key, DH_public_key=DH_public_key)