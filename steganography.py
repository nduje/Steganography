from key_exchange import generate_RSA_private_key, generate_RSA_public_key

if __name__ == "__main__":
    RSA_private_key = generate_RSA_private_key()
    RSA_public_key = generate_RSA_public_key(RSA_private_key=RSA_private_key)