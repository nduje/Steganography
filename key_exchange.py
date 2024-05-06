from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def generate_RSA_private_key():
    RSA_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    RSA_private_key = RSA_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    RSA_private_key_decoded = RSA_private_key.decode()

    print(f"RSA private key:\n {RSA_private_key_decoded}")

    return RSA_private_key

def generate_RSA_public_key(RSA_private_key):
    RSA_private_key = serialization.load_pem_private_key(
        RSA_private_key,
        password=None
    )
    
    RSA_public_key = RSA_private_key.public_key()
    RSA_public_key = RSA_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    RSA_public_key_decoded = RSA_public_key.decode()

    print(f"RSA public key:\n {RSA_public_key_decoded}")

    return RSA_public_key

def generate_DH_parameters():
    DH_parameters = dh.generate_parameters(generator=2, key_size=2048)

    g = DH_parameters.parameter_numbers().g
    p = DH_parameters.parameter_numbers().p

    print(f"Diffie-Hellman parameters:\ng -> {g}\np -> {p}")

    return DH_parameters

def generate_DH_private_key(DH_parameters):
    DH_private_key = DH_parameters.generate_private_key()

    print(f"Diffie-Hellman private key:\n{DH_private_key}")

    return DH_private_key

def generate_DH_public_key(DH_private_key):
    DH_public_key = DH_private_key.public_key()

    print(f"Diffie-Hellman public key:\n{DH_public_key}")

    return DH_public_key

def get_DH_shared_key(DH_private_key, DH_public_key):
    DH_shared_key = DH_private_key.exchange(DH_public_key)

    print(f"Diffie-Hellman shared key:\n{DH_shared_key}")

    return DH_shared_key
