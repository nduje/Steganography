from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import padding
import base64


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

    DH_parameters = DH_parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3
    )

    DH_parameters_decoded = DH_parameters.decode()

    print(f"Diffie-Hellman parameters:\n{DH_parameters_decoded}\ng -> {g}\np -> {p}\n")


    return DH_parameters


def generate_DH_private_key(DH_parameters):
    DH_private_key = DH_parameters.generate_private_key()

    DH_private_key_bytes = DH_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    print(f"Diffie-Hellman private key:\n{DH_private_key_bytes}")

    return DH_private_key


def generate_DH_public_key(DH_private_key):
    DH_public_key = DH_private_key.public_key()

    DH_public_key = DH_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    DH_public_key_decoded = DH_public_key.decode()

    print(f"Diffie-Hellman public key:\n{DH_public_key_decoded}")

    return DH_public_key


def sign_key_client_to_server(RSA_private_key, DH_public_key):
    RSA_private_key = serialization.load_pem_private_key(
        RSA_private_key,
        password=None
    )
    
    client_signature = RSA_private_key.sign(
        DH_public_key,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    client_signature_base64 = base64.b64encode(client_signature)

    client_signature_decoded = client_signature_base64.decode()

    print(f"Client signature:\n{client_signature_decoded}\n")

    return client_signature_base64;


def sign_key_server_to_client(RSA_private_key, DH_parameters, server_DH_public_key, client_DH_public_key):
    RSA_private_key = serialization.load_pem_private_key(
        RSA_private_key,
        password=None
    )

    client_DH_public_key = client_DH_public_key.encode()

    message = DH_parameters + server_DH_public_key + client_DH_public_key
    
    server_signature = RSA_private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    server_signature_base64 = base64.b64encode(server_signature)

    server_signature_decoded = server_signature_base64.decode()

    print(f"Server signature:\n{server_signature_decoded}\n")

    return server_signature_base64;


def get_key(private_key, public_key):
    public_key = public_key.encode()
    public_key = serialization.load_pem_public_key(public_key)

    DH_shared_key = private_key.exchange(public_key)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(DH_shared_key)

    derived_key = base64.b64encode(derived_key).decode()

    return derived_key