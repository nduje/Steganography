# Steganography

## Steps:

- RSA key generation (server/client)
- Diffie-Hellman key exchange (server/client)
- Steganography key generation (server)
- Steganography key AES-CBC encryption based on exchanged symmetric key (server)
- Steganography key exchange (server/client)
- Decrypt steganography using AES-CBC decryption algorithm (client)
- Choose secret message (server)
- Secret message AES-CBC encryption based on exchanged symmetric key (server)
- Hide encrypted message within carrier using steganography algorithm based on steganography key (server)
- Carrier exchange (server/client)
- Extract encrypted message from carrier using reverse steganography algorithm based on steganography key (client)
- Decrypt hidden message using AES-CBC decryption algorithm (client)
