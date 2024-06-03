# Steganography

"Steganography" project involves the design and implementation of a custom steganographic algorithm as a practical assignment for the "Computer Forensics" course.

## Steps:

- **RSA** key generation _(server/client)_
- **Diffie-Hellman** key exchange _(server/client)_
- Choose **secret message** _(server)_
- Encrypt the secret message using the **AES-CTR encryption algorithm** with the exchanged symmetric key _(server)_
- Conceal the encrypted message within the carrier using a **steganography algorithm** _(server)_
- **Carrier** exchange _(server/client)_
- Extract the encrypted message from the carrier using a **reverse steganography algorithm** _(client)_
- Decrypt the secret message using the **AES-CTR decryption algorithm** with the exchanged symmetric key _(client)_

## Documentation:
- [Documentation page](https://github.com/nduje/Steganography/blob/master/documentation)
- [Steganography.pptx](https://github.com/nduje/Steganography/blob/master/documentation/Steganography.pptx)
- [Steganography.pdf](https://github.com/nduje/Steganography/blob/master/documentation/Steganography.pdf)
