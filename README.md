## JSON Web Token (JWT)

A JSON Web Token (JWT) is a standardized and open format (RFC 7519) that provides a compact and self-contained method for securely transmitting information between parties in the form of a JSON object.

JWTs can be signed using either a secret with the HMAC algorithm or a public/private key pair using RSA. The structure of a JWT token is as follows:

```[Base64(HEADER)].[Base64(PAYLOAD)].[Base64(SIGNATURE)]```

Note: Most applications utilize JSON Web Tokens (JWT) to enable the client to assert its identity for subsequent exchanges after authentication, though it can also serve for general information exchange.


## Base64 Encoding + AES
### Base64
Base64 is an encoding scheme that transforms binary data into an ASCII string format, facilitating the transfer of binary data across various channels. It converts any type of data into a lengthy string of plain text.

### AES algorithm
The Advanced Encryption Standard (AES) is an iterative, symmetric-key block cipher supporting cryptographic keys of 128, 192, and 256 bits for encrypting and decrypting data in 128-bit blocks. It operates with the same key for both encryption and decryption.

Implementation of AES encryption and decryption can be achieved using the Java Cryptography Architecture (JCA) within the JDK. AES offers six modes of operation:

ECB (Electronic Code Book)
CBC (Cipher Block Chaining)
CFB (Cipher FeedBack)
OFB (Output FeedBack)
CTR (Counter)
GCM (Galois/Counter Mode)
 
AES maintains a fixed block size of 128 bits or 16 bytes. The ciphertext size is identical to the cleartext size, and in ECB and CBC modes, a padding algorithm like PKCS 5 is recommended.

Therefore, the size of data after encryption is calculated as follows:

```ciphertext_size (bytes) = cleartext_size + (16 - (cleartext_size % 16))```
