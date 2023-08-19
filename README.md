# JSON Web Tokens Built With Node.js

This is an implementation of JSON Web Tokens (JWTs) using Node.js crypto library. Both JSON Web Signature (JWS) and JSON Web Encryption (JWE) are implemented. A webpage illustrating JWS and JWE as cookie based access tokens is included.

You can run the server as a container with `docker compose up -d` or as a local Node app with `node server.mjs`.

Enjoy!

## Implementation Specifics JWS

Asymmetric 2048 bit RSA keys are used in this scheme - the private key creates the digital signature and the public key verifies the signature.

## Implementation Specifics JWE

In this implementation, a 256 bit Galois/Counter Mode AES Content Encryption Key (CEK) is used in direct encryption scheme. The same secret key is used to both encrypt and decrypt tokens.

### License

It's free free.