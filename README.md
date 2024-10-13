# JSON Web Tokens Built With Node.js

An implementation of JSON Web Tokens (JWTs), JSON Web Signature (JWS) and JSON Web Encryption (JWE), using Node.js crypto library. A webpage illustrating JWS and JWE as cookie based access tokens is included.

## Start The Server
You can run the Node.js server as a container with `docker compose up -d` or as a local Node app with `node server.mjs`.

### AES and RSA Keys Are Automatically Created & Stored In A Created Folder Named `keys`.

## JWS Implementation Specifics

Asymmetric 2048 bit RSA keys are used in this scheme - the private key creates the digital signature and the public key verifies the signature.

## JWE Implementation Specifics

In this implementation, a 256 bit Galois/Counter Mode AES encryption key is used in direct encryption scheme. The same secret key encrypts and decrypts tokens.

## License

The cost is $1,000,000.00 USD. I accept check, cash, gold, silver, platinum, diamonds, and bitcoin.