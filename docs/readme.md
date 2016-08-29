# oscrypto Documentation

*oscrypto* is a library that exposes cryptography primitives from the host
operating system. It is broken down into a few different submodules:

| Submodule                                | Functionality                                                                                 |
| ---------------------------------------- | --------------------------------------------------------------------------------------------- |
| [`oscrypto`](oscrypto.md)                | Configuration and information about backend                                                   |
| [`oscrypto.symmetric`](symmetric.md)     | AES, Triple DES, DES, RC2 and RC4 encryption                                                  |
| [`oscrypto.asymmetric`](asymmetric.md)   | RSA, DSA and EC-key signing and verification, RSA encryption                                  |
| [`oscrypto.kdf`](kdf.md)                 | PBKDF2, PBKDF1 and PKCS#12 key derivation functions                                           |
| [`oscrypto.keys`](keys.md)               | Certificate, public key and private key loading, parsing and normalization                    |
| [`oscrypto.tls`](tls.md)                 | TLSv1.x socket wrappers utilizing OS trust store and modern cipher suites                     |
| [`oscrypto.trust_list`](trust_list.md)   | CA certificate list export from the OS trust store                                            |
| [`oscrypto.util`](util.md)               | Random byte generation, constant time string comparison                                       |

Many of the supported ciphers and hashes are not necessarily modern, and should
primarily be used for integration with legacy systems. For modern cryptography,
please see [Modern Cryptography](#modern-cryptography).

## Modern Cryptography

A good place to get an overview of the correct tools to use for modern
cryptography is [(Updated) Cryptographic Right Answers](https://gist.github.com/tqbf/be58d2d39690c3b366ad)
by Thomas Ptacek.

In short, you probably want to be using [NaCl](http://nacl.cr.yp.to/) by Daniel
J. Bernstein (DJB) - he is a very accomplished cryptographer. Using
[scrypt](http://www.tarsnap.com/scrypt.html) by Colin Percival for password
hashing is a good idea. Here are some libraries for Python that may be useful:

 - https://github.com/pyca/pynacl
 - https://pypi.python.org/pypi/scrypt/

Thomas‘s recommendations are an alternative, slightly-updated version
of [Cryptographic Right Answers](http://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html)
by Colin Percival. Colin‘s contain recommendations that may be a little more
accessible, using things like RSA PSS for signing, RSA OAEP for encryption,
scrypt or PBKDF2 for password hashing, and AES CTR with HMAC for symmetric
encryption.

## Learning

Before using *oscrypto*, you should know a bit about cryptography, and how to
safely use the primitives. If you don‘t, you could very likely utilize them in
an unsafe way, resulting in exposure of confidential information, including
secret keys, encrypted data, and more.

Here are some topics worth learning about:

 - Block ciphers (AES, Triple DES (2-key and 3-key), DES, RC2)
 - Weak block ciphers (Triple DES 2-key, DES, RC2)
 - Block cipher padding (PKCS#7 and PKCS#5)
 - Block cipher padding oracle attacks
 - Block cipher modes of operation (CBC, ECB, CFB, OFB, CTR)
 - Block cipher modes to avoid (ECB)
 - Nonce reuse in CTR-mode
 - Authenticated encryption (AEAD, EtM, MtE, E&M)
 - Authenticated block cipher modes (GCM, CCM)
 - Stream ciphers (RC4)
 - Hashing (MD5, SHA1, SHA-2 (SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA512/256))
 - Weak hashes (MD5, SHA1)
 - Length extension attacks (MD5, SHA1, SHA-256, SHA-512)
 - HMAC
 - Cryptographically random numbers
 - RSA key sizes (1024, 2048, 3072, 4096)
 - DSA key sizes and hash algorithms
   - SHA1/1024
   - SHA1/2048 (non-standard)
   - SHA-2/2048
   - SHA-2/3072
 - Elliptic curve (EC) keys and named curves
   - P-192 / secp192r1 / prime192v1
   - P-224 / secp224r1
   - P-256 / secp256r1 / prime256v1
   - P-384 / secp384r1
   - P-521 / secp521r1
 - RSA signature padding (PKCS#1 v1.5 and PSS)
 - RSA encryption padding (PKCS#1 v1.5 and OAEP)
 - Weak RSA signature/encryption padding (PKCS#1 v1.5)
 - Timing attacks

Some sources to learn more about cryptography:

 - [Crypto101](https://www.crypto101.io/)
 - [(Updated) Cryptographic Right Answers](https://gist.github.com/tqbf/be58d2d39690c3b366ad)
 - [How To Safely Generate a Random Number](http://sockpuppet.org/blog/2014/02/25/safely-generate-random-numbers/)
 - http://crypto.stackexchange.com/
