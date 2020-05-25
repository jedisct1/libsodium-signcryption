# signcryption using libsodium

An implementation of the Toorani-Beheshti signcryption scheme, instantiated over the Ristretto255 group.

## Why

Traditional authenticated encryption with a shared key allows two or more parties to decrypt a ciphertext and verify that it was created by a member of the group knowing that secret key.

However, it doesn't allow verification of who in a group originally created a message.

In order to do so, authenticated encryption has to be combined with signatures.

The Toorani-Beheshti signcryption scheme achieves this using a single key pair per device, with forward security and public verifiability.

## Parameter definitions

- `sender_id`: an identifier for a sender. It may be the sender's public key but it doesn't have to. It can also be an account number, or anything that can uniquely identifier a user. It doesn't need to be secret, nor have high entropy. A user can send messages from multiple devices, each with their own key pair, as long as the `sender_id` remains the same.
- `recipient_id`: an identifier for the recipient of a message. It can represent a specific party, or, for a message sent to a group, a group identifier.
- `info`: this describes the context in which a message was sent. Signature verification will fail if the context expected by the verifier doesn't match the one the signature was origially created for.
- `shared_key`: a shared secret key, used for encryption.

## Source code

- The `src/tbsbr` directory contains the main source code, with the scheme implemented using the BLAKE2b hash function and the Ristretto255 group. This is the recommended version.
- As an alternative, the `src/tbsbe` directory contains an version using the standard edwards25519 encoding.

The API decription below assumes the `tbsbr` version is being used, but both versions have the exact same API with a different prefix.

## Key pair creation

```c
void crypto_signcrypt_tbsbr_keygen(unsigned char pk[crypto_signcrypt_tbsbr_PUBLICKEYBYTES],
                                   unsigned char sk[crypto_signcrypt_tbsbr_SECRETKEYBYTES]);
```

Create a new key pair, putting the public key into `pk` and the secret into `sk`.

```c
void crypto_signcrypt_tbsbr_seed_keygen(unsigned char pk[crypto_signcrypt_tbsbr_PUBLICKEYBYTES],
                                        unsigned char sk[crypto_signcrypt_tbsbr_SECRETKEYBYTES],
                                        const unsigned char seed[crypto_signcrypt_tbsbr_SEEDBYTES]);
```

Create a deterministic key pair from the seed `seed`.

## Signcryption

These functions are called by the sender.

```c
int crypto_signcrypt_tbsbr_sign_before(
    unsigned char st[crypto_signcrypt_tbsbr_STATEBYTES],
    unsigned char shared_key[crypto_signcrypt_tbsbr_SHAREDBYTES],
    const unsigned char *sender_id, size_t sender_id_len,
    const unsigned char *recipient_id, size_t recipient_id_len,
    const unsigned char *info, size_t info_len,
    const unsigned char sender_sk[crypto_signcrypt_tbsbr_SECRETKEYBYTES],
    const unsigned char recipient_pk[crypto_signcrypt_tbsbr_PUBLICKEYBYTES],
    const unsigned char *m, size_t m_len);
```

This function computes a shared key `shared_key` that can later be used to encrypt a message from `sender_id` to `recipient_id` in the `info` context.

`m` is the message to be encrypted, and `m_len` its size in bytes. On a system with a reliable secure random number generator, this is optional and `m` can be set to `NULL`, with `m_len` set to `0`.

`shared_key` can then be used to encrypt the message with any authenticated encryption system.

`st` will contain the state, required for the `sign_after` step.

The function returns `-1` or error, `0` on success.

```c
int crypto_signcrypt_tbsbr_sign_after(
    unsigned char       st[crypto_signcrypt_tbsbr_STATEBYTES],
    unsigned char       sig[crypto_signcrypt_tbsbr_SIGNBYTES],
    const unsigned char sender_sk[crypto_signcrypt_tbsbr_SECRETKEYBYTES],
    const unsigned char *c, size_t c_len);
```

Once the message has been encrypted, it must be signed with this function. `c` is the ciphertext, and `c_len` its length.

The signature is stored into `sig`.

The function returns `-1` or error, `0` on success.

A typical signcryption sequence is thus:

- `crypto_signcrypt_tbsbr_sign_before()`
- encrypt with `shared_key`
- `crypto_signcrypt_tbsbr_sign_after()`

## Unsigncryption

The functions are called by the recipient.

```c
int crypto_signcrypt_tbsbr_verify_before(
    unsigned char       st[crypto_signcrypt_tbsbr_STATEBYTES],
    unsigned char       shared_key[crypto_signcrypt_tbsbr_SHAREDBYTES],
    const unsigned char sig[crypto_signcrypt_tbsbr_SIGNBYTES],
    const unsigned char *sender_id, size_t sender_id_len,
    const unsigned char *recipient_id, size_t recipient_id_len,
    const unsigned char *info, size_t info_len,
    const unsigned char sender_pk[crypto_signcrypt_tbsbr_PUBLICKEYBYTES],
    const unsigned char recipient_sk[crypto_signcrypt_tbsbr_PUBLICKEYBYTES]);
```

This function creates a state `st` and recovers the encryption shared key `shared_key` from the signature `sig`, the message sender identifier `sender_id`, the recipient `recipient_len`, the context `info`, the sender's public key `sender_pk`  and the recipent's secret key `recipient_sk`.

The shared key can then be used to decrypt the ciphertext.

The function returns `-1` or error, `0` on success.

```c
int crypto_signcrypt_tbsbr_verify_after(
    unsigned char       st[crypto_signcrypt_tbsbr_STATEBYTES],
    const unsigned char sig[crypto_signcrypt_tbsbr_SIGNBYTES],
    const unsigned char sender_pk[crypto_signcrypt_tbsbr_PUBLICKEYBYTES],
    const unsigned char *c, size_t c_len);
```

This function verifies that the signature `sig` is valid for the ciphertext `c` of length `c_len` bytes, the sender's public key `sender_pk` and the previously computed state `st`.

It returns `-1` is the verification failed, and `0` if it succeeded.

A typical unsigncryption sequence is thus:

- `crypto_signcrypt_tbsbr_verify_before()`
- decrypt with `shared_key`
- `crypto_signcrypt_tbsbr_verify_after()` - The return of that function *must* be checked.

## Public verification

The fact that a message was sent by a specific sender to a specific recipient in a specific context can also be publicly verified, even without giving the ability to decrypt the ciphertext.

```c
int crypto_signcrypt_tbsr_verify_public(
    const unsigned char sig[crypto_signcrypt_tbsbr_SIGNBYTES],
    const unsigned char *sender_id, size_t sender_id_len,
    const unsigned char *recipient_id, size_t recipient_id_len,
    const unsigned char *info, size_t info_len,
    const unsigned char sender_pk[crypto_signcrypt_tbsbr_PUBLICKEYBYTES],
    const unsigned char *c, size_t c_len);
```

This function verifies that `sig` is a valid signature for the ciphertext `c` of length `c_len` bytes, the sender identifier `sender_id`, the recipient `recipient_id`, the context `info`, and the sender's public key `sender_pk`.

# Constants

- `crypto_signcrypt_tbsbr_SECRETKEYBYTES` = 32
- `crypto_signcrypt_tbsbr_PUBLICKEYBYTES` = 32
- `crypto_signcrypt_tbsbr_SHAREDBYTES` = 32
- `crypto_signcrypt_tbsbr_SEEDBYTES` = 64
- `crypto_signcrypt_tbsbr_SIGNBYTES` = 64
- `crypto_signcrypt_tbsbr_STATEBYTES` = 512

## References

- _A Directly Public Verifiable Signcryption Scheme based on Elliptic Curves_ [[PDF]](https://arxiv.org/ftp/arxiv/papers/1002/1002.3316.pdf) (M. Toorani, A. Beheshti).
