#ifndef signcrypt_tbsbr_H
#define signcrypt_tbsbr_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>

#define crypto_signcrypt_tbsbr_SECRETKEYBYTES 32
#define crypto_signcrypt_tbsbr_PUBLICKEYBYTES 32
#define crypto_signcrypt_tbsbr_SHAREDBYTES 32
#define crypto_signcrypt_tbsbr_SEEDBYTES 64
#define crypto_signcrypt_tbsbr_SIGNBYTES (32 + 32)
#define crypto_signcrypt_tbsbr_STATEBYTES 512

int crypto_signcrypt_tbsbr_sign_before(
    unsigned char st[crypto_signcrypt_tbsbr_STATEBYTES],
    unsigned char shared_key[crypto_signcrypt_tbsbr_SHAREDBYTES], const unsigned char *sender_id,
    size_t sender_id_len, const unsigned char *recipient_id, size_t recipient_id_len,
    const unsigned char *info, size_t info_len,
    const unsigned char sender_sk[crypto_signcrypt_tbsbr_SECRETKEYBYTES],
    const unsigned char recipient_pk[crypto_signcrypt_tbsbr_PUBLICKEYBYTES], const unsigned char *m,
    size_t m_len);

int crypto_signcrypt_tbsbr_sign_after(
    unsigned char       st[crypto_signcrypt_tbsbr_STATEBYTES],
    unsigned char       sig[crypto_signcrypt_tbsbr_SIGNBYTES],
    const unsigned char sender_sk[crypto_signcrypt_tbsbr_SECRETKEYBYTES], const unsigned char *c,
    size_t c_len);

int crypto_signcrypt_tbsbr_verify_before(
    unsigned char       st[crypto_signcrypt_tbsbr_STATEBYTES],
    unsigned char       shared_key[crypto_signcrypt_tbsbr_SHAREDBYTES],
    const unsigned char sig[crypto_signcrypt_tbsbr_SIGNBYTES], const unsigned char *sender_id,
    size_t sender_id_len, const unsigned char *recipient_id, size_t recipient_id_len,
    const unsigned char *info, size_t info_len,
    const unsigned char sender_pk[crypto_signcrypt_tbsbr_PUBLICKEYBYTES],
    const unsigned char recipient_sk[crypto_signcrypt_tbsbr_PUBLICKEYBYTES]);

int crypto_signcrypt_tbsbr_verify_after(
    unsigned char       st[crypto_signcrypt_tbsbr_STATEBYTES],
    const unsigned char sig[crypto_signcrypt_tbsbr_SIGNBYTES],
    const unsigned char sender_pk[crypto_signcrypt_tbsbr_PUBLICKEYBYTES], const unsigned char *c,
    size_t c_len);

int crypto_signcrypt_tbsr_verify_public(
    const unsigned char sig[crypto_signcrypt_tbsbr_SIGNBYTES], const unsigned char *sender_id,
    size_t sender_id_len, const unsigned char *recipient_id, size_t recipient_id_len,
    const unsigned char *info, size_t info_len,
    const unsigned char sender_pk[crypto_signcrypt_tbsbr_PUBLICKEYBYTES], const unsigned char *c,
    size_t c_len);

void crypto_signcrypt_tbsbr_keygen(unsigned char pk[crypto_signcrypt_tbsbr_PUBLICKEYBYTES],
                                   unsigned char sk[crypto_signcrypt_tbsbr_SECRETKEYBYTES]);

void crypto_signcrypt_tbsbr_seed_keygen(unsigned char pk[crypto_signcrypt_tbsbr_PUBLICKEYBYTES],
                                        unsigned char sk[crypto_signcrypt_tbsbr_SECRETKEYBYTES],
                                        const unsigned char seed[crypto_signcrypt_tbsbr_SEEDBYTES]);

#ifdef __cplusplus
}
#endif

#endif
