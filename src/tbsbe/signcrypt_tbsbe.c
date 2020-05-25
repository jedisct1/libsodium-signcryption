#include "signcrypt_tbsbe.h"
#include <sodium.h>
#include <string.h>

typedef struct crypto_signcrypt_tbsbe_sign_state {
    crypto_generichash_state h;
    unsigned char            nonce[crypto_core_ed25519_SCALARBYTES];
    unsigned char            r[crypto_core_ed25519_BYTES];
    unsigned char            challenge[crypto_core_ed25519_SCALARBYTES];
} crypto_signcrypt_tbsbe_sign_state;

static int sc25519_is_canonical(const unsigned char s[crypto_core_ed25519_SCALARBYTES])
{
    static const unsigned char L[32] = { 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
                                         0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10 };
    unsigned char              c = 0, n = 1;
    unsigned int               i = 32;

    do {
        i--;
        c |= ((s[i] - L[i]) >> 8) & n;
        n &= ((s[i] ^ L[i]) - 1) >> 8;
    } while (i != 0);

    return (c != 0);
}

static void lp_update(crypto_generichash_state *h, const unsigned char *x, size_t x_len)
{
    unsigned char x_len_u8 = (unsigned char) x_len;

    crypto_generichash_update(h, &x_len_u8, 1);
    crypto_generichash_update(h, x, x_len);
}

int crypto_signcrypt_tbsbe_sign_before(
    unsigned char st_[crypto_signcrypt_tbsbe_STATEBYTES],
    unsigned char shared_key[crypto_signcrypt_tbsbe_SHAREDBYTES], const unsigned char *sender_id,
    size_t sender_id_len, const unsigned char *recipient_id, size_t recipient_id_len,
    const unsigned char *info, size_t info_len,
    const unsigned char sender_sk[crypto_core_ed25519_SCALARBYTES],
    const unsigned char recipient_pk[crypto_core_ed25519_BYTES], const unsigned char *m,
    size_t m_len)
{
    unsigned char                      rs[crypto_core_ed25519_NONREDUCEDSCALARBYTES];
    unsigned char                      ks[crypto_core_ed25519_SCALARBYTES];
    unsigned char                      kp[crypto_core_ed25519_BYTES];
    unsigned char                      noise[32];
    crypto_signcrypt_tbsbe_sign_state *st = (crypto_signcrypt_tbsbe_sign_state *) (void *) st_;

    if (sender_id_len > 0xff || recipient_id_len > 0xff || info_len > 0xff) {
        return -1;
    }
    randombytes_buf(noise, sizeof noise);
    crypto_generichash_init(&st->h, NULL, 0, crypto_core_ed25519_NONREDUCEDSCALARBYTES);
    crypto_generichash_update(&st->h, (const unsigned char *) "nonce", sizeof "nonce" - 1);
    crypto_generichash_update(&st->h, sender_sk, crypto_core_ed25519_SCALARBYTES);
    crypto_generichash_update(&st->h, recipient_pk, crypto_core_ed25519_BYTES);
    crypto_generichash_update(&st->h, noise, sizeof noise);
    crypto_generichash_update(&st->h, m, m_len);
    crypto_generichash_final(&st->h, rs, crypto_core_ed25519_NONREDUCEDSCALARBYTES);
    crypto_core_ed25519_scalar_reduce(st->nonce, rs);

    if (crypto_scalarmult_ed25519_base_noclamp(st->r, st->nonce) != 0) {
        return -1;
    }
    memcpy(rs, st->r, crypto_core_ed25519_SCALARBYTES);
    memset(rs + crypto_core_ed25519_SCALARBYTES, 0,
           crypto_core_ed25519_NONREDUCEDSCALARBYTES - crypto_core_ed25519_SCALARBYTES);
    crypto_core_ed25519_scalar_reduce(rs, rs);
    crypto_core_ed25519_scalar_mul(ks, rs, sender_sk);
    crypto_core_ed25519_scalar_add(ks, st->nonce, ks);
    if (crypto_scalarmult_ed25519_noclamp(kp, ks, recipient_pk) != 0) {
        return -1;
    }

    crypto_generichash_init(&st->h, NULL, 0, crypto_signcrypt_tbsbe_SHAREDBYTES);
    crypto_generichash_update(&st->h, (const unsigned char *) "shared_key",
                              sizeof "shared_key" - 1);
    crypto_generichash_update(&st->h, kp, sizeof kp);
    lp_update(&st->h, sender_id, sender_id_len);
    lp_update(&st->h, recipient_id, recipient_id_len);
    lp_update(&st->h, info, info_len);
    crypto_generichash_final(&st->h, shared_key, crypto_signcrypt_tbsbe_SHAREDBYTES);

    crypto_generichash_init(&st->h, NULL, 0, crypto_core_ed25519_NONREDUCEDSCALARBYTES);
    crypto_generichash_update(&st->h, (const unsigned char *) "sign_key", sizeof "sign_key" - 1);
    crypto_generichash_update(&st->h, st->r, crypto_core_ed25519_BYTES);
    lp_update(&st->h, sender_id, sender_id_len);
    lp_update(&st->h, recipient_id, recipient_id_len);
    lp_update(&st->h, info, info_len);

    return 0;
}

int crypto_signcrypt_tbsbe_sign_after(
    unsigned char       st_[crypto_signcrypt_tbsbe_STATEBYTES],
    unsigned char       sig[crypto_signcrypt_tbsbe_SIGNBYTES],
    const unsigned char sender_sk[crypto_core_ed25519_SCALARBYTES], const unsigned char *c,
    size_t c_len)
{
    unsigned char                      nonreduced[crypto_core_ed25519_NONREDUCEDSCALARBYTES];
    crypto_signcrypt_tbsbe_sign_state *st = (crypto_signcrypt_tbsbe_sign_state *) (void *) st_;
    unsigned char *                    r = sig, *s = sig + crypto_core_ed25519_BYTES;

    crypto_generichash_update(&st->h, c, c_len);
    crypto_generichash_final(&st->h, nonreduced, sizeof nonreduced);
    crypto_core_ed25519_scalar_reduce(st->challenge, nonreduced);

    crypto_core_ed25519_scalar_mul(s, st->challenge, sender_sk);
    crypto_core_ed25519_scalar_sub(s, s, st->nonce);
    memcpy(r, st->r, crypto_core_ed25519_BYTES);
    sodium_memzero(st, sizeof *st);

    return 0;
}

int crypto_signcrypt_tbsbe_verify_before(
    unsigned char       st_[crypto_signcrypt_tbsbe_STATEBYTES],
    unsigned char       shared_key[crypto_signcrypt_tbsbe_SHAREDBYTES],
    const unsigned char sig[crypto_signcrypt_tbsbe_SIGNBYTES], const unsigned char *sender_id,
    size_t sender_id_len, const unsigned char *recipient_id, size_t recipient_id_len,
    const unsigned char *info, size_t info_len,
    const unsigned char sender_pk[crypto_core_ed25519_BYTES],
    const unsigned char recipient_sk[crypto_core_ed25519_BYTES])
{
    unsigned char                      kp[crypto_core_ed25519_BYTES];
    unsigned char                      rs[crypto_core_ed25519_NONREDUCEDSCALARBYTES];
    crypto_signcrypt_tbsbe_sign_state *st = (crypto_signcrypt_tbsbe_sign_state *) (void *) st_;
    const unsigned char *              r = sig, *s = sig + crypto_core_ed25519_BYTES;

    if (sender_id_len > 0xff || recipient_id_len > 0xff || info_len > 0xff ||
        !sc25519_is_canonical(s)) {
        return -1;
    }
    memcpy(rs, r, crypto_core_ed25519_SCALARBYTES);
    memset(rs + crypto_core_ed25519_SCALARBYTES, 0,
           crypto_core_ed25519_NONREDUCEDSCALARBYTES - crypto_core_ed25519_SCALARBYTES);
    crypto_core_ed25519_scalar_reduce(rs, rs);
    if (crypto_scalarmult_ed25519_noclamp(kp, rs, sender_pk) != 0) {
        return -1;
    }
    crypto_core_ed25519_add(kp, r, kp);
    if (crypto_scalarmult_ed25519_noclamp(kp, recipient_sk, kp) != 0) {
        return -1;
    }

    crypto_generichash_init(&st->h, NULL, 0, crypto_signcrypt_tbsbe_SHAREDBYTES);
    crypto_generichash_update(&st->h, (const unsigned char *) "shared_key",
                              sizeof "shared_key" - 1);
    crypto_generichash_update(&st->h, kp, sizeof kp);
    lp_update(&st->h, sender_id, sender_id_len);
    lp_update(&st->h, recipient_id, recipient_id_len);
    lp_update(&st->h, info, info_len);
    crypto_generichash_final(&st->h, shared_key, crypto_signcrypt_tbsbe_SHAREDBYTES);

    crypto_generichash_init(&st->h, NULL, 0, crypto_core_ed25519_NONREDUCEDSCALARBYTES);
    crypto_generichash_update(&st->h, (const unsigned char *) "sign_key", sizeof "sign_key" - 1);
    crypto_generichash_update(&st->h, r, crypto_core_ed25519_BYTES);
    lp_update(&st->h, sender_id, sender_id_len);
    lp_update(&st->h, recipient_id, recipient_id_len);
    lp_update(&st->h, info, info_len);

    return 0;
}

int crypto_signcrypt_tbsbe_verify_after(unsigned char        st_[crypto_signcrypt_tbsbe_STATEBYTES],
                                        const unsigned char  sig[crypto_signcrypt_tbsbe_SIGNBYTES],
                                        const unsigned char  sender_pk[crypto_core_ed25519_BYTES],
                                        const unsigned char *c, size_t c_len)
{
    unsigned char                      check_expected[crypto_core_ed25519_BYTES];
    unsigned char                      check_found[crypto_core_ed25519_BYTES];
    unsigned char                      nonreduced[crypto_core_ed25519_NONREDUCEDSCALARBYTES];
    crypto_signcrypt_tbsbe_sign_state *st = (crypto_signcrypt_tbsbe_sign_state *) (void *) st_;
    const unsigned char *              r = sig, *s = sig + crypto_core_ed25519_BYTES;

    crypto_generichash_update(&st->h, c, c_len);
    crypto_generichash_final(&st->h, nonreduced, sizeof nonreduced);
    crypto_core_ed25519_scalar_reduce(st->challenge, nonreduced);

    crypto_scalarmult_ed25519_base_noclamp(check_expected, s);
    crypto_core_ed25519_add(check_expected, check_expected, r);

    if (crypto_scalarmult_ed25519_noclamp(check_found, st->challenge, sender_pk) != 0) {
        return -1;
    }
    if (sodium_memcmp(check_expected, check_found, crypto_core_ed25519_SCALARBYTES) != 0) {
        return -1;
    }
    return 0;
}

int crypto_signcrypt_tbsr_verify_public(const unsigned char  sig[crypto_signcrypt_tbsbe_SIGNBYTES],
                                        const unsigned char *sender_id, size_t sender_id_len,
                                        const unsigned char *recipient_id, size_t recipient_id_len,
                                        const unsigned char *info, size_t info_len,
                                        const unsigned char  sender_pk[crypto_core_ed25519_BYTES],
                                        const unsigned char *c, size_t c_len)
{
    crypto_signcrypt_tbsbe_sign_state st;
    const unsigned char *             r = sig, *s = sig + crypto_core_ed25519_BYTES;

    if (sender_id_len > 0xff || recipient_id_len > 0xff || info_len > 0xff ||
        !sc25519_is_canonical(s)) {
        return -1;
    }
    crypto_generichash_init(&st.h, NULL, 0, crypto_core_ed25519_NONREDUCEDSCALARBYTES);
    crypto_generichash_update(&st.h, (const unsigned char *) "sign_key", sizeof "sign_key" - 1);
    crypto_generichash_update(&st.h, r, crypto_core_ed25519_BYTES);
    lp_update(&st.h, sender_id, sender_id_len);
    lp_update(&st.h, recipient_id, recipient_id_len);
    lp_update(&st.h, info, info_len);

    return crypto_signcrypt_tbsbe_verify_after((unsigned char *) (void *) &st, sig, sender_pk, c,
                                               c_len);
}

void crypto_signcrypt_tbsbe_keygen(unsigned char pk[crypto_core_ed25519_BYTES],
                                   unsigned char sk[crypto_core_ed25519_SCALARBYTES])
{
    crypto_core_ed25519_scalar_random(sk);
    crypto_scalarmult_ed25519_base_noclamp(pk, sk);
}

void crypto_signcrypt_tbsbe_seed_keygen(unsigned char       pk[crypto_core_ed25519_BYTES],
                                        unsigned char       sk[crypto_core_ed25519_SCALARBYTES],
                                        const unsigned char seed[crypto_signcrypt_tbsbe_SEEDBYTES])
{
    crypto_core_ed25519_scalar_reduce(sk, seed);
    crypto_scalarmult_ed25519_base_noclamp(pk, sk);
}
