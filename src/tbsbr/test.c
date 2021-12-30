#include "signcrypt_tbsbr.h"
#include <sodium.h>
#include <stdio.h>

int main(void)
{
    unsigned char sender_pk[crypto_signcrypt_tbsbr_PUBLICKEYBYTES];
    unsigned char sender_sk[crypto_signcrypt_tbsbr_SECRETKEYBYTES];
    unsigned char recipient_pk[crypto_signcrypt_tbsbr_PUBLICKEYBYTES];
    unsigned char recipient_sk[crypto_signcrypt_tbsbr_SECRETKEYBYTES];
    unsigned char crypt_key[crypto_signcrypt_tbsbr_SHAREDBYTES];
    unsigned char sig[crypto_signcrypt_tbsbr_SIGNBYTES];
    unsigned char st[crypto_signcrypt_tbsbr_STATEBYTES];
    unsigned char m[4] = { 't', 'e', 's', 't' };
    unsigned char c[4 + crypto_secretbox_MACBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];

    /* in this example, we simply use the encryption nonce as the info */
    const unsigned char *info     = nonce;
    size_t               info_len = sizeof nonce;

    if (sodium_init() != 0) {
        return 1;
    }
    crypto_signcrypt_tbsbr_keygen(sender_pk, sender_sk);
    crypto_signcrypt_tbsbr_keygen(recipient_pk, recipient_sk);
    randombytes_buf(nonce, sizeof nonce);

    /* sender-side */

    if (crypto_signcrypt_tbsbr_sign_before(st, crypt_key, (const unsigned char *) "sender",
                                           sizeof "sender" - 1, (const unsigned char *) "recipient",
                                           sizeof "recipient" - 1, info, info_len, sender_sk,
                                           recipient_pk, m, sizeof m) != 0 ||
        crypto_secretbox_easy(c, m, sizeof m, nonce, crypt_key) != 0 ||
        crypto_signcrypt_tbsbr_sign_after(st, sig, sender_sk, c, sizeof c) != 0) {
        return 1;
    }

    /* recipient-side */

    if (crypto_signcrypt_tbsbr_verify_before(
            st, crypt_key, sig, (const unsigned char *) "sender", sizeof "sender" - 1,
            (const unsigned char *) "recipient", sizeof "recipient" - 1, info, info_len, sender_pk,
            recipient_sk) != 0 ||
        crypto_secretbox_open_easy(m, c, sizeof c, nonce, crypt_key) != 0 ||
        crypto_signcrypt_tbsbr_verify_after(st, sig, sender_pk, c, sizeof c) != 0) {
        return 1;
    }

    /* the sender can also be publicly verified */

    if (crypto_signcrypt_tbsbr_verify_public(
            sig, (const unsigned char *) "sender", sizeof "sender" - 1,
            (const unsigned char *) "recipient", sizeof "recipient" - 1, info, info_len, sender_pk,
            c, sizeof c) != 0) {
        return 1;
    }

    return 0;
}
