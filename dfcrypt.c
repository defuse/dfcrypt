#include <string.h>
#include <sodium.h>
#include <assert.h>

/*
 * WARNING: This code has not received any security review and may contain fatal
 * flaws. I was extremely tired when I wrote it, so it it probably does. Don't
 * use it!
 */

#include "dfcrypt.h"

void dfcrypt_register_new_appseed(dfcrypt_application_seed_t *appseed_out)
{
    randombytes_buf(appseed_out->appseed, DFCRYPT_APPSEED_BYTES);
    appseed_out->appseed_length = DFCRYPT_APPSEED_BYTES;
}

void dfcrypt_random_key(dfcrypt_key_t *key_out)
{
    randombytes_buf(key_out->key, DFCRYPT_KEY_BYTES);
}

void dfcrypt_init(
    dfcrypt_state_t *new_state_out,
    dfcrypt_application_seed_t *appseed,
    dfcrypt_key_t *key
)
{
    memcpy(new_state_out->key, key->key, DFCRYPT_KEY_BYTES);
    memcpy(new_state_out->appseed, appseed->appseed, DFCRYPT_APPSEED_BYTES);
    new_state_out->appseed_length = DFCRYPT_APPSEED_BYTES;
}

void dfcrypt_encrypt(
    const dfcrypt_state_t *state,
    const unsigned char *ptxt,
    size_t ptxt_len_bytes,
    const unsigned char *message_number,
    unsigned char *ctxt_out
)
{
    unsigned char *salt = ctxt_out;
    unsigned char *nonce = ctxt_out + DFCRYPT_INTERNAL_SALT_BYTES;
    unsigned char *encrypted = nonce + crypto_stream_chacha20_NONCEBYTES;
    unsigned char *mac = encrypted + ptxt_len_bytes;

    unsigned char keys[DFCRYPT_INTERNAL_AKEY_BYTES + DFCRYPT_INTERNAL_EKEY_BYTES];
    const unsigned char *akey = keys;
    const unsigned char *ekey = keys + DFCRYPT_INTERNAL_AKEY_BYTES;

    /* Sample a random salt and nonce. */
    randombytes_buf(salt, DFCRYPT_INTERNAL_SALT_BYTES);
    randombytes_buf(nonce, crypto_stream_chacha20_NONCEBYTES);

    /* Derive the authentication and encryption keys. */
    assert(sizeof(keys) == 64);
    crypto_generichash_blake2b_salt_personal(
        keys,                   /* output */
        sizeof(keys),           /* output length */
        state->appseed,         /* input */
        state->appseed_length,  /* input length */
        state->key,             /* key */
        DFCRYPT_KEY_BYTES,      /* key length */
        salt,                   /* salt */
        message_number          /* personalization (can be NULL) */
    );

    /* Encrypt the ciphertext. */
    crypto_stream_chacha20_xor(
        encrypted,      /* output */
        ptxt,           /* input */
        ptxt_len_bytes, /* input length */
        nonce,          /* nonce */
        ekey            /* key */
    );

    /* Append the MAC. */
    crypto_generichash_blake2b(
        mac,                            /* output */
        DFCRYPT_INTERNAL_MAC_BYTES,     /* output length */
        ctxt_out,                       /* input */
        DFCRYPT_INTERNAL_SALT_BYTES +
        crypto_stream_chacha20_NONCEBYTES + ptxt_len_bytes, /* input length */
        akey,                           /* key */
        DFCRYPT_INTERNAL_AKEY_BYTES     /* key length */
    );
}

int dfcrypt_decrypt(
    const dfcrypt_state_t *state,
    const unsigned char *ctxt,
    size_t ctxt_len_bytes,
    const unsigned char *message_number,
    unsigned char *ptxt_out
)
{
    const unsigned char *salt = ctxt;
    const unsigned char *nonce = ctxt + DFCRYPT_INTERNAL_SALT_BYTES;
    const unsigned char *encrypted = nonce + crypto_stream_chacha20_NONCEBYTES;
    const unsigned char *ciphertext_mac = ctxt + ctxt_len_bytes - DFCRYPT_INTERNAL_MAC_BYTES;

    unsigned char keys[DFCRYPT_INTERNAL_AKEY_BYTES + DFCRYPT_INTERNAL_EKEY_BYTES];
    const unsigned char *akey = keys;
    const unsigned char *ekey = keys + DFCRYPT_INTERNAL_AKEY_BYTES;

    unsigned char computed_mac[DFCRYPT_INTERNAL_MAC_BYTES];

    /* Derive the authentication and encryption keys. */
    assert(sizeof(keys) == 64);
    crypto_generichash_blake2b_salt_personal(
        keys,                   /* output */
        sizeof(keys),           /* output length */
        state->appseed,         /* input */
        state->appseed_length,  /* input length */
        state->key,             /* key */
        DFCRYPT_KEY_BYTES,      /* key length */
        salt,                   /* salt */
        message_number          /* personalization (can be NULL) */
    );

    /* Re-compute the MAC. */
    crypto_generichash_blake2b(
        computed_mac,                                   /* output */
        DFCRYPT_INTERNAL_MAC_BYTES,                     /* output length */
        ctxt,                                           /* input */
        ctxt_len_bytes - DFCRYPT_INTERNAL_MAC_BYTES,    /* input length */
        akey,                                           /* key */
        DFCRYPT_INTERNAL_AKEY_BYTES                     /* key length */
    );

    /* Check the MAC. */
    if (sodium_memcmp(computed_mac, ciphertext_mac, DFCRYPT_INTERNAL_MAC_BYTES) != 0) {
        return -1;
    }

    /* Decrypt the plaintext. */
    crypto_stream_chacha20_xor(
        ptxt_out,                                   /* output */
        encrypted,                                  /* input */
        ctxt_len_bytes - DFCRYPT_CIPHERTEXT_GROWTH, /* input length */
        nonce,                                      /* nonce */
        ekey                                        /* key */
    );

    return 0;
}
