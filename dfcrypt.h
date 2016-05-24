#ifndef DFCRYPT_H
#define DFCRYPT_H

/*
 * WARNING: This code has not received any security review and may contain fatal
 * flaws. I was extremely tired when I wrote it, so it it probably does. Don't
 * use it!
 */

#include <sodium.h>

// TODO: append _32 and _16 to the constants to make everything obvious.

#define DFCRYPT_KEY_BYTES           32
#define DFCRYPT_APPSEED_BYTES       16
#define DFCRYPT_INTERNAL_SALT_BYTES 32
#define DFCRYPT_INTERNAL_MAC_BYTES  32
#define DFCRYPT_CIPHERTEXT_GROWTH   (DFCRYPT_INTERNAL_SALT_BYTES + crypto_stream_chacha20_NONCEBYTES + DFCRYPT_INTERNAL_MAC_BYTES)
#define DFCRYPT_INTERNAL_AKEY_BYTES 32
#define DFCRYPT_INTERNAL_EKEY_BYTES 32

// TODO: benchmark comparisons to crypto_secretbox_easy
// TODO: make the appseed actually variable-length
// TODO: add additional data

typedef struct {
    unsigned char key[DFCRYPT_KEY_BYTES];
} dfcrypt_key_t;

typedef struct {
    unsigned char appseed[DFCRYPT_APPSEED_BYTES];
    size_t appseed_length;
} dfcrypt_application_seed_t;

typedef struct {
    unsigned char key[DFCRYPT_KEY_BYTES];
    unsigned char appseed[DFCRYPT_APPSEED_BYTES];
    size_t appseed_length;
} dfcrypt_state_t;

void dfcrypt_register_new_appseed(dfcrypt_application_seed_t *appseed_out);
void dfcrypt_random_key(dfcrypt_key_t *key_out);

// TODO: load and store of keys

void dfcrypt_init(
    dfcrypt_state_t *new_state_out,
    dfcrypt_application_seed_t *appseed,
    dfcrypt_key_t *key
);

void dfcrypt_encrypt(
    const dfcrypt_state_t *state,
    const unsigned char *ptxt,
    size_t ptxt_len_bytes,
    const unsigned char *message_number,
    unsigned char *ctxt_out
);

int dfcrypt_decrypt(
    const dfcrypt_state_t *state,
    const unsigned char *ctxt,
    size_t ctxt_len_bytes,
    const unsigned char *message_number,
    unsigned char *ptxt_out
) __attribute__ ((warn_unused_result));

#endif
