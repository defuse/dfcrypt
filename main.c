#include <stdio.h>
#include <string.h>
#include <sodium.h>

#include "dfcrypt.h"

int main(int argc, char **argv)
{
    if (sodium_init() != 0) {
        return 1;
    }

    dfcrypt_application_seed_t appseed;
    dfcrypt_key_t key;
    dfcrypt_state_t dfcrypt;

    // TODO: make this persistent
    dfcrypt_register_new_appseed(&appseed);
    dfcrypt_random_key(&key);

    dfcrypt_init(&dfcrypt, &appseed, &key);

#define MESSAGE "Hello, world!\n"

    // TODO: rename it to overhead
    unsigned char ciphertext[strlen(MESSAGE) + DFCRYPT_CIPHERTEXT_GROWTH];
    unsigned char plaintext[strlen(MESSAGE)];

    dfcrypt_encrypt(
        &dfcrypt,
        MESSAGE,
        strlen(MESSAGE),
        NULL,
        ciphertext
    );

    if (dfcrypt_decrypt(
        &dfcrypt,
        ciphertext,
        sizeof(ciphertext),
        NULL,
        plaintext
    ) != 0) {
        return 1;
    }

    printf("%s", plaintext);
    return 0;
}
