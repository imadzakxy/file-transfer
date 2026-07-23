#include "crypto.h"

#include <string.h>

int ft_derive_key(const char *passphrase, const unsigned char *salt,
                  unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
    if (sodium_init() < 0)
        return -1;

    if (crypto_pwhash(key, crypto_secretstream_xchacha20poly1305_KEYBYTES,
                      passphrase, strlen(passphrase), salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0)
        return -1;

    return 0;
}
