#ifndef CRYPTO_H
#define CRYPTO_H

#include <sodium.h>

int ft_derive_key(const char *passphrase, const unsigned char *salt,
                  unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]);

#endif
