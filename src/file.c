#include "file.h"

#include <errno.h>
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "compat.h"
#include "crypto.h"
#include "net.h"
#include "protocol.h"

static void put_u32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)(v & 0xff);
}

static uint32_t get_u32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void put_u64(unsigned char *p, uint64_t v)
{
    for (int i = 7; i >= 0; i--) {
        p[i] = (unsigned char)(v & 0xff);
        v >>= 8;
    }
}

static uint64_t get_u64(const unsigned char *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v = (v << 8) | p[i];
    return v;
}

static void progress(const char *label, uint64_t done, uint64_t total)
{
    int pct = total > 0 ? (int)((done * 100) / total) : 100;
    if (pct > 100)
        pct = 100;
    int filled = pct / 2;

    fprintf(stderr, "\r%s [", label);
    for (int i = 0; i < 50; i++)
        fputc(i < filled ? '#' : '-', stderr);
    fprintf(stderr, "] %3d%% (%llu/%llu)", pct, (unsigned long long)done,
            (unsigned long long)total);
}

static int send_chunk(int fd, const unsigned char *data, size_t len)
{
    unsigned char hdr[4];
    put_u32(hdr, (uint32_t)len);
    if (send_all(fd, hdr, sizeof(hdr)) != 0)
        return -1;
    return send_all(fd, data, len);
}

static int recv_chunk(int fd, unsigned char *buf, size_t cap, size_t *out_len)
{
    unsigned char hdr[4];
    if (recv_all(fd, hdr, sizeof(hdr)) != 0)
        return -1;

    uint32_t len = get_u32(hdr);
    if (len > cap) {
        fprintf(stderr, "chunk too large: %u\n", len);
        return -1;
    }
    if (recv_all(fd, buf, len) != 0)
        return -1;

    *out_len = len;
    return 0;
}

static const char *base_name(const char *path)
{
    const char *a = strrchr(path, '/');
    const char *b = strrchr(path, '\\');
    const char *p = a > b ? a : b;
    return p != NULL ? p + 1 : path;
}

int ft_send(int fd, const char *path, const char *passphrase)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return -1;
    }

    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        perror("fopen");
        return -1;
    }

    if (fseeko(f, 0, SEEK_END) != 0) {
        perror("fseek");
        fclose(f);
        return -1;
    }
    long long size = (long long)ftello(f);
    if (size < 0) {
        perror("ftell");
        fclose(f);
        return -1;
    }
    rewind(f);

    const char *name = base_name(path);
    size_t name_len = strlen(name);
    if (name_len > 255)
        name_len = 255;

    unsigned char salt[FT_SALT_LEN];
    randombytes_buf(salt, sizeof(salt));

    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    if (ft_derive_key(passphrase, salt, key) != 0) {
        fprintf(stderr, "key derivation failed\n");
        fclose(f);
        return -1;
    }

    if (send_all(fd, FT_MAGIC, 4) != 0 ||
        send_all(fd, salt, sizeof(salt)) != 0) {
        fclose(f);
        return -1;
    }

    crypto_secretstream_xchacha20poly1305_state st;
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
    if (send_all(fd, header, sizeof(header)) != 0) {
        fclose(f);
        return -1;
    }

    unsigned char meta[4 + 255 + 8];
    put_u32(meta, (uint32_t)name_len);
    memcpy(meta + 4, name, name_len);
    put_u64(meta + 4 + name_len, (uint64_t)size);
    size_t meta_len = 4 + name_len + 8;

    unsigned char enc[FT_CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned long long enc_len = 0;

    if (crypto_secretstream_xchacha20poly1305_push(
            &st, enc, &enc_len, meta, meta_len, NULL, 0,
            crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) != 0 ||
        send_chunk(fd, enc, (size_t)enc_len) != 0) {
        fclose(f);
        return -1;
    }

    unsigned char in[FT_CHUNK_SIZE];
    size_t n;
    uint64_t total = 0;

    while ((n = fread(in, 1, sizeof(in), f)) > 0) {
        if (crypto_secretstream_xchacha20poly1305_push(
                &st, enc, &enc_len, in, n, NULL, 0,
                crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) != 0) {
            fclose(f);
            return -1;
        }
        if (send_chunk(fd, enc, (size_t)enc_len) != 0) {
            fclose(f);
            return -1;
        }
        total += n;
        progress("sending", total, (uint64_t)size);
    }

    if (ferror(f)) {
        perror("fread");
        fclose(f);
        return -1;
    }

    if (crypto_secretstream_xchacha20poly1305_push(
            &st, enc, &enc_len, NULL, 0, NULL, 0,
            crypto_secretstream_xchacha20poly1305_TAG_FINAL) != 0 ||
        send_chunk(fd, enc, (size_t)enc_len) != 0) {
        fclose(f);
        return -1;
    }

    progress("sending", (uint64_t)size, (uint64_t)size);
    fputc('\n', stderr);
    fclose(f);
    fprintf(stderr, "sent %s (%lld bytes)\n", name, (long long)size);
    return 0;
}

static int safe_name(const char *name)
{
    if (name[0] == '\0' || strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
        return 0;
    if (strchr(name, '/') != NULL || strchr(name, '\\') != NULL)
        return 0;
    return 1;
}

int ft_receive(int fd, const char *outdir, const char *passphrase)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return -1;
    }

    unsigned char magic[4];
    unsigned char salt[FT_SALT_LEN];
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    if (recv_all(fd, magic, sizeof(magic)) != 0) {
        fprintf(stderr, "connection closed\n");
        return -1;
    }
    if (memcmp(magic, FT_MAGIC, 4) != 0) {
        fprintf(stderr, "bad protocol magic\n");
        return -1;
    }
    if (recv_all(fd, salt, sizeof(salt)) != 0 ||
        recv_all(fd, header, sizeof(header)) != 0) {
        fprintf(stderr, "connection closed\n");
        return -1;
    }

    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    if (ft_derive_key(passphrase, salt, key) != 0) {
        fprintf(stderr, "key derivation failed\n");
        return -1;
    }

    crypto_secretstream_xchacha20poly1305_state st;
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
        fprintf(stderr, "invalid stream header\n");
        return -1;
    }

    unsigned char enc[FT_CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char plain[FT_CHUNK_SIZE];
    unsigned long long plain_len = 0;
    unsigned char tag = 0;
    size_t enc_len = 0;

    if (recv_chunk(fd, enc, sizeof(enc), &enc_len) != 0 ||
        crypto_secretstream_xchacha20poly1305_pull(&st, plain, &plain_len, &tag,
                                                   enc, enc_len, NULL, 0) != 0) {
        fprintf(stderr, "decryption failed (wrong passphrase?)\n");
        return -1;
    }

    if (plain_len < 12) {
        fprintf(stderr, "invalid metadata\n");
        return -1;
    }

    uint32_t name_len = get_u32(plain);
    if (name_len == 0 || name_len > 255 || name_len + 12 > plain_len) {
        fprintf(stderr, "invalid file name\n");
        return -1;
    }

    char name[256];
    memcpy(name, plain + 4, name_len);
    name[name_len] = '\0';
    uint64_t size = get_u64(plain + 4 + name_len);

    if (!safe_name(name)) {
        fprintf(stderr, "unsafe file name rejected: %s\n", name);
        return -1;
    }

    if (ft_mkdir(outdir) != 0 && errno != EEXIST) {
        perror("mkdir");
        return -1;
    }

    char outpath[4096];
    snprintf(outpath, sizeof(outpath), "%s/%s", outdir, name);

    FILE *f = fopen(outpath, "wb");
    if (f == NULL) {
        perror("fopen");
        return -1;
    }

    uint64_t total = 0;
    for (;;) {
        if (recv_chunk(fd, enc, sizeof(enc), &enc_len) != 0)
            break;

        if (crypto_secretstream_xchacha20poly1305_pull(&st, plain, &plain_len,
                                                       &tag, enc, enc_len,
                                                       NULL, 0) != 0) {
            fprintf(stderr, "decryption failed\n");
            fclose(f);
            return -1;
        }

        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL)
            break;

        if (plain_len > 0 && fwrite(plain, 1, (size_t)plain_len, f) != plain_len) {
            perror("fwrite");
            fclose(f);
            return -1;
        }
        total += plain_len;
        progress("receiving", total, size);
    }

    progress("receiving", size, size);
    fputc('\n', stderr);
    fclose(f);

    if (total != size)
        fprintf(stderr, "warning: size mismatch (%llu/%llu)\n",
                (unsigned long long)total, (unsigned long long)size);

    fprintf(stderr, "received %s -> %s (%llu bytes)\n", name, outpath,
            (unsigned long long)total);
    return 0;
}
