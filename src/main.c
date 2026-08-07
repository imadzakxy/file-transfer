#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "compat.h"
#include "file.h"
#include "net.h"

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage:\n"
            "  %s send <host> <port> <file> --pass <passphrase>\n"
            "  %s receive <port> <outdir> --pass <passphrase> [--multi]\n",
            argv0, argv0);
}

static const char *find_pass(int argc, char **argv)
{
    for (int i = 2; i + 1 < argc; i++) {
        if (strcmp(argv[i], "--pass") == 0)
            return argv[i + 1];
    }
    return NULL;
}

static int has_flag(int argc, char **argv, const char *flag)
{
    for (int i = 2; i < argc; i++)
        if (strcmp(argv[i], flag) == 0)
            return 1;
    return 0;
}

int main(int argc, char **argv)
{
    if (net_init() != 0) {
        fprintf(stderr, "winsock init failed\n");
        return 1;
    }

    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }

    const char *pass = find_pass(argc, argv);
    if (pass == NULL) {
        fprintf(stderr, "error: --pass is required\n");
        usage(argv[0]);
        return 2;
    }

    if (strcmp(argv[1], "send") == 0) {
        if (argc < 5) {
            usage(argv[0]);
            return 2;
        }

        int fd = tcp_connect(argv[2], argv[3]);
        if (fd < 0)
            return 1;

        int rc = ft_send(fd, argv[4], pass);
        close_socket(fd);
        return rc == 0 ? 0 : 1;
    }

    if (strcmp(argv[1], "receive") == 0) {
        if (argc < 4) {
            usage(argv[0]);
            return 2;
        }

        int multi = has_flag(argc, argv, "--multi");
        int server = tcp_listen(argv[2]);
        if (server < 0)
            return 1;

        fprintf(stderr, "listening on port %s\n", argv[2]);
        for (;;) {
            int client = accept(server, NULL, NULL);
            if (client < 0) {
                if (sock_errno() == SOCK_EINTR)
                    continue;
                perror("accept");
                break;
            }

            int rc = ft_receive(client, argv[3], pass);
            close_socket(client);
            if (rc != 0)
                fprintf(stderr, "transfer failed\n");
            if (!multi)
                break;
        }

        close_socket(server);
        return 0;
    }

    usage(argv[0]);
    return 2;
}
