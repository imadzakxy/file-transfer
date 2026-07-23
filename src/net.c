#include "net.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "compat.h"

int tcp_connect(const char *host, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *res;
    int fd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
        return -1;
    }

    for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0)
            continue;
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0)
            break;
        close_socket(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    if (fd < 0)
        perror("connect");
    return fd;
}

int tcp_listen(const char *port)
{
    struct addrinfo hints;
    struct addrinfo *res;
    int fd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    int rc = getaddrinfo(NULL, port, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
        return -1;
    }

    for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0)
            continue;

        int yes = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes,
                   sizeof(yes));
        if (p->ai_family == AF_INET6) {
            int no = 0;
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&no,
                       sizeof(no));
        }

        if (bind(fd, p->ai_addr, p->ai_addrlen) == 0 &&
            listen(fd, 4) == 0)
            break;

        close_socket(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    if (fd < 0)
        perror("bind/listen");
    return fd;
}

int send_all(int fd, const void *buf, size_t len)
{
    const unsigned char *p = (const unsigned char *)buf;
    size_t sent = 0;

    while (sent < len) {
        ft_ssize_t n = send(fd, (const char *)(p + sent), len - sent, 0);
        if (n < 0) {
            if (sock_errno() == SOCK_EINTR)
                continue;
            perror("send");
            return -1;
        }
        if (n == 0)
            return -1;
        sent += (size_t)n;
    }
    return 0;
}

int recv_all(int fd, void *buf, size_t len)
{
    unsigned char *p = (unsigned char *)buf;
    size_t got = 0;

    while (got < len) {
        ft_ssize_t n = recv(fd, (char *)(p + got), len - got, 0);
        if (n < 0) {
            if (sock_errno() == SOCK_EINTR)
                continue;
            perror("recv");
            return -1;
        }
        if (n == 0)
            return -1;
        got += (size_t)n;
    }
    return 0;
}
