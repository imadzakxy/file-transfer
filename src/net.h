#ifndef NET_H
#define NET_H

#include <stddef.h>

int tcp_connect(const char *host, const char *port);
int tcp_listen(const char *port);
int send_all(int fd, const void *buf, size_t len);
int recv_all(int fd, void *buf, size_t len);

#endif
