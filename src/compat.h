#ifndef COMPAT_H
#define COMPAT_H

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <direct.h>
#include <fcntl.h>
#include <io.h>
#include <sys/types.h>

typedef int ft_socklen_t;
typedef SSIZE_T ft_ssize_t;
typedef SOCKADDR_STORAGE ft_sockaddr_storage;

#define close_socket(fd) closesocket((SOCKET)(fd))
#define sock_errno() WSAGetLastError()
#define SOCK_EINTR WSAEINTR
#define SOCK_EINPROGRESS WSAEINPROGRESS
#define ft_mkdir(path) _mkdir(path)
#define ft_strncasecmp _strnicmp
#define fseeko _fseeki64
#define ftello _ftelli64

static inline void sock_set_nonblocking(int fd, int on)
{
    u_long mode = on ? 1UL : 0UL;
    ioctlsocket((SOCKET)fd, FIONBIO, &mode);
}

static inline void sock_set_timeout(int fd, int sec)
{
    DWORD ms = (DWORD)sec * 1000UL;
    setsockopt((SOCKET)fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&ms,
               sizeof(ms));
    setsockopt((SOCKET)fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&ms,
               sizeof(ms));
}

static inline int net_init(void)
{
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa);
}

static inline void net_cleanup(void)
{
    WSACleanup();
}

static inline void ft_sleep(int sec)
{
    Sleep((DWORD)sec * 1000UL);
}

#else

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

typedef socklen_t ft_socklen_t;
typedef ssize_t ft_ssize_t;
typedef struct sockaddr_storage ft_sockaddr_storage;

#define close_socket(fd) close(fd)
#define sock_errno() errno
#define SOCK_EINTR EINTR
#define SOCK_EINPROGRESS EINPROGRESS
#define ft_mkdir(path) mkdir((path), 0700)
#define ft_strncasecmp strncasecmp

static inline void sock_set_nonblocking(int fd, int on)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return;
    fcntl(fd, F_SETFL, on ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK));
}

static inline void sock_set_timeout(int fd, int sec)
{
    struct timeval tv;
    tv.tv_sec = sec;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static inline int net_init(void)
{
    return 0;
}

static inline void net_cleanup(void)
{
}

static inline void ft_sleep(int sec)
{
    sleep((unsigned int)sec);
}

#endif

#endif
