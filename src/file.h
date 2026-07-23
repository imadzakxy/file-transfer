#ifndef FILE_H
#define FILE_H

int ft_send(int fd, const char *path, const char *passphrase);
int ft_receive(int fd, const char *outdir, const char *passphrase);

#endif
