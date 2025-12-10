#ifndef _WRAP_SOCKET_H
#define _WRAP_SOCKET_H

#include "lib/logging.h"
#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>

// clang-format off

/* --- socket functions --- */
int  Socket(int domain, int type, int protocol);
int  Connect(int fd, const struct sockaddr *srvaddr, socklen_t addrlen);
int  Bind(int fd, const struct sockaddr *myaddr, socklen_t addrlen);
int  Listen(int fd, int backlog);
int  Accept(int fd, struct sockaddr *cliaddr, socklen_t *addrlen);
int  Close(int fd);

/* --- address conversion --- */
int         Inet_pton(int af, const char *srcptr, void *dstptr);
const char *Inet_ntop(int af, const void *srcptr, char *dstptr, size_t len);

#endif
