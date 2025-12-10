#include "socket.h"

int Socket(int domain, int type, int protocol)
{
    int fd;
    if ((fd = socket(domain, type, protocol)) < 0)
        return log_error("socket error");
    return fd;
}

int Connect(int fd, const struct sockaddr *srvaddr, socklen_t addrlen)
{
    if (connect(fd, srvaddr, addrlen) < 0)
        return log_error("connect error");
    return 0;
}

int Bind(int fd, const struct sockaddr *myaddr, socklen_t addrlen)
{
    if (bind(fd, myaddr, addrlen) < 0)
        return log_error("bind error");
    return 0;
}

int Listen(int fd, int backlog)
{
    if (listen(fd, backlog) < 0)
        return log_error("listen error");
    return 0;
}

int Accept(int fd, struct sockaddr *cliaddr, socklen_t *addrlen)
{
    int nfd;
    if ((nfd = accept(fd, cliaddr, addrlen)) < 0)
        return log_error("accept error");
    return nfd;
}

int Close(int fd)
{
    if (close(fd) == -1)
        return log_error("close error");
    return 0;
}

int Inet_pton(int af, const char *srcptr, void *dstptr)
{
    int rc;
    if ((rc = inet_pton(af, srcptr, dstptr)) < 0)
        return log_error("inet_pton error");
    else if (rc == 0)
        return log_error("inet_pton error: invalid 'presentation' format");
    return 0;
}

const char *
Inet_ntop(int af, const void *srcptr, char *dstptr, size_t len)
{
    const char *ptr;
    if ((ptr = inet_ntop(af, srcptr, dstptr, len)) == NULL)
    {
        log_msg(LOG_ERROR, 1, "inet_ntop error");
        return NULL;
    }
    return ptr;
}
