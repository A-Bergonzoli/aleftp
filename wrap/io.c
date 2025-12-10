#include <openssl/ssl.h>

#include "wrap/io.h"
#include "lib/logging.h"

ssize_t Read(int fd, void *buf, size_t count)
{
    char *p = (char *)buf;
    size_t left = count;

    while (left > 0)
    {
        ssize_t nread = read(fd, p, left);
        if (nread < 0)
        {
            if (errno == EINTR)
                continue;
            return log_error("read error");
        }
        else if (nread == 0)
            break; /* EOF, done reading */

        left -= (size_t)nread;
        p += nread;
    }

    return (ssize_t)(count - left);
}

ssize_t SSL_Read_ex(SSL *ssl, void *buf, size_t count)
{
    char *p = (char *)buf;
    size_t left = count;

    while (left > 0)
    {
        int rc;
        size_t nread;

        rc = SSL_read_ex(ssl, p, left, &nread);
        if (rc <= 0)
        {
            int err = SSL_get_error(ssl, rc);
            // if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            //     continue; /* retry */
            if (err == SSL_ERROR_SYSCALL && errno == EINTR)
                continue; /* retry */
            if (err == SSL_ERROR_ZERO_RETURN)
                break; /* TLS connection closed cleanly, EOF*/
            return log_error("ssl_read_ex error");
        }

        left -= (size_t)nread;
        p += nread;
    }

    return (ssize_t)(count - left);
}

ssize_t Write(int fd, const void *buf, size_t count)
{
    const char *p = (const char *)buf;
    size_t left = count;

    while (left > 0)
    {
        ssize_t nw = write(fd, p, left);
        if (nw < 0)
        {
            if (errno == EINTR)
                continue;
            return log_error("write error");
        }

        left -= (size_t)nw;
        p += nw;
    }

    return (ssize_t)count;
}

ssize_t SSL_Write_ex(SSL *ssl, const void *buf, size_t count)
{
    const char *p = (const char *)buf;
    size_t left = count;

    while (left > 0)
    {
        int rc;
        size_t written;

        rc = SSL_write_ex(ssl, p, left, &written);
        if (rc <= 0)
        {
            int err = SSL_get_error(ssl, rc);
            // if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            //     continue; /* retry */
            if (err == SSL_ERROR_SYSCALL && errno == EINTR)
                continue; /* retry */
            return log_error("ssl_write_ex error");
        }

        left -= written;
        p += written;
    }

    return (ssize_t)count;
}
