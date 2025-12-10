#ifndef WRAP_IO_H
#define WRAP_IO_H

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/* ----- system calls wrappers ----- */

/* Read(): read(2) wrapper robust against EINTR
 */
ssize_t Read(int fd, void *buf, size_t count);

/* Write(): write(2) wrapper robust against EINTR
 */
ssize_t Write(int fd, const void *buf, size_t count);

/* ----- OpenSSL functions wrappers ------ */

/* SSL_Read_ex(): SSL_read_ex(3) wrapper robust against EINTR */
ssize_t SSL_Read_ex(SSL *ssl, void *buf, size_t count);

/* SSL_Write_ex: SSL_write_ex(3) wrapper robust against EINTR */
ssize_t SSL_Write_ex(SSL *ssl, const void *buf, size_t count);

#endif
