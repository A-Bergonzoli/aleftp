#include <endian.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "include/protocol.h"
#include "lib/config.h"
#include "lib/logging.h"
#include "wrap/io.h"
#include "wrap/socket.h"

#define LISTENQ 256
#define FNAMESIZE 256
#define CMDSIZE FNAMESIZE + 8
#define BUFSIZE 4096

/* setup_ssl_ctx_server(): initialize SSL_CTX for server-side TLS.
 * Loads certificate and private key from the config paths.
 * Returns 0 on success, -1 on error. On success, caller owns *ctx and must free it.
 */
int setup_ssl_ctx_server(SSL_CTX **ctx, const char *cert_file, const char *key_file)
{
    SSL_CTX *newctx = NULL;

    if (ctx == NULL)
        return log_error("setup_ssl_ctx_server: NULL context pointer");

    newctx = SSL_CTX_new(TLS_server_method());
    if (newctx == NULL)
    {
        log_msg(LOG_ERROR, 0, "failed to create SSL_CTX");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /* load server certificate */
    if (SSL_CTX_use_certificate_file(newctx, cert_file, SSL_FILETYPE_PEM) <= 0)
    {
        log_msg(LOG_ERROR, 0, "failed to load certificate file: %s", cert_file);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(newctx);
        return -1;
    }

    /* load private key */
    if (SSL_CTX_use_PrivateKey_file(newctx, key_file, SSL_FILETYPE_PEM) <= 0)
    {
        log_msg(LOG_ERROR, 0, "failed to load private key file: %s", key_file);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(newctx);
        return -1;
    }

    /* verify that cert and key match */
    if (!SSL_CTX_check_private_key(newctx))
    {
        log_msg(LOG_ERROR, 0, "certificate and private key do not match");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(newctx);
        return -1;
    }

    /* restrict TLS version to TLSv1.2 or above */
    if (!SSL_CTX_set_min_proto_version(newctx, TLS1_2_VERSION))
    {
        log_msg(LOG_ERROR, 0, "failed to set minimum TLS protocol version");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(newctx);
        return -1;
    }

    /* disable client certificate verification (UNSAFE — only for testing) */
    SSL_CTX_set_verify(newctx, SSL_VERIFY_NONE, NULL);

    *ctx = newctx;
    return 0;
}

/* get_full_path(): resolve the absolute path of a file using realpath(3).
 *
 * The second argument to realpath() is deliberately set to NULL, so that
 * realpath() will dynamically allocate the buffer of up to PATH_MAX bytes
 * to hold the resolved pathname. This is done for robustness reasons (see
 * BUGS from realpath(3)).
 *
 * The downside is that the caller must remember to free() the returned string,
 * otherwise we leak memory. This is a reasonable tradeoff: the get a
 * malloc()'d buffer, you free() it.
 *
 * If the file does not exist, cannot be resolved, or the resolved path
 * escapes the root directory, then -1 is returned and errno is set.
 * In these scenarios, the allocated memory is taken care of before returning.
 */
int get_full_path(const char *filename, char **resolved, const char *root)
{
    char *rootreal = NULL;
    char *candidate = NULL;
    char *result = NULL;

    if (!filename || !root) {
        errno = EINVAL;
        return log_error("get_full_path: invalid file name");
    }

    rootreal = realpath(root, NULL);
    if (!rootreal)
        return log_error("get_full_path: realpath error resolving %s", root);

    if (filename[0] == '/')
        filename++;
    if (filename[0] == '\0') {
        free(rootreal);
        errno = EINVAL;
        return log_error("get_full_path: empty filename");
    }

    /* build candidate as: "<rootreal>/<filename>" */
    size_t root_len = strlen(root);
    size_t file_len = strlen(filename);
    size_t tot_len = root_len + 1 /* slash */ + file_len + 1 /* nul */;

    candidate = malloc(tot_len);
    if (!candidate) {
        free(rootreal);
        errno = ENOMEM;
        return log_error("get_full_path: could not allocate mem for candidate path");
    }

    int wrote = snprintf(candidate, tot_len, "%s/%s", rootreal, filename);
    if (wrote < 0 || (size_t)wrote >= tot_len) {
        free(candidate);
        free(rootreal);
        errno = ENAMETOOLONG;
        return log_error("get_full_path: path too long");
    }

    result = realpath(candidate, NULL);
    if (!result) {
        log_msg(LOG_ERROR, 1, "get_full_path: realpath error resolving %s", candidate);
        free(candidate);
        free(rootreal);
        return -1;
    }

    /* prevent path escape attempts */
    int ok = 0;
    size_t rootreal_len = strlen(rootreal);
    if (strncmp(result, rootreal, rootreal_len) == 0)
        if (result[rootreal_len] == '\0' || result[rootreal_len] == '/' )
            ok = 1;

    if (!ok) {
        free(result);
        free(candidate);
        free(rootreal);
        errno = EPERM;
        return log_error("get_full_path: resolved path escapes server root");
    }

    /* path is safe to use */
    *resolved = result;
    free(candidate);
    free(rootreal);
    return 0;
}

int handle_get(SSL *ssl, const char *request, const char *root)
{
    FILE *fp = NULL;
    char *fullpath = NULL;
    unsigned char buf[BUFSIZE];
    struct file_header hdr;
    long fsize;
    int rc = -1;

    log_msg(LOG_DBG, 0, "[handle_get] Got the request: '%s'", request);

    /* parse GET request */
    const char *fname = request + 4;
    while (*fname == ' ') fname++;

    if (get_full_path(fname, &fullpath, root) != 0) {
        hdr.status = errno;
        hdr.length = 0;
        if (SSL_Write_ex(ssl, &hdr, sizeof(hdr)) < 0)
            log_msg(LOG_ERROR, 0, "SSL write error (sending error header)");

        goto cleanup;
    }

    /* open file */
    fp = fopen(fullpath, "rb");
    if (!fp) {
        hdr.status = errno;
        hdr.length = 0;
        if (SSL_Write_ex(ssl, &hdr, sizeof(hdr)) < 0)
            log_msg(LOG_ERROR, 0, "SSL write error (sending error header)");

        goto cleanup;
    }

    /* prepare and send header */
    if (fseek(fp, 0, SEEK_END) != 0) {
        hdr.status = errno;
        hdr.length = 0;
        if (SSL_Write_ex(ssl, &hdr, sizeof(hdr)) < 0)
            log_msg(LOG_ERROR, 0, "SSL write error (sending error header)");

        rc = -1;
        goto cleanup;
    }
    fsize = ftell(fp);
    rewind(fp);

    hdr.length = htobe64((uint64_t)fsize);
    hdr.status = 0;
    if (SSL_Write_ex(ssl, &hdr, sizeof(hdr)) < 0) {
        log_msg(LOG_ERROR, 0, "SSL write error (sending file header)");
        goto cleanup;
    }

    /* send file */
    size_t n;
    while ((n = fread(buf, 1, BUFSIZE, fp)) > 0) {
        if (SSL_Write_ex(ssl, buf, n) < 0) {
            log_msg(LOG_ERROR, 0, "SSL write error (sending file data)");
            goto cleanup;
        }
    }

    rc = 0;

cleanup:
    if (fp) {
        log_msg(LOG_DBG, 0, "[cleanup] fclose(fp)");
        fclose(fp);
        fp = NULL;
    }
    if (fullpath) {
        log_msg(LOG_DBG, 0, "[cleanup] free(fullpath)");
        free(fullpath);
        fullpath = NULL;
    }
    return rc;
}

int main(int argc, char **argv)
{
    int listenfd, connfd;
    struct sockaddr_in srvaddr;
    char cmd[CMDSIZE];
    SSL_CTX *ssl_ctx;
    SSL *ssl;

    if (argc != 2)
        log_fatal("usage: %s <config path>\n", argv[0]);

    Config cfg = {0};
    const char *cfg_file_name = argv[1];
    if (load_config(cfg_file_name, &cfg) != 0)
        log_fatal("error loading configuration");

    log_msg(LOG_DBG, 0, "root:_%s", cfg.srv_root);

    if (setup_ssl_ctx_server(&ssl_ctx, "server.crt", "server.key") != 0)
        log_fatal("failed to set up SSL context");

    /* create listening socket */
    listenfd = Socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0)
        log_fatal("failed to create listening socket");

    memset(&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sin_family = AF_INET;
    srvaddr.sin_port = htons(cfg.srv_port);
    srvaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (Bind(listenfd, (struct sockaddr *)&srvaddr, sizeof(srvaddr)) < 0)
        log_fatal("failed to bind listening socket");
    if (Listen(listenfd, LISTENQ) < 0)
        log_fatal("failed to convert listening socket");

    log_msg(LOG_INFO, 0, "Server listening on port %d (TLS required)", cfg.srv_port);

    /* accept incoming requests and dispatch them to their handlers */
    while (1)
    {
        if ((connfd = accept(listenfd, NULL, NULL)) < 0)
        {
            if (errno == EINTR)
                continue;
            else
            {
                log_msg(LOG_ERROR, 1, "accept error");
                continue;
            }
        }
        log_msg(LOG_DBG, 0, "connection accepted");

        /* attach socket to SSL object */
        ssl = SSL_new(ssl_ctx);
        if (ssl == NULL)
        {
            log_msg(LOG_ERROR, 0, "failed to create SSL object");
            Close(connfd);
            continue;
        }
        if (!SSL_set_fd(ssl, connfd))
        {
            log_msg(LOG_ERROR, 0, "SSL_set_fd failed");
            SSL_free(ssl);
            Close(connfd);
            continue;
        }

        /* perform TLS handshake */
        if (SSL_accept(ssl) <= 0) {
            log_msg(LOG_WARN, 0, "TLS handshake failed");
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            Close(connfd);
            continue;
        }

        /* read request via SSL */
        ssize_t n = SSL_Read_ex(ssl, cmd, sizeof(cmd) - 1);
        if (n <= 0) {
            log_msg(LOG_WARN, 0, "SSL read error (no request)");
            SSL_free(ssl);
            Close(connfd);
            continue;
        }
        cmd[n] = 0;
        log_msg(LOG_DBG, 0, "read %zd bytes from socket: '%s'", n, cmd);

        if (strncmp(cmd, "GET ", 4) == 0)
        {
            log_msg(LOG_DBG, 0, "dispatching...");
            if (handle_get(ssl, cmd, cfg.srv_root) == -1)
                log_msg(LOG_WARN, 1, "handle_get returned -1");
            log_msg(LOG_INFO, 0, "GET completed.");
        }

        /* cleanup */
        SSL_shutdown(ssl);
        SSL_free(ssl);
        Close(connfd);
    }

    SSL_CTX_free(ssl_ctx);
    return 0;
}
