#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "include/protocol.h"
#include "lib/config.h"
#include "lib/logging.h"
#include "wrap/io.h"
#include "wrap/socket.h"

#define FNAMESIZE 256
#define CMDSIZE FNAMESIZE + 8
#define BUFSIZE 4096

int setup_ssl_ctx(SSL_CTX **ctx)
{
    SSL_CTX *newctx = NULL;

    if (ctx == NULL)
        return log_error("setup_ssl_ctx: NULL context pointer");

    newctx = SSL_CTX_new(TLS_client_method()); /* protocol version negotiated to highest supported */
    if (newctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        return log_error("failed to create the SSL_CTX");
    }

    /* trust the server's self-signed certificate BEFORE enabling verification */
    if (!SSL_CTX_load_verify_locations(newctx, "server.crt", NULL))
    {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(newctx);
        return log_error("failed to load server certificate");
    }

    /* a client must always verify the server's certificate;
     * we configure the client to abort the handshake if verification fails */
    SSL_CTX_set_verify(newctx, SSL_VERIFY_PEER, NULL);

    /* restrict TLS version to TLSv1.2 or above */
    if (!SSL_CTX_set_min_proto_version(newctx, TLS1_2_VERSION))
    {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(newctx);
        return log_error("failed to set the minimum TLS protocol version");
    }

    *ctx = newctx;
    return 0;
}

int do_get(SSL_CTX *ctx, const char *server_ip, const char *hostname, const char *request, uint16_t port)
{
    int sockfd;
    struct sockaddr_in srvaddr;
    FILE *fp = NULL;
    char buf[BUFSIZE];
    ssize_t n;
    struct file_header hdr;
    uint64_t left;
    SSL *ssl = NULL;
    int rc;

    /* create socket and connect */
    sockfd = Socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        log_fatal("failed to create socket");

    memset(&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sin_family = AF_INET;
    srvaddr.sin_port = htons(port);
    if (Inet_pton(AF_INET, server_ip, &srvaddr.sin_addr) < 0)
        log_fatal("failed to assign server ip address");

    if (Connect(sockfd, (struct sockaddr *)&srvaddr, sizeof(srvaddr)) < 0)
        log_fatal("failed to connect to server");

    /* attach socket to SSL obj */
    ssl = SSL_new(ctx);
    if (ssl == NULL)
        log_fatal("failed to create the SSL object");
    if (!SSL_set_fd(ssl, sockfd))
        log_fatal("SSL_set_fd failed");

    /* during TLS handshake, tell the server which hostname
     * the client is attempting to connect to. This info will
     * be included in the ClientHello */
    if (!SSL_set_tlsext_host_name(ssl, hostname))
        log_fatal("failed to set the SNI hostname");
    if (!SSL_set1_host(ssl, hostname))
        log_fatal("failed to set the certificate verification hostname");

    /* perform TLS handshake */
    if (SSL_connect(ssl) < 1)
    {
        if (SSL_get_verify_result(ssl) != X509_V_OK)
            log_msg(LOG_ERROR, 0, "Verify error: %s\n",
                    X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
        log_msg(LOG_ERROR, 0, "failed to perform TLS handshake");
        goto cleanup;
    }

    /* send request */
    if (SSL_Write_ex(ssl, request, strlen(request)) < 0)
    {
        log_msg(LOG_ERROR, 0, "SSL write failed");
        goto cleanup;
    }
    SSL_shutdown(ssl); // only once: close_notify sent but not received

    /* read header */
    n = SSL_Read_ex(ssl, &hdr, sizeof(hdr));
    if (n < (ssize_t)sizeof(hdr))
    {
        log_msg(LOG_ERROR, 0, "failed to read header from server");
        goto cleanup;
    }
    if (hdr.status != 0)
    {
        log_msg(LOG_ERROR, 0, "server reported error: %s", strerror(hdr.status));
        goto cleanup;
    }

    /* open output file */
    hdr.length = be64toh(hdr.length);
    const char *fname = request + 4;
    fp = fopen(fname, "wb");
    if (!fp)
    {
        log_msg(LOG_ERROR, 1, "failed to open %s for writing", fname);
        goto cleanup;
    }

    /* read file bytes */
    left = hdr.length;
    while (left > 0)
    {
        size_t to_read = left < BUFSIZE ? (size_t)left : BUFSIZE;
        n = SSL_Read_ex(ssl, buf, to_read);
        if (n <= 0)
        {
            log_msg(LOG_ERROR, 1, "read error during file transfer");
            break;
        }
        size_t written = fwrite(buf, 1, (size_t)n, fp);
        if (written < (size_t)n)
        {
            /* avoids local write errors, preventing silent data loss */
            log_msg(LOG_ERROR, 1, "short write to %s", fname);
            break;
        }
        left -= (uint64_t)n;
    }

    /* check for short read */
    if (left == 0)
    {
        log_msg(LOG_INFO, 0, "'GET %s' completed (%" PRIu64 " bytes).",
                fname, hdr.length);
        rc = 0;
    }
    else
    {
        log_msg(LOG_WARN, 0, "'GET %s' incomplete (%" PRIu64 "/%" PRIu64 " bytes).",
                fname, hdr.length - left, hdr.length);
        rc = -1;
    }

cleanup:
    if (fp && fclose(fp) != 0)
        log_msg(LOG_WARN, 1, "fclose returned error on %s", fname);
    if (ssl)
        SSL_free(ssl);
    if (sockfd >= 0)
        Close(sockfd);

    return rc;
}

int main(int argc, char **argv)
{
    char cmd[CMDSIZE];

    if (argc != 3)
        log_fatal("usage: %s <ip address> <config path>\n", argv[0]);

    const char *srv_ip = argv[1];
    const char *cfg_file_name = argv[2];

    SSL_CTX *ctx = NULL;
    if (setup_ssl_ctx(&ctx) == -1)
        log_fatal("error in setting up ssl ctx");

    Config cfg = {0};
    if (load_config(cfg_file_name, &cfg) != 0)
        log_fatal("error loading configuration");

    printf("connected to %s (port number %d)\n", srv_ip, cfg.srv_port);
    printf("type: GET <filename> or QUIT\n");

    while (1)
    {
        printf("> ");
        if (fgets(cmd, CMDSIZE, stdin) == NULL)
            break; /* error or EOF with no chars read */

        /* strip trailing newline */
        size_t cmd_len = strlen(cmd);
        if (cmd_len > 0 && cmd[cmd_len - 1] == '\n')
            cmd[cmd_len - 1] = 0;

        /* skip empty string */
        if (cmd_len == 0 && cmd[cmd_len] == 0)
            continue;

        if (strncmp(cmd, "GET ", 4) == 0)
        {
            /* get file from server */
            const char *fname = cmd + 4;
            if (*fname == 0)
            {
                log_msg(LOG_WARN, 0, "usage: GET <filename>");
                continue;
            }

            int rc = do_get(ctx, srv_ip, cfg.srv_hostname, cmd, cfg.srv_port);
            if (rc == 0)
                log_msg(LOG_INFO, 0, "GET %s completed.", fname);
            else
                log_msg(LOG_WARN, 1, "GET %s not completed.", fname);
        }
        else if (strcmp(cmd, "QUIT") == 0)
        {
            /* client is done */
            break;
        }
        else
        {
            log_msg(LOG_WARN, 0, "unknown command: %s", cmd);
        }
    }

    if (ctx)
        SSL_CTX_free(ctx);

    return 0;
}
