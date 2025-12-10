#include "logging.h"

#define LOGSIZE 1024

const char *to_string(log_level_t level)
{
    switch (level)
    {
    case LOG_DBG:
        return "DEBG";
    case LOG_INFO:
        return "INFO";
    case LOG_WARN:
        return "WARN";
    case LOG_ERROR:
        return "ERRO";
    case LOG_FATAL:
        return "FATL";
    default:
        return "UNKNOWN";
    }
}

/* log_va(): core logging routine.
 * It builds the log line into a fixed-size buffer, which is then written atomically with write().
 *
 * errno is always saved at the start, since it may later change.
 * If `with_error` is set, we append the errno string at the end.
 *
 * If the message does not fit the buffer, it is truncated;
 * in this case, the tail is overwritten with "..." in order for it to not happen silently.
 *
 * Finally, the log is guaranteed to terminate with a newline character.
 *
 * Buffer is written to stderr.
 */
void log_va(log_level_t level, int with_errno, const char *fmt, va_list args)
{
    int errno_save = errno;
    char buf[LOGSIZE];
    size_t pos = 0U;

    // Prefix with log level
    int rc = snprintf(buf, LOGSIZE, "[%s] ", to_string(level));
    if (rc < 0)
    {
        snprintf(buf, LOGSIZE, "snprintf error\n");
        write(STDERR_FILENO, buf, strlen(buf));
        return;
    }
    pos = (rc >= LOGSIZE) ? LOGSIZE - 1 : (size_t)rc;

    // Main log message
    rc = vsnprintf(buf + pos, LOGSIZE - pos, fmt, args);
    if (rc < 0)
    {
        snprintf(buf, LOGSIZE, "snprintf error\n");
        write(STDERR_FILENO, buf, strlen(buf));
        return;
    }
    else
    {
        pos += (rc >= (int)(LOGSIZE - pos)) ? LOGSIZE - pos - 1 : (size_t)rc;
    }

    // Append errno, if requested
    if (with_errno && errno_save != 0 && pos < LOGSIZE - 1)
    {
        rc = snprintf(buf + pos, LOGSIZE - pos, " (errno=%d: %s)", errno_save, strerror(errno_save));
        if (rc >= 0)
            pos += (rc >= (int)(LOGSIZE - pos)) ? LOGSIZE - pos - 1 : (size_t)rc;
    }

    // Ensure newline or truncation marker
    if (pos < LOGSIZE - 1)
    {
        buf[pos++] = '\n';
        buf[pos] = 0;
    }
    else
    {
        const char *marker = "...";
        size_t mlen = strlen(marker);
        memcpy(buf + LOGSIZE - mlen - 1, marker, mlen);
        buf[LOGSIZE - 1] = 0;
    }

    write(STDERR_FILENO, buf, strlen(buf));
}

void log_msg(log_level_t level, int with_errno, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    log_va(level, with_errno, fmt, args);
    va_end(args);
}

int log_error(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    log_va(LOG_ERROR, 1, fmt, args);
    va_end(args);
    return -1;
}

void log_fatal(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    log_va(LOG_FATAL, 1, fmt, args);
    va_end(args);
    exit(1);
}
