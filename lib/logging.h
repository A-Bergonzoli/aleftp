#ifndef LIB_LOGGING_H
#define LIB_LOGGING_H

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef enum
{
    LOG_DBG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
    LOG_FATAL
} log_level_t;

const char *to_string(log_level_t level);

/* log_msg(): log a message with a given level. It optionally logs errno as well.
 * This is the public API. Internally, it forwards the printf-style argument list to log_va().
 */
void log_msg(log_level_t level, int with_errno, const char *fmt, ...);

/* log_exit(): like log_msg(), but propagates the error.
 * It always logs with level LOG_ERROR and errno.
 * This is the public API. Internally, it forwards the printf-style argument list to log_va().
 */
int log_error(const char *fmt, ...);

/* log_fatal(): like log_msg(), but fatal.
 * It always logs with level LOG_FATAL and errno.
 * This is the public API. Internally, it forwards the printf-style argument list to log_va().
 */
void log_fatal(const char *fmt, ...);

#endif
