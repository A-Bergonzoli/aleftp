#ifndef INCLUDE_PROTOCOL_H
#define INCLUDE_PROTOCOL_H

#include <stdint.h>

// clang-format off

struct file_header
{
    uint64_t  length;   // [bytes] file size (network byte order)
    int32_t   status;   // 0 = OK, errno otherwise
};

#endif
