#ifndef LIB_CONFIG_H
#define LIB_CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "lib/logging.h"

#define MAX_LINE 256
#define MAX_PATH 512

typedef struct
{
    char srv_hostname[128];
    char srv_root[MAX_PATH];
    char cli_root[MAX_PATH];
    uint16_t srv_port;
} Config;

int load_config(const char *filename, Config *cfg);

#endif
