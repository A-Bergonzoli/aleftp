#include "config.h"

void trim_newline(char *str)
{
    size_t len = strlen(str);
    if (len > 0 && (str[len - 1] == '\n' || str[len - 1] == '\r'))
    {
        str[len - 1] = '\0';
    }
}

void trim_spaces(char *str)
{
    char *start = str;
    while (*start == ' ' || *start == '\t')
        start++;
    if (start != str)
        memmove(str, start, strlen(start) + 1);

    char *end = str + strlen(str) - 1;
    while (end > str && (*end == ' ' || *end == '\t')) {
        *end = 0;
        end--;
    }
}

int load_config(const char *filename, Config *cfg)
{
    FILE *f = fopen(filename, "r");
    if (!f)
        return log_error("Failed to open config file");

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f))
    {
        if (line[0] == '#' || strlen(line) == 0)
            continue;

        trim_newline(line);

        char *eq = strchr(line, '=');
        if (!eq)
            continue;

        *eq = '\0';
        char *key = line;
        char *value = eq + 1;

        trim_spaces(key);
        trim_spaces(value);

        if (strcmp(key, "srv_hostname") == 0)
        {
            strncpy(cfg->srv_hostname, value, sizeof(cfg->srv_hostname) - 1);
            cfg->srv_hostname[sizeof(cfg->srv_hostname) - 1] = 0;
        }
        else if (strcmp(key, "srv_root") == 0)
        {
            strncpy(cfg->srv_root, value, sizeof(cfg->srv_root) - 1);
            cfg->srv_root[sizeof(cfg->srv_root) - 1] = 0;
        }
        else if (strcmp(key, "cli_root") == 0)
        {
            strncpy(cfg->cli_root, value, sizeof(cfg->cli_root) - 1);
            cfg->cli_root[sizeof(cfg->cli_root) - 1] = 0;
        }
        else if (strcmp(key, "srv_port") == 0)
        {
            cfg->srv_port = (uint16_t)atoi(value);
        }
    }

    fclose(f);
    return 0;
}
