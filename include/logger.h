#ifndef LOGGER_H
#define LOGGER_H

#include "common.h"

#include <stdarg.h>

#define TOOL_NAME    "Registrator"
#define TOOL_VERSION "1.0.0"
#define TOOL_AUTHOR  "Drachh_"
#define TOOL_DESC    "Windows Multitool Framework"

typedef enum {
    LOG_ERROR,
    LOG_SUCCESS,
    LOG_INFO,
    LOG_WARNING
} log_level_t;

// Function prototypes
void print_banner(void);
void pretty_print(log_level_t level, const char* format, ...);
void print_binary_data(const BYTE* data, DWORD size);

#endif // LOGGER_H
