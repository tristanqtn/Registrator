#ifndef LOGGER_H
#define LOGGER_H

#include "common.h"

typedef enum {
    LOG_ERROR,
    LOG_SUCCESS,
    LOG_INFO,
    LOG_WARNING
} log_level_t;

// Function prototypes
void pretty_print(log_level_t level, const char* format, ...);
void print_binary_data(const BYTE* data, DWORD size);

#endif // LOGGER_H
