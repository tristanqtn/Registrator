#ifndef SYSTEM_H
#define SYSTEM_H

#include <windows.h>   
#include "logger.h"

typedef enum {
    ELEVATION_ERROR = -1,
    ELEVATION_NOT_ELEVATED = 0,
    ELEVATION_ELEVATED = 1
} elevation_status_t;

// Function prototypes
elevation_status_t is_elevated(void);

#endif // SYSTEM_H
