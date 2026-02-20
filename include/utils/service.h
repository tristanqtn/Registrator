#ifndef SERVICE_H
#define SERVICE_H

#include <windows.h>
#include <winsvc.h>
#include "logger.h"

// Timeout in milliseconds to wait for a service to reach a pending state
#define SERVICE_STATUS_POLL_INTERVAL_MS 500
#define SERVICE_STATUS_TIMEOUT_MS       10000

// Function prototypes
int create_service(const char* serviceName, const char* displayName,
                   const char* binaryPath, DWORD startType);

int start_service(const char* serviceName);

int stop_service(const char* serviceName);

int delete_service(const char* serviceName);

int modify_service(const char* serviceName, const char* newDisplayName,
                   const char* newBinaryPath, DWORD newStartType);

#endif // SERVICE_H