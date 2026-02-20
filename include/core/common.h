#ifndef COMMON_H
#define COMMON_H

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winreg.h>

// MitigationOptions
#define MITIGATION_OPTIONS_DATA_SIZE 20
#define MITIGATION_OPTIONS_REGISTRY_PATH                                       \
  "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel"
#define MITIGATION_OPTIONS_VALUE_NAME "MitigationOptions"

// PendingFileRenameOperations
#define PENDING_RENAME_OPERATION_PATH                                          \
  "SYSTEM\\CurrentControlSet\\Control\\Session Manager"
#define PENDING_RENAME_OPERATION_NAME "PendingFileRenameOperations"

// Exported Static Variables
extern const BYTE
    MITIGATION_OPTIONS_VALUE_MICROSOFT_SIGNED_ONLY[MITIGATION_DATA_SIZE];
extern const BYTE MITIGATION_OPTIONS_VALUE_DEFAULT[MITIGATION_DATA_SIZE];

#endif // COMMON_H
