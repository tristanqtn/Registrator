#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winreg.h>

// MitigationOptions
#define MITIGATION_OPTIONS_DATA_SIZE 20
#define MITIGATION_OPTIONS_REGISTRY_PATH "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel"
#define MITIGATION_OPTIONS_VALUE_NAME "MitigationOptions"

// PendingFileRenameOperations
#define PENDING_RENAME_OPERATION_PATH "SYSTEM\\CurrentControlSet\\Control\\Session Manager"
#define PENDING_RENAME_OPERATION_NAME "PendingFileRenameOperations"

// Exported Static Variables
extern const BYTE mitigationValue_MicrosoftSignedOnly[MITIGATION_DATA_SIZE];
extern const BYTE mitigationValue_default[MITIGATION_DATA_SIZE];

#endif // COMMON_H
