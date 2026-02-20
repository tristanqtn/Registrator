#ifndef REGISTRY_H
#define REGISTRY_H

#include <windows.h> 
#include <winreg.h>    
#include "logger.h"   

// Function prototypes
int set_registry_key(HKEY hive, const char* keyPath, const char* valueName, 
                   const void* data, DWORD dataSize, DWORD valueType);

char* get_registry_key(HKEY hive, const char* keyPath, const char* valueName, 
                     DWORD* dataSize);

int registry_value_exists(HKEY hive, const char* keyPath, const char* valueName);

#endif // REGISTRY_H
