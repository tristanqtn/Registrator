#ifndef REGISTRY_H
#define REGISTRY_H

#include <windows.h> 
#include <winreg.h>    
#include "logger.h"   

// Function prototypes
int set_registry_key(HKEY hive, const char* keyPath, const char* valueName,
                     const void* data, DWORD dataSize, DWORD valueType);

BYTE* get_registry_key(HKEY hive, const char* keyPath, const char* valueName,
                       DWORD* dataSize);

int append_registry_value(HKEY hive, const char* keyPath, const char* valueName,
                        const void* data, DWORD dataSize);

int delete_registry_value(HKEY hive, const char* keyPath, const char* valueName);

int delete_registry_key(HKEY hive, const char* keyPath);

int registry_value_exists(HKEY hive, const char* keyPath, const char* valueName);

#endif // REGISTRY_H
