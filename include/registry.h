#ifndef REGISTRY_H
#define REGISTRY_H

#include "common.h"
#include "logger.h"

// Function prototypes
int setRegistryKey(HKEY hive, const char* keyPath, const char* valueName, 
                   const void* data, DWORD dataSize, DWORD valueType);

char* getRegistryKey(HKEY hive, const char* keyPath, const char* valueName, 
                     DWORD* dataSize);

int registryValueExists(HKEY hive, const char* keyPath, const char* valueName);

#endif // REGISTRY_H
