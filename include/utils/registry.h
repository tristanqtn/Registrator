#ifndef REGISTRY_H
#define REGISTRY_H

#include "logger.h"
#include <windows.h>
#include <winreg.h>

// Function prototypes

// Create or open a key and write a value of the specified type.
int set_registry_key(HKEY hive, const char *keyPath, const char *valueName,
                     const void *data, DWORD dataSize, DWORD valueType);

// Read a registry value into a heap-allocated buffer (caller must free).
// valueType receives REG_SZ / REG_DWORD / REG_BINARY / etc.; pass NULL to
// ignore. See implementation for TOCTOU caveat on volatile keys.
BYTE *get_registry_key(HKEY hive, const char *keyPath, const char *valueName,
                       DWORD *dataSize, DWORD *valueType);

// Append raw bytes to an existing value, preserving its original type.
int append_registry_value(HKEY hive, const char *keyPath, const char *valueName,
                          const void *data, DWORD dataSize);

// Delete a named value from a key (key itself is kept).
int delete_registry_value(HKEY hive, const char *keyPath,
                          const char *valueName);

// Delete a key and all its values (no subkeys allowed). Uses
// RegDeleteKeyExA(KEY_WOW64_64KEY) to always target the 64-bit registry view.
int delete_registry_key(HKEY hive, const char *keyPath);

// Return 1 if the named value exists, 0 otherwise.
int registry_value_exists(HKEY hive, const char *keyPath,
                          const char *valueName);

// Write a REG_SZ value under HKCU\...\Run so a binary re-launches on logon.
// Does not require administrator privileges.
// @param name:    Value name shown in Task Manager / Autoruns
// @param binPath: Absolute path to the binary to run on logon
// @return: 0 on success, -1 on failure
int set_run_key(const char *name, const char *binPath);

// Delete a HKCU Run key entry by value name.
// Idempotent: succeeds even if the value does not exist.
// @return: 0 on success, -1 on failure
int remove_run_key(const char *name);

#endif // REGISTRY_H
