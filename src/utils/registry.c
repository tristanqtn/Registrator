#include "../../include/utils/registry.h"

//////////////////////////////////////////////////////////////
// Registry Functions ////////////////////////////////////////
//////////////////////////////////////////////////////////////

/**
 * Function to set a registry key with specified path, value name, data, and
 * type
 * @param hive:      Targeted hive (e.g., HKEY_LOCAL_MACHINE)
 * @param keyPath:   Registry path (e.g., "SOFTWARE\\MyApp")
 * @param valueName: Name of the value to set
 * @param data:      Data to write
 * @param dataSize:  Size of the data in bytes
 * @param valueType: Type of registry value (REG_SZ, REG_DWORD, REG_BINARY,
 * etc.)
 * @return: 0 on success, -1 on failure
 * Links:
 * https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcreatekeyexa
 * https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexa
 */
int set_registry_key(HKEY hive, const char *keyPath, const char *valueName,
                     const void *data, DWORD dataSize, DWORD valueType) {
  if (!keyPath || !valueName || !data) {
    pretty_print(LOG_ERROR, "Invalid parameters");
    return -1;
  }

  HKEY hKey;
  LONG result;
  DWORD disposition;

  result = RegCreateKeyExA(hive,                    // Targeted hive
                           keyPath,                 // Subkey path
                           0,                       // Reserved
                           NULL,                    // Class
                           REG_OPTION_NON_VOLATILE, // Options
                           KEY_WRITE,               // Access rights (write only)
                           NULL,                    // Security attributes
                           &hKey,                   // Handle to opened key
                           &disposition             // Disposition
  );

  if (result != ERROR_SUCCESS) {
    pretty_print(LOG_ERROR, "Failed to open/create registry key: %ld", result);
    return -1;
  }

  result = RegSetValueExA(hKey,               // Handle to key
                          valueName,          // Value name
                          0,                  // Reserved
                          valueType,          // Value type
                          (const BYTE *)data, // Value data
                          dataSize            // Size of data
  );

  if (result != ERROR_SUCCESS) {
    pretty_print(LOG_ERROR, "Failed to set registry value: %ld", result);
    RegCloseKey(hKey);
    return -1;
  }

  pretty_print(LOG_SUCCESS, "Registry value set successfully");
  RegCloseKey(hKey);
  return 0;
}

/**
 * Read a registry value and return its data as a heap-allocated buffer.
 * The caller is responsible for freeing the returned buffer.
 *
 * Note: The size is queried first and then the value is read in a second call.
 * Another process can modify the value between these two calls (TOCTOU). If
 * the value grows, the second call returns ERROR_MORE_DATA and NULL is
 * returned. Callers operating on volatile or shared keys should be aware of
 * this window.
 *
 * @param hive:      Targeted hive (e.g., HKEY_LOCAL_MACHINE)
 * @param keyPath:   Registry path (e.g., "SOFTWARE\\MyApp")
 * @param valueName: Name of the value to read
 * @param dataSize:  Receives the size of the returned buffer in bytes
 * @param valueType: Receives the registry value type (REG_SZ, REG_DWORD,
 *                   REG_BINARY, etc.). Pass NULL if not needed.
 * @return: Pointer to allocated buffer on success, NULL on failure
 * Links:
 * https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexa
 * https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryvalueexa
 */
BYTE *get_registry_key(HKEY hive, const char *keyPath, const char *valueName,
                       DWORD *dataSize, DWORD *valueType) {
  if (!keyPath || !valueName || !dataSize) {
    pretty_print(LOG_ERROR, "Invalid parameters");
    return NULL;
  }

  HKEY hKey;
  LONG result;

  result = RegOpenKeyExA(hive, keyPath, 0, KEY_READ, &hKey);
  if (result != ERROR_SUCCESS) {
    pretty_print(LOG_ERROR, "Failed to open registry key: %ld", result);
    return NULL;
  }

  result = RegQueryValueExA(hKey, valueName, NULL, valueType, NULL, dataSize);
  if (result != ERROR_SUCCESS) {
    pretty_print(LOG_ERROR, "Failed to query registry value size: %ld", result);
    RegCloseKey(hKey);
    return NULL;
  }

  BYTE *buffer = malloc(*dataSize);
  if (!buffer) {
    pretty_print(LOG_ERROR, "Memory allocation failed");
    RegCloseKey(hKey);
    return NULL;
  }

  result = RegQueryValueExA(hKey, valueName, NULL, NULL, buffer, dataSize);
  if (result != ERROR_SUCCESS) {
    pretty_print(LOG_ERROR, "Failed to read registry value: %ld", result);
    free(buffer);
    RegCloseKey(hKey);
    return NULL;
  }

  RegCloseKey(hKey);
  return buffer;
}

/**
 * Function to append data to an existing registry value
 * Reads the current value, allocates a new buffer, and writes the concatenation
 * The original value type is preserved
 * @param hive:      Targeted hive (e.g., HKEY_LOCAL_MACHINE)
 * @param keyPath:   Registry path (e.g., "SOFTWARE\\MyApp")
 * @param valueName: Name of the value to append to
 * @param data:      Data to append
 * @param dataSize:  Size of the data to append in bytes
 * @return: 0 on success, -1 on failure
 * Links:
 * https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryvalueexa
 * https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexa
 */
int append_registry_value(HKEY hive, const char *keyPath, const char *valueName,
                          const void *data, DWORD dataSize) {
  if (!keyPath || !valueName || !data || dataSize == 0) {
    pretty_print(LOG_ERROR, "Invalid parameters");
    return -1;
  }

  HKEY hKey;
  LONG result;

  result = RegOpenKeyExA(hive, keyPath, 0, KEY_READ | KEY_WRITE, &hKey);
  if (result != ERROR_SUCCESS) {
    pretty_print(LOG_ERROR, "Failed to open registry key: %ld", result);
    return -1;
  }

  DWORD existingSize = 0;
  DWORD valueType;

  result =
      RegQueryValueExA(hKey, valueName, NULL, &valueType, NULL, &existingSize);
  if (result != ERROR_SUCCESS) {
    pretty_print(LOG_ERROR, "Failed to query existing registry value size: %ld",
                 result);
    RegCloseKey(hKey);
    return -1;
  }

  if (existingSize > (DWORD)(~0) - dataSize) {
    pretty_print(LOG_ERROR, "Combined data size overflows DWORD");
    RegCloseKey(hKey);
    return -1;
  }

  BYTE *buffer = malloc(existingSize + dataSize);
  if (!buffer) {
    pretty_print(LOG_ERROR, "Memory allocation failed");
    RegCloseKey(hKey);
    return -1;
  }

  result = RegQueryValueExA(hKey, valueName, NULL, NULL, buffer, &existingSize);
  if (result != ERROR_SUCCESS) {
    pretty_print(LOG_ERROR, "Failed to read existing registry value: %ld",
                 result);
    free(buffer);
    RegCloseKey(hKey);
    return -1;
  }

  memcpy(buffer + existingSize, data, dataSize);

  result = RegSetValueExA(hKey,                   // Handle to key
                          valueName,              // Value name
                          0,                      // Reserved
                          valueType,              // Preserve original type
                          buffer,                 // Combined data
                          existingSize + dataSize // Total size
  );

  free(buffer);

  if (result != ERROR_SUCCESS) {
    pretty_print(LOG_ERROR, "Failed to write appended registry value: %ld",
                 result);
    RegCloseKey(hKey);
    return -1;
  }

  pretty_print(LOG_SUCCESS, "Registry value appended successfully");
  RegCloseKey(hKey);
  return 0;
}

/**
 * Function to delete a registry value from a key
 * @param hive:      Targeted hive (e.g., HKEY_LOCAL_MACHINE)
 * @param keyPath:   Registry path (e.g., "SOFTWARE\\MyApp")
 * @param valueName: Name of the value to delete
 * @return: 0 on success, -1 on failure
 * Links:
 * https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexa
 * https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regdeletevaluea
 */
int delete_registry_value(HKEY hive, const char *keyPath,
                          const char *valueName) {
  if (!keyPath || !valueName) {
    pretty_print(LOG_ERROR, "Invalid parameters");
    return -1;
  }

  HKEY hKey;
  LONG result;

  result = RegOpenKeyExA(hive, keyPath, 0, KEY_WRITE, &hKey);
  if (result != ERROR_SUCCESS) {
    pretty_print(LOG_ERROR, "Failed to open registry key: %ld", result);
    return -1;
  }

  result = RegDeleteValueA(hKey,     // Handle to key
                           valueName // Value name to delete
  );

  if (result != ERROR_SUCCESS) {
    pretty_print(LOG_ERROR, "Failed to delete registry value: %ld", result);
    RegCloseKey(hKey);
    return -1;
  }

  pretty_print(LOG_SUCCESS, "Registry value deleted successfully");
  RegCloseKey(hKey);
  return 0;
}

/**
 * Delete a registry key and all its values.
 * The key must have no subkeys — subkeys must be deleted first.
 *
 * Uses RegDeleteKeyExA with KEY_WOW64_64KEY to target the native 64-bit
 * registry view on 64-bit Windows. RegDeleteKeyA does not accept a view flag
 * and is subject to WoW64 redirection when called from a 32-bit process,
 * which can silently operate on the wrong view (e.g.,
 * HKLM\SOFTWARE\WOW6432Node\... instead of HKLM\SOFTWARE\...).
 *
 * @param hive:    Targeted hive (e.g., HKEY_LOCAL_MACHINE)
 * @param keyPath: Full path to the key to delete (e.g., "SOFTWARE\\MyApp")
 * @return: 0 on success, -1 on failure
 * Links:
 * https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regdeletekeyexa
 */
int delete_registry_key(HKEY hive, const char *keyPath) {
  if (!keyPath) {
    pretty_print(LOG_ERROR, "Invalid parameters");
    return -1;
  }

  LONG result = RegDeleteKeyExA(hive,            // Parent hive
                                keyPath,         // Subkey path to delete
                                KEY_WOW64_64KEY, // Always target 64-bit view
                                0                // Reserved
  );

  if (result != ERROR_SUCCESS) {
    pretty_print(LOG_ERROR, "Failed to delete registry key: %ld", result);
    return -1;
  }

  pretty_print(LOG_SUCCESS, "Registry key deleted successfully");
  return 0;
}

/**
 * Function to check whether a registry value exists under a given key
 * @param hive:      Targeted hive (e.g., HKEY_LOCAL_MACHINE)
 * @param keyPath:   Registry path (e.g., "SOFTWARE\\MyApp")
 * @param valueName: Name of the value to check
 * @return: 1 if value exists, 0 otherwise
 * Links:
 * https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexa
 * https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryvalueexa
 */
int registry_value_exists(HKEY hive, const char *keyPath,
                          const char *valueName) {
  if (!keyPath || !valueName) {
    pretty_print(LOG_ERROR, "Invalid parameters");
    return 0;
  }

  HKEY hKey;
  LONG result;

  result = RegOpenKeyExA(hive, keyPath, 0, KEY_READ, &hKey);
  if (result != ERROR_SUCCESS) {
    return 0;
  }

  result = RegQueryValueExA(hKey, valueName, NULL, NULL, NULL, NULL);

  RegCloseKey(hKey);

  if (result == ERROR_SUCCESS) {
    return 1;
  } else if (result == ERROR_FILE_NOT_FOUND) {
    return 0;
  } else {
    pretty_print(LOG_WARNING, "Error checking registry value existence: %ld",
                 result);
    return 0;
  }
}

//////////////////////////////////////////////////////////////
// Persistence Helpers ///////////////////////////////////////
//////////////////////////////////////////////////////////////

#define RUN_KEY_PATH "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"

/**
 * Write a REG_SZ entry under HKCU\...\Run so the binary re-launches on logon.
 * No administrator privileges required.
 */
int set_run_key(const char *name, const char *binPath) {
  if (!name || !binPath) {
    pretty_print(LOG_ERROR, "set_run_key: invalid parameters");
    return -1;
  }
  return set_registry_key(HKEY_CURRENT_USER, RUN_KEY_PATH, name, binPath,
                          (DWORD)(strlen(binPath) + 1), // include null terminator
                          REG_SZ);
}

/**
 * Remove a HKCU Run key value.
 * Treats ERROR_FILE_NOT_FOUND as success (idempotent).
 */
int remove_run_key(const char *name) {
  if (!name) {
    pretty_print(LOG_ERROR, "remove_run_key: invalid parameters");
    return -1;
  }

  HKEY hKey;
  LONG result = RegOpenKeyExA(HKEY_CURRENT_USER, RUN_KEY_PATH, 0, KEY_WRITE,
                              &hKey);
  if (result != ERROR_SUCCESS) {
    pretty_print(LOG_ERROR, "remove_run_key: failed to open key: %ld", result);
    return -1;
  }

  result = RegDeleteValueA(hKey, name);
  RegCloseKey(hKey);

  if (result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND) {
    pretty_print(LOG_SUCCESS, "remove_run_key: '%s' removed (or was absent)",
                 name);
    return 0;
  }

  pretty_print(LOG_ERROR, "remove_run_key: RegDeleteValueA failed: %ld",
               result);
  return -1;
}