#include "../include/registry.h"

/**
 * Function to set a registry key with specified path, value name, data, and type
 * @param hive: Targetted hive (e.g., "HKLM")
 * @param keyPath: Registry path (e.g., "SOFTWARE\\MyApp")
 * @param valueName: Name of the value to set
 * @param data: Data to write
 * @param dataSize: Size of the data
 * @param valueType: Type of registry value (REG_SZ, REG_DWORD, etc.)
 * @return: 0 on success, -1 on failure
 * Links : 
 *  - https://learn.microsoft.com/fr-fr/windows/win32/api/winreg/nf-winreg-regcreatekeyexa
 *  - https://learn.microsoft.com/fr-fr/windows/win32/api/winreg/nf-winreg-regsetvalueexa
 */
int set_registry_key(HKEY hive, const char* keyPath, const char* valueName, 
                   const void* data, DWORD dataSize, DWORD valueType) {
    if (!keyPath || !valueName || !data) {
        pretty_print(LOG_ERROR, "Invalid parameters");
        return -1;
    }
    
    HKEY hKey;
    LONG result;
    DWORD disposition;
    
    // Open or create the registry key
    result = RegCreateKeyExA(
        hive,                       // Targetted hive
        keyPath,                    // Subkey path
        0,                          // Reserved
        NULL,                       // Class
        REG_OPTION_NON_VOLATILE,    // Options
        KEY_WRITE | KEY_READ,       // Access rights
        NULL,                       // Security attributes
        &hKey,                      // Handle to opened key
        &disposition                // Disposition
    );

    if (result != ERROR_SUCCESS) {
        pretty_print(LOG_ERROR, "Failed to open/create registry key: %ld", result);
        return -1;
    }
    
    // Set the registry value
    result = RegSetValueExA(
        hKey,               // Handle to key
        valueName,          // Value name
        0,                  // Reserved
        valueType,          // Value type
        (const BYTE*)data,  // Value data
        dataSize            // Size of data
    );
    
    if (result != ERROR_SUCCESS) {
        pretty_print(LOG_ERROR, "Failed to set registry value: %ld", result);
        RegCloseKey(hKey);
        return -1;
    }
    
    pretty_print(LOG_SUCCESS, "Registry key set successfully");
    RegCloseKey(hKey);
    return 0;
}

/**
 * Function to set a registry key with specified path, value name, data, and type
 * @param hive: Targetted hive (e.g., "HKLM")
 * @param keyPath: Registry path (e.g., "SOFTWARE\\MyApp")
 * @param valueName: Name of the value to set
 * @param dataSize: Size of the data
 * @return: Value of registry key on success, NULL on failure
 * Links : 
 *  - https://learn.microsoft.com/fr-fr/windows/win32/api/winreg/nf-winreg-regopenkeyexa
 *  - https://learn.microsoft.com/fr-fr/windows/win32/api/winreg/nf-winreg-regqueryvalueexa
 */
char* get_registry_key(HKEY hive, const char* keyPath, const char* valueName, DWORD* dataSize) {
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
    
    // Get required buffer size
    result = RegQueryValueExA(hKey, valueName, NULL, NULL, NULL, dataSize);
    if (result != ERROR_SUCCESS) {
        pretty_print(LOG_ERROR, "Failed to query registry value size: %ld", result);
        RegCloseKey(hKey);
        return NULL;
    }
    
    // Allocate buffer
    char* buffer = malloc(*dataSize);
    if (!buffer) {
        pretty_print(LOG_ERROR, "Memory allocation failed");
        RegCloseKey(hKey);
        return NULL;
    }
    
    
    // Get actual value
    result = RegQueryValueExA(hKey, valueName, NULL, NULL, (BYTE*)buffer, dataSize);
    if (result != ERROR_SUCCESS) {
        pretty_print(LOG_ERROR, "Failed to read registry value: %ld", result);
        free(buffer);
        RegCloseKey(hKey);
        return NULL;
    }
    
    RegCloseKey(hKey);
    return buffer; // Caller must free this memory
}

/**
 * Function to check if a registry value exists
 * @param hive: Targetted hive (e.g., HKEY_LOCAL_MACHINE)
 * @param keyPath: Registry path (e.g., "SOFTWARE\\MyApp")
 * @param valueName: Name of the value to check
 * @return: 1 if value exists, 0 otherwise
 * Links : 
 * - https://learn.microsoft.com/fr-fr/windows/win32/api/winreg/nf-winreg-regopenkeyexa
 * - https://learn.microsoft.com/fr-fr/windows/win32/api/winreg/nf-winreg-regqueryvalueexa
 */
int registry_value_exists(HKEY hive, const char* keyPath, const char* valueName) {
    if (!keyPath || !valueName) {
        pretty_print(LOG_ERROR, "Invalid parameters for registry value existence check");
        return 0;
    }
    
    HKEY hKey;
    LONG result;
    
    // Try to open the registry key
    result = RegOpenKeyExA(hive, keyPath, 0, KEY_READ, &hKey);
    if (result != ERROR_SUCCESS) {
        // Key doesn't exist, so value doesn't exist either
        pretty_print(LOG_INFO, "Registry key does not exist: %s\\%s", hive, keyPath);
        return 0;
    }
    
    // Try to query the value (just check if it exists, don't read data)
    result = RegQueryValueExA(hKey, valueName, NULL, NULL, NULL, NULL);
    
    RegCloseKey(hKey);
    
    if (result == ERROR_SUCCESS) {
        pretty_print(LOG_INFO, "Registry value exists: %s\\%s", keyPath, valueName);
        return 1;
    } else if (result == ERROR_FILE_NOT_FOUND) {
        pretty_print(LOG_INFO, "Registry value does not exist: %s\\%s", keyPath, valueName);
        return 0;
    } else {
        pretty_print(LOG_WARNING, "Error checking registry value existence: %ld", result);
        return 0;
    }
}