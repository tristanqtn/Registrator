#include "../include/logger.h"
#include "../include/registry.h"
#include "../include/system.h"
#include "../include/common.h"

int main(void) {
    elevation_status_t status = is_elevated();
    
    switch (status) {
        case ELEVATION_ELEVATED:
            pretty_print(LOG_SUCCESS, "Administrator privileges detected");
            break;
        case ELEVATION_NOT_ELEVATED:
            pretty_print(LOG_WARNING, "Standard user privileges - some operations may fail");
            return 1;
        case ELEVATION_ERROR:
            pretty_print(LOG_ERROR, "Could not determine elevation status");
            return 1;
    }
    
    if (registryValueExists(HKEY_LOCAL_MACHINE, MITIGATION_REGISTRY_PATH, MITIGATION_VALUE_NAME)) {
        pretty_print(LOG_INFO, "Reading existing registry value");
        DWORD dataSize;
        char* value = getRegistryKey(HKEY_LOCAL_MACHINE, MITIGATION_REGISTRY_PATH, MITIGATION_VALUE_NAME, &dataSize);
        
        if (value) {
            pretty_print(LOG_SUCCESS, "Current registry value:");
            print_binary_data((const BYTE*)value, dataSize);
            free(value);
        }
    } else {
        pretty_print(LOG_INFO, "Registry value does not exist, will create it");
    }
    
    // Set new registry value
    pretty_print(LOG_INFO, "Setting registry value");
    int result = setRegistryKey(
        HKEY_LOCAL_MACHINE, 
        MITIGATION_REGISTRY_PATH,
        MITIGATION_VALUE_NAME,
        mitigationValue_MicrosoftSignedOnly, 
        sizeof(mitigationValue_MicrosoftSignedOnly), 
        REG_BINARY
    );
    
    if (result != 0) {
        pretty_print(LOG_ERROR, "Failed to set registry value");
        return 1;
    }
    
    // Verify the value was set
    pretty_print(LOG_INFO, "Verifying registry value was set");
    DWORD dataSize;
    char* value = getRegistryKey(HKEY_LOCAL_MACHINE, MITIGATION_REGISTRY_PATH, MITIGATION_VALUE_NAME, &dataSize);
    
    if (value) {
        pretty_print(LOG_SUCCESS, "Successfully retrieved registry value");
        print_binary_data((const BYTE*)value, dataSize);
        free(value);
    } else {
        pretty_print(LOG_ERROR, "Failed to retrieve registry value");
    }
    
    printf("\nPress Enter to exit...");
    getchar();
    
    return 0;
}
