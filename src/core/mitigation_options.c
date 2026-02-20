#include "../../include/core/mitigation_option.h"

/**
 * Check read, apply and verify the MitigationOptions registry policy
 * @return: 0 on success, -1 on failure
 */
int set_mitigation_policy(void) {

  if (registry_value_exists(HKEY_LOCAL_MACHINE,
                            MITIGATION_OPTIONS_REGISTRY_PATH,
                            MITIGATION_OPTIONS_VALUE_NAME)) {
    DWORD dataSize;
    BYTE *value =
        get_registry_key(HKEY_LOCAL_MACHINE, MITIGATION_OPTIONS_REGISTRY_PATH,
                         MITIGATION_OPTIONS_VALUE_NAME, &dataSize);
    if (value) {
      pretty_print(LOG_INFO, "Current registry value:");
      print_binary_data(value, dataSize);
      free(value);
    }
  } else {
    pretty_print(LOG_INFO, "Registry value does not exist, will create it");
  }

  if (set_registry_key(HKEY_LOCAL_MACHINE, MITIGATION_OPTIONS_REGISTRY_PATH,
                       MITIGATION_OPTIONS_VALUE_NAME,
                       MITIGATION_OPTIONS_VALUE_MICROSOFT_SIGNED_ONLY,
                       sizeof(MITIGATION_OPTIONS_VALUE_MICROSOFT_SIGNED_ONLY),
                       REG_BINARY) != 0) {
    pretty_print(LOG_ERROR, "Failed to set registry value");
    return -1;
  }

  DWORD dataSize;
  BYTE *value =
      get_registry_key(HKEY_LOCAL_MACHINE, MITIGATION_OPTIONS_REGISTRY_PATH,
                       MITIGATION_OPTIONS_VALUE_NAME, &dataSize);
  if (value) {
    pretty_print(LOG_SUCCESS, "Registry value verified:");
    print_binary_data(value, dataSize);
    free(value);
  } else {
    pretty_print(LOG_ERROR, "Failed to verify registry value");
    return -1;
  }

  return 0;
}

/**
 * Check remove and verify the MitigationOptions registry policy
 * @return: 0 on success, -1 on failure
 */
int unset_mitigation_policy(void) {

  if (registry_value_exists(HKEY_LOCAL_MACHINE,
                            MITIGATION_OPTIONS_REGISTRY_PATH,
                            MITIGATION_OPTIONS_VALUE_NAME)) {
    DWORD dataSize;
    BYTE *value =
        get_registry_key(HKEY_LOCAL_MACHINE, MITIGATION_OPTIONS_REGISTRY_PATH,
                         MITIGATION_OPTIONS_VALUE_NAME, &dataSize);
    if (value) {
      pretty_print(LOG_INFO, "Current registry value:");
      print_binary_data(value, dataSize);
      free(value);
    }
    if (set_registry_key(
            HKEY_LOCAL_MACHINE, MITIGATION_OPTIONS_REGISTRY_PATH,
            MITIGATION_OPTIONS_VALUE_NAME, MITIGATION_OPTIONS_VALUE_DEFAULT,
            sizeof(MITIGATION_OPTIONS_VALUE_DEFAULT), REG_BINARY) != 0) {
      pretty_print(LOG_ERROR, "Failed to set registry value");
      return -1;
    }

    value =
        get_registry_key(HKEY_LOCAL_MACHINE, MITIGATION_OPTIONS_REGISTRY_PATH,
                         MITIGATION_OPTIONS_VALUE_NAME, &dataSize);
    if (value) {
      pretty_print(LOG_SUCCESS, "Registry value verified:");
      print_binary_data(value, dataSize);
      free(value);
    } else {
      pretty_print(LOG_ERROR, "Failed to verify registry value");
      return -1;
    }
  } else {
    pretty_print(LOG_INFO, "Registry value does not exist, nothing to do");
  }

  return 0;
}