#include "../../include/utils/service.h"

//////////////////////////////////////////////////////////////
// Internal Helpers //////////////////////////////////////////
//////////////////////////////////////////////////////////////

/**
 * Open the Service Control Manager with the requested access rights
 * @param access: Desired access (e.g., SC_MANAGER_CREATE_SERVICE)
 * @return: Handle on success, NULL on failure
 */
static SC_HANDLE open_scm(DWORD access) {
  SC_HANDLE hSCM =
      OpenSCManagerA(NULL,  // Local machine
                     NULL,  // Default database (SERVICES_ACTIVE_DATABASE)
                     access // Desired access
      );

  if (!hSCM) {
    pretty_print(LOG_ERROR, "Failed to open Service Control Manager: %lu",
                 GetLastError());
  }

  return hSCM;
}

/**
 * Open an existing service with the requested access rights
 * @param hSCM:        Handle to the SCM
 * @param serviceName: Name of the service to open
 * @param access:      Desired access (e.g., SERVICE_START)
 * @return: Handle on success, NULL on failure
 */
static SC_HANDLE open_service(SC_HANDLE hSCM, const char *serviceName,
                              DWORD access) {
  SC_HANDLE hService = OpenServiceA(hSCM,        // SCM handle
                                    serviceName, // Service name
                                    access       // Desired access
  );

  if (!hService) {
    pretty_print(LOG_ERROR, "Failed to open service '%s': %lu", serviceName,
                 GetLastError());
  }

  return hService;
}

/**
 * Poll the service status until it leaves a pending state or the timeout
 * elapses.
 *
 * Elapsed time is measured with GetTickCount64() rather than accumulated Sleep
 * durations to avoid drift: QueryServiceStatus itself takes non-zero time, so
 * purely summing sleep intervals would undercount real elapsed time and could
 * loop past the intended deadline.
 *
 * @param hService:     Handle to the service
 * @param pendingState: The transitional state to wait through (e.g.,
 *                      SERVICE_STOP_PENDING)
 * @param targetState:  The expected final state (e.g., SERVICE_STOPPED)
 * @return: 1 if target state reached, 0 on timeout or error
 */
static int wait_for_service_state(SC_HANDLE hService, DWORD pendingState,
                                  DWORD targetState) {
  SERVICE_STATUS status;
  ULONGLONG start = GetTickCount64();

  while (GetTickCount64() - start < SERVICE_STATUS_TIMEOUT_MS) {
    if (!QueryServiceStatus(hService, &status)) {
      pretty_print(LOG_ERROR, "Failed to query service status: %lu",
                   GetLastError());
      return 0;
    }

    if (status.dwCurrentState == targetState) {
      return 1;
    }

    if (status.dwCurrentState != pendingState) {
      pretty_print(LOG_WARNING, "Service reached unexpected state: %lu",
                   status.dwCurrentState);
      return 0;
    }

    Sleep(SERVICE_STATUS_POLL_INTERVAL_MS);
  }

  pretty_print(LOG_WARNING, "Timed out waiting for service state transition");
  return 0;
}

//////////////////////////////////////////////////////////////
// Service Functions /////////////////////////////////////////
//////////////////////////////////////////////////////////////

/**
 * Create and register a new Windows service
 * @param serviceName: Internal service name (used by SCM)
 * @param displayName: Human-readable name shown in services.msc
 * @param binaryPath:  Absolute path to the service executable
 * @param startType:   Start type (SERVICE_AUTO_START, SERVICE_DEMAND_START,
 * SERVICE_DISABLED)
 * @return: 0 on success, -1 on failure
 * Links:
 * https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea
 */
int create_service(const char *serviceName, const char *displayName,
                   const char *binaryPath, DWORD startType) {
  if (!serviceName || !displayName || !binaryPath) {
    pretty_print(LOG_ERROR, "Invalid parameters");
    return -1;
  }

  SC_HANDLE hSCM = open_scm(SC_MANAGER_CREATE_SERVICE);
  if (!hSCM)
    return -1;

  SC_HANDLE hService = CreateServiceA(hSCM,        // SCM handle
                                      serviceName, // Internal service name
                                      displayName, // Display name
                                      SERVICE_ALL_ACCESS, // Desired access
                                      SERVICE_WIN32_OWN_PROCESS, // Service type
                                      startType,                 // Start type
                                      SERVICE_ERROR_NORMAL, // Error control
                                      binaryPath, // Path to executable
                                      NULL,       // No load ordering group
                                      NULL,       // No tag identifier
                                      NULL,       // No dependencies
                                      NULL,       // LocalSystem account
                                      NULL        // No password
  );

  if (!hService) {
    pretty_print(LOG_ERROR, "Failed to create service '%s': %lu", serviceName,
                 GetLastError());
    CloseServiceHandle(hSCM);
    return -1;
  }

  pretty_print(LOG_SUCCESS, "Service '%s' created successfully", serviceName);

  CloseServiceHandle(hService);
  CloseServiceHandle(hSCM);
  return 0;
}

/**
 * Start a stopped service and wait for it to reach SERVICE_RUNNING
 * @param serviceName: Internal name of the service to start
 * @return: 0 on success, -1 on failure
 * Links:
 * https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicea
 */
int start_service(const char *serviceName) {
  if (!serviceName) {
    pretty_print(LOG_ERROR, "Invalid parameters");
    return -1;
  }

  SC_HANDLE hSCM = open_scm(SC_MANAGER_CONNECT);
  if (!hSCM)
    return -1;

  SC_HANDLE hService =
      open_service(hSCM, serviceName, SERVICE_START | SERVICE_QUERY_STATUS);
  if (!hService) {
    CloseServiceHandle(hSCM);
    return -1;
  }

  if (!StartServiceA(hService, // Service handle
                     0,        // No arguments
                     NULL      // No argument array
                     )) {
    DWORD err = GetLastError();
    if (err == ERROR_SERVICE_ALREADY_RUNNING) {
      pretty_print(LOG_INFO, "Service '%s' is already running", serviceName);
      CloseServiceHandle(hService);
      CloseServiceHandle(hSCM);
      return 0;
    }
    pretty_print(LOG_ERROR, "Failed to start service '%s': %lu", serviceName,
                 err);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return -1;
  }

  if (!wait_for_service_state(hService, SERVICE_START_PENDING,
                              SERVICE_RUNNING)) {
    pretty_print(LOG_ERROR, "Service '%s' did not reach running state",
                 serviceName);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return -1;
  }

  pretty_print(LOG_SUCCESS, "Service '%s' started successfully", serviceName);

  CloseServiceHandle(hService);
  CloseServiceHandle(hSCM);
  return 0;
}

/**
 * Send a stop control to a running service and wait for SERVICE_STOPPED
 * @param serviceName: Internal name of the service to stop
 * @return: 0 on success, -1 on failure
 * Links:
 * https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-controlservice
 */
int stop_service(const char *serviceName) {
  if (!serviceName) {
    pretty_print(LOG_ERROR, "Invalid parameters");
    return -1;
  }

  SC_HANDLE hSCM = open_scm(SC_MANAGER_CONNECT);
  if (!hSCM)
    return -1;

  SC_HANDLE hService =
      open_service(hSCM, serviceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
  if (!hService) {
    CloseServiceHandle(hSCM);
    return -1;
  }

  SERVICE_STATUS status;

  if (!ControlService(hService,             // Service handle
                      SERVICE_CONTROL_STOP, // Control code
                      &status               // Receives current status
                      )) {
    DWORD err = GetLastError();
    if (err == ERROR_SERVICE_NOT_ACTIVE) {
      pretty_print(LOG_INFO, "Service '%s' is already stopped", serviceName);
      CloseServiceHandle(hService);
      CloseServiceHandle(hSCM);
      return 0;
    }
    pretty_print(LOG_ERROR, "Failed to send stop control to '%s': %lu",
                 serviceName, err);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return -1;
  }

  if (!wait_for_service_state(hService, SERVICE_STOP_PENDING,
                              SERVICE_STOPPED)) {
    pretty_print(LOG_ERROR, "Service '%s' did not reach stopped state",
                 serviceName);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return -1;
  }

  pretty_print(LOG_SUCCESS, "Service '%s' stopped successfully", serviceName);

  CloseServiceHandle(hService);
  CloseServiceHandle(hSCM);
  return 0;
}

/**
 * Delete a service from the SCM database
 * The service must be stopped before deletion — this function does not stop it
 * @param serviceName: Internal name of the service to delete
 * @return: 0 on success, -1 on failure
 * Links:
 * https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-deleteservice
 */
int delete_service(const char *serviceName) {
  if (!serviceName) {
    pretty_print(LOG_ERROR, "Invalid parameters");
    return -1;
  }

  SC_HANDLE hSCM = open_scm(SC_MANAGER_CONNECT);
  if (!hSCM)
    return -1;

  SC_HANDLE hService = open_service(hSCM, serviceName, DELETE);
  if (!hService) {
    CloseServiceHandle(hSCM);
    return -1;
  }

  if (!DeleteService(hService)) {
    pretty_print(LOG_ERROR, "Failed to delete service '%s': %lu", serviceName,
                 GetLastError());
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return -1;
  }

  pretty_print(LOG_SUCCESS, "Service '%s' deleted successfully", serviceName);

  CloseServiceHandle(hService);
  CloseServiceHandle(hSCM);
  return 0;
}

/**
 * Modify the configuration of an existing service
 * Pass NULL or SERVICE_NO_CHANGE to leave a field unchanged
 * @param serviceName:    Internal name of the service to modify
 * @param newDisplayName: New display name, or NULL to leave unchanged
 * @param newBinaryPath:  New path to the service executable, or NULL to leave
 * unchanged
 * @param newStartType:   New start type, or SERVICE_NO_CHANGE to leave
 * unchanged
 * @return: 0 on success, -1 on failure
 * Links:
 * https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfiga
 */
int modify_service(const char *serviceName, const char *newDisplayName,
                   const char *newBinaryPath, DWORD newStartType) {
  if (!serviceName) {
    pretty_print(LOG_ERROR, "Invalid parameters");
    return -1;
  }

  SC_HANDLE hSCM = open_scm(SC_MANAGER_CONNECT);
  if (!hSCM)
    return -1;

  SC_HANDLE hService = open_service(hSCM, serviceName, SERVICE_CHANGE_CONFIG);
  if (!hService) {
    CloseServiceHandle(hSCM);
    return -1;
  }

  if (!ChangeServiceConfigA(hService,          // Service handle
                            SERVICE_NO_CHANGE, // Service type — unchanged
                            newStartType,      // Start type
                            SERVICE_NO_CHANGE, // Error control — unchanged
                            newBinaryPath,     // New binary path, or NULL
                            NULL,          // Load ordering group — unchanged
                            NULL,          // Tag ID — unchanged
                            NULL,          // Dependencies — unchanged
                            NULL,          // Account name — unchanged
                            NULL,          // Password — unchanged
                            newDisplayName // New display name, or NULL
                            )) {
    pretty_print(LOG_ERROR, "Failed to modify service '%s': %lu", serviceName,
                 GetLastError());
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return -1;
  }

  pretty_print(LOG_SUCCESS, "Service '%s' modified successfully", serviceName);

  CloseServiceHandle(hService);
  CloseServiceHandle(hSCM);
  return 0;
}