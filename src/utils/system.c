#include "../../include/utils/system.h"

//////////////////////////////////////////////////////////////
// System Functions //////////////////////////////////////////
//////////////////////////////////////////////////////////////

/**
 * Check if the current process is running with elevated privileges (as
 * Administrator) using CheckTokenMembership against the built-in Administrators
 * SID.
 *
 * Note: CheckTokenMembership(NULL, ...) inspects the *effective* token of the
 * current thread, not the primary process token. If the thread is impersonating
 * (e.g., after a token-swap or impersonation call), this reflects the
 * impersonated identity rather than the original process elevation. For a
 * UAC-aware check that is always tied to the process token regardless of
 * impersonation, open the process token with OpenProcessToken and query
 * TokenElevation via GetTokenInformation instead.
 *
 * @return: elevation_status_t element
 */
elevation_status_t is_elevated(void) {
  BOOL isAdmin = FALSE;
  PSID adminGroup = NULL;
  SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

  if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                               DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                               &adminGroup)) {

    if (!CheckTokenMembership(NULL, adminGroup, &isAdmin)) {
      pretty_print(LOG_ERROR, "Failed to check token membership: %lu",
                   GetLastError());
      FreeSid(adminGroup);
      return ELEVATION_ERROR;
    }

    FreeSid(adminGroup);
  } else {
    pretty_print(LOG_ERROR, "Failed to create admin SID: %lu", GetLastError());
    return ELEVATION_ERROR;
  }

  if (isAdmin) {
    pretty_print(LOG_INFO, "Process is running with elevated privileges");
    return ELEVATION_ELEVATED;
  } else {
    pretty_print(LOG_INFO, "Process is running with standard privileges");
    return ELEVATION_NOT_ELEVATED;
  }
}