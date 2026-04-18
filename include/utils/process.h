#ifndef PROCESS_H
#define PROCESS_H

#include "logger.h"
#include <windows.h>

// ── Enumeration ───────────────────────────────────────────────────────────────

// Find a process by exact name (case-insensitive).
// Returns 0 if not found.
DWORD find_pid_by_name(const char *name);

// Find the first process whose name contains substr (case-insensitive).
// Useful when targeting processes with version-suffixed names ("MsMpEng").
// Returns 0 if not found.
DWORD find_pid_containing(const char *substr);

// Print a formatted table of all running processes (PID, PPID, session, name).
void list_processes(void);

// ── Termination ───────────────────────────────────────────────────────────────

// Terminate a process by PID. Returns 0 on success, -1 on failure.
// Call enable_privilege("SeDebugPrivilege") first for cross-session targets.
int kill_process_by_pid(DWORD pid);

// Find the first process matching name (exact, case-insensitive) and kill it.
int kill_process_by_name(const char *name);

// ── Injection Detection ───────────────────────────────────────────────────────

// Scan a process's virtual address space for private executable memory regions.
//
// MEM_PRIVATE + PAGE_EXECUTE* regions that are not backed by a mapped file
// are strong indicators of shellcode drops or reflective PE loading.
// Prints each suspicious region with base address, size, and protection flags.
//
// @param pid: Target process ID. Pass 0 to scan all accessible processes.
void scan_process_injections(DWORD pid);

// Scan thread start addresses for threads whose entry points fall outside
// any loaded image (i.e., start address resolves to private/mapped memory).
//
// This catches CreateRemoteThread-style injections and thread hijacks.
// Uses NtQueryInformationThread(ThreadQuerySetWin32StartAddress) loaded
// dynamically from ntdll to avoid a static dependency on an undocumented export.
//
// @param pid: Target process ID. Pass 0 to scan all accessible processes.
void scan_thread_injections(DWORD pid);

#endif // PROCESS_H
