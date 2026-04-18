#include "../../include/utils/process.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <tlhelp32.h>

// ThreadQuerySetWin32StartAddress — undocumented but stable since XP.
// Returns the Win32 start address passed to CreateThread / CreateRemoteThread.
#define THREAD_QUERY_SET_WIN32_START_ADDRESS 9

typedef LONG (WINAPI *pfnNtQueryInformationThread)(
    HANDLE ThreadHandle,
    DWORD  ThreadInformationClass,
    PVOID  ThreadInformation,
    ULONG  ThreadInformationLength,
    PULONG ReturnLength
);

//////////////////////////////////////////////////////////////
// Internal Helpers //////////////////////////////////////////
//////////////////////////////////////////////////////////////

// Case-insensitive substring search.
static int ci_contains(const char *haystack, const char *needle) {
  size_t nlen = strlen(needle);
  size_t hlen = strlen(haystack);
  if (nlen > hlen) return 0;
  for (size_t i = 0; i <= hlen - nlen; i++) {
    if (_strnicmp(haystack + i, needle, nlen) == 0) return 1;
  }
  return 0;
}

// Human-readable page-protection string (low byte only).
static const char *protect_str(DWORD p) {
  switch (p & 0xFF) {
  case PAGE_EXECUTE:           return "--X-";
  case PAGE_EXECUTE_READ:      return "-RX-";
  case PAGE_EXECUTE_READWRITE: return "WRX!";
  case PAGE_READONLY:          return "-R--";
  case PAGE_READWRITE:         return "WR--";
  case PAGE_NOACCESS:          return "----";
  default:                     return "????";
  }
}

// Type of memory region.
static const char *type_str(DWORD t) {
  switch (t) {
  case MEM_IMAGE:   return "IMAGE";
  case MEM_MAPPED:  return "MAPPED";
  case MEM_PRIVATE: return "PRIVATE";
  default:          return "UNKNOWN";
  }
}

//////////////////////////////////////////////////////////////
// Process Enumeration ///////////////////////////////////////
//////////////////////////////////////////////////////////////

DWORD find_pid_by_name(const char *name) {
  if (!name) return 0;

  HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnap == INVALID_HANDLE_VALUE) {
    pretty_print(LOG_ERROR, "find_pid_by_name: snapshot failed: %lu",
                 GetLastError());
    return 0;
  }

  PROCESSENTRY32 pe;
  pe.dwSize = sizeof(pe);
  DWORD result = 0;

  if (Process32First(hSnap, &pe)) {
    do {
      if (_stricmp(pe.szExeFile, name) == 0) {
        result = pe.th32ProcessID;
        break;
      }
    } while (Process32Next(hSnap, &pe));
  }

  CloseHandle(hSnap);
  return result;
}

DWORD find_pid_containing(const char *substr) {
  if (!substr) return 0;

  HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnap == INVALID_HANDLE_VALUE) {
    pretty_print(LOG_ERROR, "find_pid_containing: snapshot failed: %lu",
                 GetLastError());
    return 0;
  }

  PROCESSENTRY32 pe;
  pe.dwSize = sizeof(pe);
  DWORD result = 0;

  if (Process32First(hSnap, &pe)) {
    do {
      if (ci_contains(pe.szExeFile, substr)) {
        result = pe.th32ProcessID;
        break;
      }
    } while (Process32Next(hSnap, &pe));
  }

  CloseHandle(hSnap);
  return result;
}

void list_processes(void) {
  HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnap == INVALID_HANDLE_VALUE) {
    pretty_print(LOG_ERROR, "list_processes: snapshot failed: %lu",
                 GetLastError());
    return;
  }

  pretty_print(LOG_INFO, "Running processes:");
  printf("  %-8s  %-8s  %-5s  %s\n", "PID", "PPID", "SESS", "NAME");
  printf("  %-8s  %-8s  %-5s  %s\n", "---", "----", "----", "----");

  PROCESSENTRY32 pe;
  pe.dwSize = sizeof(pe);

  if (Process32First(hSnap, &pe)) {
    do {
      DWORD session = 0xFFFF;
      ProcessIdToSessionId(pe.th32ProcessID, &session);
      printf("  %-8lu  %-8lu  %-5lu  %s\n",
             pe.th32ProcessID, pe.th32ParentProcessID, session,
             pe.szExeFile);
    } while (Process32Next(hSnap, &pe));
  }

  CloseHandle(hSnap);
}

//////////////////////////////////////////////////////////////
// Process Termination ///////////////////////////////////////
//////////////////////////////////////////////////////////////

int kill_process_by_pid(DWORD pid) {
  HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
  if (!hProcess) {
    pretty_print(LOG_ERROR,
                 "kill_process_by_pid: OpenProcess(%lu) failed: %lu — "
                 "try enable_privilege(\"SeDebugPrivilege\") first",
                 pid, GetLastError());
    return -1;
  }

  BOOL ok = TerminateProcess(hProcess, 1);
  CloseHandle(hProcess);

  if (!ok) {
    pretty_print(LOG_ERROR,
                 "kill_process_by_pid: TerminateProcess(%lu) failed: %lu",
                 pid, GetLastError());
    return -1;
  }

  pretty_print(LOG_SUCCESS, "kill_process_by_pid: PID %lu terminated", pid);
  return 0;
}

int kill_process_by_name(const char *name) {
  DWORD pid = find_pid_by_name(name);
  if (!pid) {
    pretty_print(LOG_ERROR, "kill_process_by_name: '%s' not found", name);
    return -1;
  }
  return kill_process_by_pid(pid);
}

//////////////////////////////////////////////////////////////
// Injection Detection — VAD Scan ////////////////////////////
//////////////////////////////////////////////////////////////

// Scan one process's virtual address space for private executable regions.
static void scan_vad_single(DWORD pid) {
  HANDLE hProcess = OpenProcess(
      PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
  if (!hProcess) return; // silently skip inaccessible processes

  MEMORY_BASIC_INFORMATION mbi;
  LPVOID addr = NULL;
  int hits = 0;

  while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
    // Criterion: committed private (not file-backed) memory that is executable.
    // Legitimate code lives in MEM_IMAGE regions; shellcode and reflective
    // loaders almost always land in MEM_PRIVATE allocations.
    if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
        (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
      if (!hits) {
        pretty_print(LOG_WARNING,
                     "PID %-6lu — suspicious private executable region(s):",
                     pid);
      }
      printf("    base=%-16p  size=0x%-8zx  prot=%s  type=%s%s\n",
             mbi.BaseAddress, mbi.RegionSize,
             protect_str(mbi.Protect),
             type_str(mbi.Type),
             (mbi.Protect & PAGE_EXECUTE_READWRITE) ? "  [!!! RWX]" : "");
      hits++;
    }
    addr = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
  }

  CloseHandle(hProcess);
}

void scan_process_injections(DWORD pid) {
  if (pid != 0) {
    scan_vad_single(pid);
    return;
  }

  HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnap == INVALID_HANDLE_VALUE) return;

  PROCESSENTRY32 pe;
  pe.dwSize = sizeof(pe);

  if (Process32First(hSnap, &pe)) {
    do {
      if (pe.th32ProcessID <= 4) continue; // skip idle (0) and System (4)
      scan_vad_single(pe.th32ProcessID);
    } while (Process32Next(hSnap, &pe));
  }

  CloseHandle(hSnap);
}

//////////////////////////////////////////////////////////////
// Injection Detection — Thread Start Address Scan ///////////
//////////////////////////////////////////////////////////////

// Check every thread owned by target_pid using NtQueryInformationThread.
static void scan_thread_starts_single(
    DWORD target_pid, pfnNtQueryInformationThread NtQIT) {

  // TH32CS_SNAPTHREAD always returns all threads system-wide (pid param unused)
  HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (hSnap == INVALID_HANDLE_VALUE) return;

  HANDLE hProcess = OpenProcess(
      PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, target_pid);
  if (!hProcess) {
    CloseHandle(hSnap);
    return;
  }

  THREADENTRY32 te;
  te.dwSize = sizeof(te);
  int hits = 0;

  if (Thread32First(hSnap, &te)) {
    do {
      if (te.th32OwnerProcessID != target_pid) continue;

      HANDLE hThread =
          OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
      if (!hThread) continue;

      // Retrieve the Win32 start address recorded at CreateThread time.
      // For CreateRemoteThread injections this points into the injected region.
      PVOID start_addr = NULL;
      NtQIT(hThread, THREAD_QUERY_SET_WIN32_START_ADDRESS,
            &start_addr, sizeof(start_addr), NULL);
      CloseHandle(hThread);

      if (!start_addr) continue;

      MEMORY_BASIC_INFORMATION mbi;
      if (VirtualQueryEx(hProcess, start_addr, &mbi, sizeof(mbi)) != sizeof(mbi))
        continue;

      // Threads starting in MEM_IMAGE memory are normal (DLL/exe code).
      // MEM_PRIVATE or MEM_MAPPED start addresses are suspicious.
      if (mbi.Type != MEM_IMAGE) {
        if (!hits) {
          pretty_print(LOG_WARNING,
                       "PID %-6lu — thread(s) starting outside image memory:",
                       target_pid);
        }
        printf("    TID %-8lu  start=%-16p  prot=%s  type=%s\n",
               te.th32ThreadID, start_addr,
               protect_str(mbi.Protect), type_str(mbi.Type));
        hits++;
      }
    } while (Thread32Next(hSnap, &te));
  }

  if (hits) {
    pretty_print(LOG_WARNING,
                 "PID %-6lu — %d suspicious thread start address(es)", target_pid,
                 hits);
  }

  CloseHandle(hProcess);
  CloseHandle(hSnap);
}

void scan_thread_injections(DWORD pid) {
  // Load NtQueryInformationThread dynamically — undocumented, no import lib entry.
  pfnNtQueryInformationThread NtQIT =
      (pfnNtQueryInformationThread)GetProcAddress(
          GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");
  if (!NtQIT) {
    pretty_print(LOG_ERROR,
                 "scan_thread_injections: NtQueryInformationThread not found "
                 "in ntdll — cannot proceed");
    return;
  }

  if (pid != 0) {
    scan_thread_starts_single(pid, NtQIT);
    return;
  }

  HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnap == INVALID_HANDLE_VALUE) return;

  PROCESSENTRY32 pe;
  pe.dwSize = sizeof(pe);

  if (Process32First(hSnap, &pe)) {
    do {
      if (pe.th32ProcessID <= 4) continue;
      scan_thread_starts_single(pe.th32ProcessID, NtQIT);
    } while (Process32Next(hSnap, &pe));
  }

  CloseHandle(hSnap);
}
