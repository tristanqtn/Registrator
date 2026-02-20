# Registrator

A lightweight C framework for interacting with Windows systems. The goal is to keep the binary self-contained, dependency-free, and easy to build from both Windows and Linux environments.

---

## Project Structure

```
registrator/
│
├── include/
│   ├── core/
│   │   ├── common.h            # Global includes (windows.h, winreg.h, ...) and project-wide constants
│   │   └── mitigation_option.h # MitigationOption registry value modifiers 
│   └── utils/
│       ├── logger.h           # Logging types, banner macros (TOOL_NAME, TOOL_VERSION, ...)
│       ├── registry.h         # Registry read/write/check prototypes
│       ├── service.h          # Service creation/modification/deletion prototypes
│       └── system.h           # Elevation check prototype and elevation_status_t enum
│
├── src/
│   ├── core/
│   │   ├── common.c            # Definitions of shared binary constants (e.g. MitigationOptions values)
│   │   ├── main.c              # Entry point — orchestrates elevation check, registry operations
│   │   └── mitigation_option.c # MitigationOption registry value modifiers 
│   └── utils/
│       ├── logger.c           # print_banner(), pretty_print(), print_binary_data()
│       ├── registry.c         # set_registry_key(), get_registry_key(), append_registry_value(), delete_registry_value(), delete_registry_key(), registry_value_exists()
│       ├── service.c          # create_service(), start_service(), stop_service(), delete_service(), modify_service()
│       └── system.c           # is_elevated() via CheckTokenMembership
│
└── Makefile
```

### Dependency rule

`utils` never include `core` headers. The dependency arrow is strictly one-directional:

```
core  →  utils  →  (stdlib / WinAPI only)
```

If a utility needs a type or constant from `core`, that is a signal it has been misclassified and belongs in `core`.

---

## Building on Windows

### Prerequisites

- [MinGW-w64](https://www.mingw-w64.org/) or MSVC (cl.exe)
- Make (comes with MinGW, or use `nmake` with MSVC)

### Compile with MinGW

```bash
make
```

The default Makefile target compiles all sources and links against the required system libraries:

```makefile
CC      = gcc
CFLAGS  = -Wall -Wextra -O2
LDFLAGS = -ladvapi32

SRCS    = $(wildcard src/utils/*.c) $(wildcard src/core/*.c)
OUT     = registrator.exe

all:
	$(CC) $(CFLAGS) $(SRCS) -I include -o $(OUT) $(LDFLAGS)
```

### Compile with MSVC

```bash
cl /W3 /O2 \
   src/core/main.c src/core/common.c \
   src/utils/logger.c src/utils/registry.c src/utils/system.c \
   /I include \
   /link advapi32.lib \
   /out:registrator.exe
```

---

## Building on Linux (cross-compilation)

Cross-compiling for Windows from Linux requires the MinGW-w64 toolchain.

### Install the toolchain

```bash
# Debian / Ubuntu
sudo apt install mingw-w64

# Arch
sudo pacman -S mingw-w64-gcc

# Fedora
sudo dnf install mingw64-gcc
```

### Compile

```bash
x86_64-w64-mingw32-gcc \
    src/core/main.c src/core/common.c \
    src/utils/logger.c src/utils/registry.c src/utils/system.c \
    -I include \
    -ladvapi32 \
    -o registrator.exe
```

Or via Make by overriding the compiler:

```bash
make CC=x86_64-w64-mingw32-gcc
```

The output `registrator.exe` is a native Windows PE binary that can be copied and executed directly on any target machine.

---

## Producing a standalone binary (static linking)

By default, MinGW links against its own runtime DLLs (`libgcc_s_seh-1.dll`, `libstdc++-6.dll`, `libwinpthread-1.dll`). To bundle everything into a single executable with no external dependencies, pass the following flags at link time:

```bash
x86_64-w64-mingw32-gcc \
    src/core/main.c src/core/common.c \
    src/utils/logger.c src/utils/registry.c src/utils/system.c \
    -I include \
    -ladvapi32 \
    -static -static-libgcc -static-libstdc++ \
    -o registrator.exe
```

| Flag | Effect |
|---|---|
| `-static` | Links all libraries statically, including the C runtime |
| `-static-libgcc` | Embeds `libgcc` into the binary |
| `-static-libstdc++` | Embeds the C++ standard library (harmless for pure C, safe to include) |

The resulting binary will run on any Windows x64 machine without requiring any redistributable or runtime installation. Note that Windows system DLLs (`advapi32.dll`, `kernel32.dll`, etc.) are always loaded dynamically — this is expected and unavoidable, as they are guaranteed to be present on every Windows installation.

### Verify there are no unexpected DLL dependencies

On Linux, after building:

```bash
x86_64-w64-mingw32-objdump -p registrator.exe | grep "DLL Name"
```

Expected output (only system DLLs should appear):

```
DLL Name: KERNEL32.dll
DLL Name: msvcrt.dll
DLL Name: ADVAPI32.dll
```

If any MinGW runtime DLL (`libgcc`, `libwinpthread`, etc.) appears in this list, the static flags were not applied correctly.

---

## Requirements

- Target OS: Windows x64
- Requires administrator privileges at runtime (elevation is checked on startup)
- No third-party libraries — WinAPI only
```bash
gcc -I./include src/*.c -o program.exe
```