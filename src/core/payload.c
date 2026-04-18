#include "../../include/core/payload.h"

/*
 * Replace the placeholder below with the actual payload bytes.
 *
 * Quick conversion from a compiled binary:
 *
 *   Linux (xxd):
 *     xxd -i payload.exe
 *
 *   Python:
 *     python3 -c "
 *       d = open('payload.exe','rb').read()
 *       print('{' + ','.join(hex(b) for b in d) + '}')
 *       print(len(d))
 *     "
 *
 *   PowerShell (on Windows):
 *     $b=[IO.File]::ReadAllBytes('payload.exe')
 *     '0x'+($b|ForEach-Object{$_.ToString('x2')})-join',0x'
 */
const BYTE PAYLOAD_DATA[] = {
    /* TODO: replace with real payload bytes */
    0x00
};

const SIZE_T PAYLOAD_SIZE = sizeof(PAYLOAD_DATA);
