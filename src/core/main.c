#include "../../include/core/common.h"
#include "../../include/core/mitigation_option.h"
#include "../../include/utils/system.h"

int main(void) {

  print_banner();

  elevation_status_t status = is_elevated();

  switch (status) {
  case ELEVATION_ELEVATED:
    pretty_print(LOG_SUCCESS, "Administrator privileges detected");
    break;
  case ELEVATION_NOT_ELEVATED:
    pretty_print(LOG_WARNING,
                 "Standard user privileges - some operations may fail");
    return 1;
  case ELEVATION_ERROR:
    pretty_print(LOG_ERROR, "Could not determine elevation status");
    return 1;
  }

  set_mitigation_policy();

  printf("\nPress Enter to exit...");
  getchar();

  return 0;
}
