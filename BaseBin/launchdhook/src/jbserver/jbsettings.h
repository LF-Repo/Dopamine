#include <xpc/xpc.h>

int jbsettings_get(const char *key, xpc_object_t *valueOut);
int jbsettings_set(const char *key, xpc_object_t value);

// Restore the persisted jailbreak settings into gSystemInfo. Call once from
// launchd's startup path, before any client can read them back.
void jbsettings_load(void);
