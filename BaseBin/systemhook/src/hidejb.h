#ifndef SYSTEMHOOK_HIDEJB_H
#define SYSTEMHOOK_HIDEJB_H

#include <stdbool.h>

// Returns true if the current process should hide jailbreak traces from itself
// (i.e. launchdhook spawned it with DOPAMINE_APP_HIDE=1).
bool hidejb_enabled(void);

// Installs per-process jailbreak-hiding hooks (filesystem paths + sysctl).
// This must be called after litehook's memory-hook routing is set up
// (on iOS 19+ that means after hookd_provider_init), but before any of the
// normal systemhook hooks (TweakLoader, csops, necp, ...) would be installed,
// because a "hidden" app must never load tweaks or expose the jailbreak.
void hidejb_init(const char *jbroot);

#endif // SYSTEMHOOK_HIDEJB_H
