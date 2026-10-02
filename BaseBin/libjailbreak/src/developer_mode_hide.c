// developer_mode_hide.c
//
// Hides the AMFI "developer mode" flag for the global HideJailbreak feature.
//
// RootHide's equivalent is hideDeveloperMode() in libjailbreak/src/roothider/
// common.m, which swaps the two sysctl OIDs (security.mac.amfi.developer_mode_
// status <-> security.mac.amfi.launch_env_logging) inside the kernel's sysctl
// list so that the flag is *reported* as 0 while the real kernel state stays
// untouched. That swap is strictly better (it does not disturb actual developer
// mode), but it depends on the developer_mode_status / launch_env_logging kernel
// symbols which this fork does not have in its symbol table yet.
//
// As a safe, dependency-free equivalent we toggle the developer_mode_enabled
// storage byte in exactly the same way DOJailbreaker's ensureDevModeEnabled()
// already writes 1 to it during jailbreak (see Application/Dopamine/Jailbreak/
// DOJailbreaker.m). Writing 0 makes sysctlbyname("security.mac.amfi.developer_
// mode_status") return 0 (stock-looking); writing 1 restores the real jailbroken
// state. The call is guarded and non-fatal: on an unsupported device the symbol
// lookup yields 0 and we simply return -1 so the caller can skip this step.

#include "developer_mode_hide.h"
#include "info.h"
#include "primitives.h"

int developer_mode_set_hidden(bool hidden)
{
    // Locate the developer-mode storage exactly like DOJailbreaker's
    // ensureDevModeEnabled does:
    //   * non-SPTM: developer_mode_enabled is a global that holds a pointer to
    //     the real 1-byte storage (kread64 to follow the pointer).
    //   * SPTM:     txm_developer_mode_storage is the storage address itself.
    uint64_t developer_mode_storage = 0;
    if (ksymbol(developer_mode_enabled)) {
        developer_mode_storage = kread64(ksymbol(developer_mode_enabled));
    }
    else if (ksymbol_txm(txm_developer_mode_storage)) {
        developer_mode_storage = ksymbol_txm(txm_developer_mode_storage);
    }

    if (!developer_mode_storage) {
        // Not jailbroken, or a device where we cannot locate (and must not
        // blindly write) the storage. Nothing to do.
        return -1;
    }

    // hidden  -> 0 : "developer mode disabled" (stock)
    // visible -> 1 : developer mode enabled (the real Dopamine state)
    uint8_t value = hidden ? 0 : 1;

    // kwrite8 is non-fatal on its own (returns an error code); if the storage
    // lives in TXM-protected memory this write is simply rejected and the caller
    // logs/skips. No kernel state is corrupted.
    return kwrite8(developer_mode_storage, value);
}
