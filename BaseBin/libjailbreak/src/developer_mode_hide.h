#ifndef DEVELOPER_MODE_HIDE_H
#define DEVELOPER_MODE_HIDE_H

#include <stdbool.h>

// Hide / unhide the AMFI "developer mode" flag that jailbreak detectors read via
//
//     sysctlbyname("security.mac.amfi.developer_mode_status", ...)
//
// On an iOS 16+ Dopamine device (installed through TrollStore) developer mode is
// force-enabled, so this sysctl returns 1 where a stock device returns 0. That
// single bit is one of the most common jailbreak tells and is NOT covered by the
// existing global hide (which only removes /var/jb, unmounts fakelib, quarantines
// jailbreak files and hides URL schemes).
//
//   hidden = true  -> report "developer mode disabled" (stock-looking)
//   hidden = false -> restore the real state (developer mode enabled)
//
// This is the safe equivalent of RootHide's hideDeveloperMode() (see
// BaseBin/libjailbreak/src/roothider/common.m in the RootHide tree). RootHide
// swaps the sysctl OIDs so the flag is only *reported* as off while the kernel
// state stays on; that needs the developer_mode_status / launch_env_logging
// kernel symbols which are not yet present in this fork's symbol table. Here we
// instead toggle the developer_mode_enabled storage exactly the way
// DOJailbreaker's ensureDevModeEnabled() already does, which makes the sysctl
// report 0 as well. It is guarded and non-fatal: if the storage symbol is
// unavailable the call returns -1 and the caller just skips this step.
//
// Caller requirement: the calling process must already have kernel read/write
// primitives. The Dopamine app does NOT (post-reboot), so HideJailbreak invokes
// this from jbctl, which first calls jbclient_initialize_primitives() to acquire
// krw + the serialized kernel-symbol table from launchdhook.
//
// Returns 0 on success, -1 when the storage cannot be located or written
// (not jailbroken, or an SPTM device whose txm storage is not writable).
int developer_mode_set_hidden(bool hidden);

#endif // DEVELOPER_MODE_HIDE_H
