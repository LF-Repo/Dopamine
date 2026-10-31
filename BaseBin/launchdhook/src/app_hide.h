#ifndef APP_HIDE_H
#define APP_HIDE_H

// Diagnostic log shared by app_hide.m and the spawn hook. Defined here because
// both files write to it and it needs to be a single path.
#define APP_HIDE_LOG_PATH "/var/mobile/Documents/noinject_log.txt"

// RootHide-style jailbreak-level hiding for "Hide for App" (ported from
// RootHide's libjailbreak/src/roothider/xpc_hook.m + blacklist.cpp):
// launchd hides jailbreak processes / jobs / coalitions from "hidden" apps'
// XPC enumeration queries, instead of relying on the injected dylib's own hooks.

// Install the XPC reply hooks (must run in launchd, pid 1).
void app_hide_init(void);

// The spawn hook uses these to mark a just-spawned hidden app as blacklisted:
//   void *pidp = app_hide_alloc_pid();
//   ... posix_spawn writes the child pid into *pidp ...
//   app_hide_commit_pid(pidp);
void *app_hide_alloc_pid(void);
void app_hide_commit_pid(void *pidp);

// Query whether a pid is currently a "hidden" (blacklisted) app. Used by the
// jbserver's blacklist-check action so rootlesshooks (lsd) can filter jailbreak
// URL schemes for hidden apps without any per-app injection.
bool app_hide_is_blacklisted_pid(pid_t pid);

// RootHide-style "no-injection" mode: temporarily hide the jailbreak globally
// (remove /var/jb, unmount fakelib) so a bare-spawned (uninjected) app sees a
// clean system, then restore once the app exits.
void app_hide_global_hide(void);
void app_hide_global_restore(void);
void app_hide_watch_exit(pid_t pid);

// Record a no-inject app that was just spawned. The hide is re-derived from this
// set (plus liveness checks) rather than from a counter, so it cannot drift.
void app_hide_note_pid(pid_t pid);

// A no-inject app was launched but never produced a pid (spawn failure). Release
// the pending-hide window so the jailbreak is not left hidden for an app that
// does not exist.
void app_hide_abort_pending_hide(void);

// "Jailbreak app resurrection": while the jailbreak is hidden (a no-inject app
// is running), spawning a jailbreak app (under /var/jb/) restores the jailbreak
// so the jailbreak app can run. No re-hide on exit (accepted limitation).
bool app_hide_is_currently_hidden(void);

// True while a resurrection is holding the jailbreak visible on behalf of still
// running no-inject apps, or while a hide is in flight without a known pid. The
// watchdog uses this to keep reconciling during those windows instead of assuming
// "not hidden" means "nothing to do".
bool app_hide_has_pending_no_inject_state(void);

bool app_hide_is_jailbreak_app(const char *path);

// Settings.app (stock /Applications/Preferences.app) behaves like a jailbreak
// app: it lists every tweak's settings from /var/jb/Library/PreferenceBundles,
// so it must resurrect the jailbreak too.
bool app_hide_is_settings_app(const char *path);
void app_hide_resurrect_for_jb_app(void);

// Track a jailbreak app's pid after resurrection; it gets killed when the
// jailbreak is re-hidden (so it doesn't write into the real jbroot after /var/jb
// is removed).
void app_hide_track_jailbreak_app(pid_t pid);

// Schedule a delayed advisory app-state sample for a just-spawned no-inject app,
// and make sure the hide watchdog is running. The watchdog (not this sample) owns
// the decision to restore, because a single early app-state read cannot tell a
// still-launching foreground app from a background launch.
void app_hide_check_role_after_spawn(pid_t pid);

// Undo a jailbreak-level hide that was still in effect when the previous
// userspace ended (reboot-while-hidden, logout-while-hidden).
//
// The hide is a one-way ratchet on its own: it removes /var/jb, unmounts fakelib
// and leaves .safe_mode on disk, and no launchd-side code puts any of that back.
// Called only from launchdhook's startup path, where "the previous session ended
// hidden" is a known fact rather than a guess. Idempotent.
void app_hide_recover_hidden_jailbreak(void);

// True when this executable is an extension of an app whose Hide Manager level
// is High or Max (hideLevel >= 2), and the extension must therefore be refused
// outright. Extensions (.appex, PlugIns/, Extensions/) are normally started by
// the system while the parent app is not foreground, so no hide would be active
// for them; refusing the spawn is the only way to keep them from running with a
// fully visible jailbreak. Returns false for anything that is not such an
// extension, so the ordinary spawn path is unaffected.
bool app_hide_should_refuse_extension_launch(const char *path);

#endif // APP_HIDE_H
