#ifndef APP_HIDE_H
#define APP_HIDE_H

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

// "Jailbreak app resurrection": while the jailbreak is hidden (a no-inject app
// is running), spawning a jailbreak app (under /var/jb/) restores the jailbreak
// so the jailbreak app can run. No re-hide on exit (accepted limitation).
bool app_hide_is_currently_hidden(void);
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

// Schedule a delayed Mach-task-role check for a just-spawned no-inject app:
// if the app turns out to be a background launch, undo the hide. This fixes
// background refreshes/pushes from leaving the jailbreak hidden.
void app_hide_check_role_after_spawn(pid_t pid);

#endif // APP_HIDE_H
