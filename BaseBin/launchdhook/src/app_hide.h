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

#endif // APP_HIDE_H
