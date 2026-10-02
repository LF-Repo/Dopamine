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

#endif // APP_HIDE_H
