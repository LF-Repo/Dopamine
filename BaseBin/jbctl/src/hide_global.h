#ifndef HIDE_GLOBAL_H
#define HIDE_GLOBAL_H

// RootHide-style global hiding helpers used by the "Hide for App" no-injection
// mode (and reusable by the app-side global HideJailbreak). These run as root
// inside jbctl and modify the on-disk state that a bare-spawned (uninjected)
// app would otherwise still see: jailbreak apps' URL schemes and jailbreak
// files under /var/mobile/Library.

int hide_global_urlschemes_hide(void);
int hide_global_urlschemes_show(void);
int hide_global_audit_hide(void);
int hide_global_audit_restore(void);

#endif // HIDE_GLOBAL_H
