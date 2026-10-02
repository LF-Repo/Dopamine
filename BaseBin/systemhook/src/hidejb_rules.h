#ifndef SYSTEMHOOK_HIDEJB_RULES_H
#define SYSTEMHOOK_HIDEJB_RULES_H

#include <stdbool.h>

// Set the canonical jbroot (resolves /var/jb) and our own bundle id.
// Called once from hidejb_init before any hook is installed.
void hidejb_rules_set_jbroot(const char *jbroot);
void hidejb_rules_set_self_bundle_id(void);

// True when `path` is a jailbreak path/file that should be hidden from the app.
//
// This lives in a SEPARATE compilation unit (hidejb_rules.c) so it can never be
// inlined into the hook functions in hidejb.c. Clang -Os has a register-
// allocation bug when this complex string-matching body is inlined into the
// hooks (it ends up calling strncmp with the hook's `flags`/`mode` args).
bool hidejb_rules_path_is_jailbreak(const char *path);

// True when `dirpath` is a directory that could contain entries which
// hidejb_rules_path_is_jailbreak() would hide. Used by the readdir hook to skip
// entry filtering entirely for the vast majority of directories (perf).
bool hidejb_rules_dir_may_hide_entries(const char *dirpath);

// True when the *basename* of `path` looks like a jailbreak library
// (systemhook.dylib, libellekit.dylib, ...). Used for dyld image hiding.
bool hidejb_rules_path_has_marker(const char *path);

// Cheap readdir-side decision: should `entryName`, a component directly inside
// `dirpath`, be hidden? Avoids building the full path in the hot loop.
bool hidejb_rules_dir_hides_entry(const char *dirpath, const char *entryName);

#endif
