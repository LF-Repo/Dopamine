#import <xpc/xpc.h>
#import <xpc_private.h>
#import <sys/types.h>
#import <sys/stat.h>
#import <sys/mount.h>
#import <string.h>
#import <unistd.h>
#import <substrate.h>
#import <mach-o/dyld.h>
#import <libjailbreak/libjailbreak.h>
#import <Foundation/Foundation.h>
#import <litehook.h>

#import "daemon_hook.h"
#import "app_hide.h"

void xpc_dictionary_add_launch_daemon_plist_at_path(xpc_object_t xdict, const char *path)
{
	int ldFd = open(path, O_RDONLY);
	if (ldFd >= 0) {
		struct stat s = {};
		if(fstat(ldFd, &s) != 0) {
			close(ldFd);
			return;
		}
		size_t len = s.st_size;
		void *addr = mmap(NULL, len, PROT_READ, MAP_FILE | MAP_PRIVATE, ldFd, 0);
		if (addr != MAP_FAILED) {
			xpc_object_t daemonXdict = xpc_create_from_plist(addr, len);
			if (daemonXdict) {
				xpc_dictionary_set_value(xdict, path, daemonXdict);
			}
			munmap(addr, len);
		}
		close(ldFd);
	}
}

// A userspace reboot tears down the whole userspace. If the jailbreak is still
// globally hidden at that point (a NoInject app is running in the background),
// the reboot cannot complete: launchd re-reads /var/jb while the symlink is gone
// and the quarantined jailbreak files are still moved away, so the logout /
// reboot hangs (or comes back with a half-torn-down userspace).
//
// Therefore: force-restore the jailbreak state right before a userspace reboot
// is allowed to proceed. This is idempotent and a no-op when nothing is hidden.
void app_hide_force_restore_before_userspace_reboot(void)
{
	// This XPC key can be queried more than once per reboot request; only ever do
	// the real work once per hidden-state, otherwise we'd spawn jbctl repeatedly
	// while launchd is busy answering.
	static bool didRestore = false;

	if (!app_hide_is_currently_hidden()) {
		didRestore = false; // armed again for the next hide cycle
		return;
	}

	// Cheap heuristic so we do no real work in the common (nothing hidden) case:
	// while hidden, /var/jb is removed and /usr/lib carries the fakelib mount.
	struct statfs fsb;
	bool fakelibMounted = (statfs("/usr/lib", &fsb) == 0) && (strcmp(fsb.f_mntonname, "/usr/lib") != 0);
	bool jbSymlinkGone = (access("/var/jb", F_OK) != 0);
	if (!fakelibMounted && !jbSymlinkGone) return;
	if (didRestore) return;
	didRestore = true;

	app_hide_force_restore();
}

xpc_object_t (*xpc_dictionary_get_value_orig)(xpc_object_t xdict, const char *key);
xpc_object_t xpc_dictionary_get_value_hook(xpc_object_t xdict, const char *key)
{
	xpc_object_t origXvalue = xpc_dictionary_get_value_orig(xdict, key);
	if (!strcmp(key, "LaunchDaemons")) {
		if (xpc_get_type(origXvalue) == XPC_TYPE_DICTIONARY) {
			for (NSString *daemonPlistName in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:JBROOT_PATH(@"/basebin/LaunchDaemons") error:nil]) {
				if ([daemonPlistName.pathExtension isEqualToString:@"plist"]) {
					xpc_dictionary_add_launch_daemon_plist_at_path(origXvalue, [JBROOT_PATH(@"/basebin/LaunchDaemons") stringByAppendingPathComponent:daemonPlistName].fileSystemRepresentation);
				}
			}
			for (NSString *daemonPlistName in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:JBROOT_PATH(@"/Library/LaunchDaemons") error:nil]) {
				if ([daemonPlistName.pathExtension isEqualToString:@"plist"]) {
					xpc_dictionary_add_launch_daemon_plist_at_path(origXvalue, [JBROOT_PATH(@"/Library/LaunchDaemons") stringByAppendingPathComponent:daemonPlistName].fileSystemRepresentation);
				}
			}
		}
	}
	else if (!strcmp(key, "Paths")) {
		if (xpc_get_type(origXvalue) == XPC_TYPE_ARRAY) {
			xpc_array_set_string(origXvalue, XPC_ARRAY_APPEND, JBROOT_PATH("/basebin/LaunchDaemons"));
			xpc_array_set_string(origXvalue, XPC_ARRAY_APPEND, JBROOT_PATH("/Library/LaunchDaemons"));
		}
	}
	else if (!strcmp(key, "com.apple.private.xpc.launchd.userspace-reboot")) {
		if (!origXvalue || xpc_get_type(origXvalue) == XPC_TYPE_BOOL) {
			bool origValue = false;
			if (origXvalue) {
				origValue = xpc_bool_get_value(origXvalue);
			}
			if (!origValue) {
				// A userspace reboot must never run with the jailbreak still
				// globally hidden, otherwise logout / reboot userspace hangs.
				app_hide_force_restore_before_userspace_reboot();

				// Allow watchdogd to do userspace reboots
				return xpc_dictionary_get_value_orig(xdict, "com.apple.private.iowatchdog.user-access");
			}
		}
	}
	return origXvalue;
}

void initDaemonHooks(void)
{
	xpc_dictionary_get_value_orig = xpc_dictionary_get_value;
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, xpc_dictionary_get_value, (void *)xpc_dictionary_get_value_hook, NULL);
}