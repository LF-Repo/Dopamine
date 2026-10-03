// app_hide.m — RootHide-style jailbreak-level process hiding for "Hide for App".
//
// Ported from RootHide's libjailbreak/src/roothider/xpc_hook.m + blacklist.cpp.
// launchd hooks xpc_dictionary_create_reply / xpc_pipe_routine_reply and, for any
// request coming from a "hidden" (blacklisted) app, strips jailbreak coalitions
// out of the reply so the app cannot enumerate them.
//
// This runs entirely inside launchd — no app binary is modified. It complements
// the in-process hidejb hooks (which hide /var/jb etc. inside the injected app).

#import <Foundation/Foundation.h>

#include <libproc.h>
#include <sys/proc_info.h>
#include <mach/mach.h>
#include <mach/task_policy.h>
#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <pthread.h>
#include <xpc/xpc.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <litehook.h>
#include <unistd.h>
#include <limits.h>
#include <sys/mount.h>

#include <libjailbreak/libjailbreak.h>
#include <xpc_private.h>
#include <libjailbreak/codesign.h>
#include <libjailbreak/util.h>
#include "jbserver/jbserver_local.h"

extern void systemwide_domain_set_enabled(bool enabled);

// Not exposed by the public SDK; same value RootHide uses in common.m.
#define PROC_PIDUNIQIDENTIFIERINFO 17

// string_has_prefix is defined in systemhook/src/common/common.c, which is
// compiled into launchdhook as well.
bool string_has_prefix(const char *str, const char *prefix);

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

static int proc_get_pidversion(pid_t pid)
{
	struct {
		uint8_t  p_uuid[16];
		uint64_t p_uniqueid;
		uint64_t p_puniqueid;
		int32_t  p_idversion;
		uint32_t p_reserve2;
		uint64_t p_reserve3;
		uint64_t p_reserve4;
	} uniqidinfo = {0};
	if (proc_pidinfo(pid, PROC_PIDUNIQIDENTIFIERINFO, 0, &uniqidinfo, sizeof(uniqidinfo)) <= 0) return 0;
	return uniqidinfo.p_idversion;
}

static bool proc_get_identifier(pid_t pid, char *out, size_t outSize)
{
	struct { uint32_t magic; uint32_t length; } header = {0};
	if (csops(pid, CS_OPS_IDENTITY, &header, sizeof(header)) != 0 && errno != ERANGE) return false;
	uint32_t len = ntohl(header.length);
	if (len == 0 || len > 4096) return false;
	char *buf = malloc(len);
	if (!buf) return false;
	bool ok = (csops(pid, CS_OPS_IDENTITY, buf, len) == 0);
	if (ok) strlcpy(out, buf + sizeof(header), outSize);
	free(buf);
	return ok;
}

// Simplified App Store detection: Apple system identifiers are "safe" (never
// hidden). RootHide additionally whitelists every installed App Store app via
// StoredAppIdentifiers; that is a follow-up. For now this means a hidden app also
// loses sight of other third-party coalitions, which is the safer direction for a
// detection-focused app.
static bool is_safe_bundle_identifier(const char *identifier)
{
	if (!identifier || !identifier[0]) return false;
	if (string_has_prefix(identifier, "com.apple.")) return true;
	return false;
}

// ---------------------------------------------------------------------------
// blacklisted (hidden) process tracking
// ---------------------------------------------------------------------------

static NSMutableDictionary<NSNumber *, NSNumber *> *gBlacklistedState = nil; // pid -> pidversion
static pthread_rwlock_t gStateLock = PTHREAD_RWLOCK_INITIALIZER;

static void state_init(void)
{
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		gBlacklistedState = [NSMutableDictionary dictionary];
	});
}

static bool is_blacklisted_token(audit_token_t *token)
{
	pid_t pid = audit_token_to_pid(*token);
	if (pid <= 0) return false;
	state_init();

	__block bool blacklisted = false;
	pthread_rwlock_rdlock(&gStateLock);
	NSNumber *cachedVersion = gBlacklistedState[@(pid)];
	if (cachedVersion && cachedVersion.intValue == proc_get_pidversion(pid)) {
		blacklisted = true;
	}
	pthread_rwlock_unlock(&gStateLock);
	return blacklisted;
}

void *app_hide_alloc_pid(void)
{
	pid_t *pidp = (pid_t *)malloc(sizeof(pid_t));
	*pidp = 0;
	return pidp;
}

static void app_hide_log(NSString *msg);

void app_hide_commit_pid(void *pidp)
{
	if (!pidp) return;
	pid_t pid = *(pid_t *)pidp;
	if (pid > 0) {
		state_init();
		int pidversion = proc_get_pidversion(pid);
		pthread_rwlock_wrlock(&gStateLock);
		gBlacklistedState[@(pid)] = @(pidversion);
		pthread_rwlock_unlock(&gStateLock);
		app_hide_log([NSString stringWithFormat:@"commit pid %d (version %d), blacklist size %lu", pid, pidversion, (unsigned long)gBlacklistedState.count]);

		// Diagnostic: read POSIX signal dispositions (pbi_sigignore / pbi_sigcatch).
		// These fields were removed from the iOS 26 SDK's struct proc_bsdinfo, but
		// they still exist at fixed offsets 112 / 116 in the iOS 16 runtime struct
		// (our actual device). Read them via a raw buffer + fixed offsets so the
		// compiler never sees the removed field names.
		unsigned char bsdinfoBuf[256] = {0};
		if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, bsdinfoBuf, sizeof(bsdinfoBuf)) > 0) {
			uint32_t sigignore = *(uint32_t *)(bsdinfoBuf + 112);
			uint32_t sigcatch = *(uint32_t *)(bsdinfoBuf + 116);
			app_hide_log([NSString stringWithFormat:@"  child %d sigignore=0x%x sigcatch=0x%x", pid, sigignore, sigcatch]);
		}

		// Diagnostic: dump the child's mach exception ports so we can see what a
		// "signal handlers set" detector observes on a bare (no-inject) app.
		mach_port_t task = MACH_PORT_NULL;
		if (task_for_pid(mach_task_self(), pid, &task) != KERN_SUCCESS) {
			app_hide_log([NSString stringWithFormat:@"  child %d task_for_pid failed", pid]);
		} else {
			exception_mask_t masks[EXC_TYPES_COUNT] = {0};
			mach_port_t ports[EXC_TYPES_COUNT] = {0};
			exception_behavior_t behaviors[EXC_TYPES_COUNT] = {0};
			thread_state_flavor_t flavors[EXC_TYPES_COUNT] = {0};
			mach_msg_type_number_t count = 0;
			kern_return_t kr = task_get_exception_ports(task, EXC_MASK_ALL, masks, &count, ports, behaviors, flavors);
			if (kr != KERN_SUCCESS) {
				app_hide_log([NSString stringWithFormat:@"  child %d task_get_exception_ports kr=%d", pid, kr]);
			} else if (count == 0) {
				app_hide_log([NSString stringWithFormat:@"  child %d no exception ports (clean)", pid]);
			} else {
				for (mach_msg_type_number_t i = 0; i < count; i++) {
					app_hide_log([NSString stringWithFormat:@"  child %d exc mask=0x%x port=0x%x", pid, masks[i], ports[i]]);
				}
			}
			mach_port_deallocate(mach_task_self(), task);
		}
	}
	free(pidp);
}

bool app_hide_is_blacklisted_pid(pid_t pid)
{
	if (pid <= 0) return false;
	state_init();

	bool blacklisted = false;
	pthread_rwlock_rdlock(&gStateLock);
	NSNumber *cachedVersion = gBlacklistedState[@(pid)];
	if (cachedVersion && cachedVersion.intValue == proc_get_pidversion(pid)) {
		blacklisted = true;
	}
	pthread_rwlock_unlock(&gStateLock);
	return blacklisted;
}

static void app_hide_remove_pid(pid_t pid)
{
	if (pid <= 0) return;
	state_init();
	pthread_rwlock_wrlock(&gStateLock);
	[gBlacklistedState removeObjectForKey:@(pid)];
	pthread_rwlock_unlock(&gStateLock);
}

// ---------------------------------------------------------------------------
// bind() hook (RootHide roothider.m new_bind) — force auto-assigned (port 0)
// sockets into the ephemeral range so jailbreak sockets don't land on a
// suspicious fixed port. Hooks launchd itself; applied via GOT rebind (no
// instruction replacement, which would panic launchd on arm64).
// ---------------------------------------------------------------------------

static int (*orig_bind)(int, const struct sockaddr *, socklen_t);

static int new_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	if (addr && addr->sa_family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
		struct sockaddr_in addr_in = *(struct sockaddr_in *)addr;
		in_port_t port = ntohs(addr_in.sin_port);
		if (port == 0) {
			int ret = -1;
			for (port = IPPORT_HIFIRSTAUTO; port <= IPPORT_HILASTAUTO; port++) {
				addr_in.sin_port = htons(port);
				ret = orig_bind(sockfd, (struct sockaddr *)&addr_in, addrlen);
				if (ret == 0 || errno != EADDRINUSE) break;
			}
			return ret;
		}
	}
	else if (addr && addr->sa_family == AF_INET6 && addrlen >= sizeof(struct sockaddr_in6)) {
		struct sockaddr_in6 addr_in6 = *(struct sockaddr_in6 *)addr;
		in_port_t port = ntohs(addr_in6.sin6_port);
		if (port == 0) {
			int ret = -1;
			for (port = IPPORT_HIFIRSTAUTO; port <= IPPORT_HILASTAUTO; port++) {
				addr_in6.sin6_port = htons(port);
				ret = orig_bind(sockfd, (struct sockaddr *)&addr_in6, addrlen);
				if (ret == 0 || errno != EADDRINUSE) break;
			}
			return ret;
		}
	}
	return orig_bind(sockfd, addr, addrlen);
}

static void app_hide_log(NSString *msg)
{
	FILE *f = fopen("/var/mobile/Documents/noinject_log.txt", "a");
	if (f) {
		fprintf(f, "%s\n", msg.UTF8String);
		fclose(f);
	}
}

// ---------------------------------------------------------------------------
// XPC reply hooks (RootHide xpc_hook.m)
// ---------------------------------------------------------------------------

static xpc_object_t (*orig_xpc_dictionary_create_reply)(xpc_object_t original);
static int (*orig_xpc_pipe_routine_reply)(xpc_object_t reply);

static xpc_object_t new_xpc_dictionary_create_reply(xpc_object_t original)
{
	xpc_object_t reply = orig_xpc_dictionary_create_reply(original);
	if (reply) {
		audit_token_t clientToken = {0};
		xpc_dictionary_get_audit_token(original, &clientToken);
		if (is_blacklisted_token(&clientToken)) {
			xpc_dictionary_set_value(reply, "roothide-blacklisted-process-request", original);
		}
	}
	return reply;
}

static int new_xpc_pipe_routine_reply(xpc_object_t reply)
{
	if (xpc_get_type(reply) == XPC_TYPE_DICTIONARY) {
		xpc_object_t original = xpc_dictionary_get_value(reply, "roothide-blacklisted-process-request");
		if (original) {
			xpc_dictionary_set_value(reply, "roothide-blacklisted-process-request", NULL);

			audit_token_t clientToken = {0};
			xpc_dictionary_get_audit_token(original, &clientToken);

			uint64_t routine = xpc_dictionary_get_uint64(original, "routine");
			uint64_t subsystem = xpc_dictionary_get_uint64(original, "subsystem");

			if (subsystem == 3 && routine == 829) {
				// coalition query: hide the coalition unless it is the app itself
				// or an Apple/App Store bundle.
				int64_t error = xpc_dictionary_get_int64(reply, "error");
				const char *name = xpc_dictionary_get_string(reply, "name");
				const char *bundle_identifier = xpc_dictionary_get_string(reply, "bundle_identifier");
				const char *bundle = bundle_identifier ? bundle_identifier : (name ? name : "");

				char client_identifier[255] = {0};
				proc_get_identifier(audit_token_to_pid(clientToken), client_identifier, sizeof(client_identifier));

				bool isSafe = is_safe_bundle_identifier(bundle);
				bool isSelf = client_identifier[0] && string_has_prefix(bundle, client_identifier);

				if (error == 0 && !isSelf && !isSafe) {
					xpc_dictionary_set_value(reply, "cid", NULL);
					xpc_dictionary_set_value(reply, "name", NULL);
					xpc_dictionary_set_value(reply, "bundle_identifier", NULL);
					xpc_dictionary_set_value(reply, "resource-usage-blob", NULL);
					xpc_dictionary_set_int64(reply, "error", 3);
				}
			}
		}
	}
	return orig_xpc_pipe_routine_reply(reply);
}

void app_hide_init(void)
{
	// Save the originals, then GOT-rebind (NOT instruction-replace). Instruction
	// replacement clears CS_VALID on arm64 and panics launchd (pid 1) during the
	// jailbreak "protection" stage; the existing initXPCHooks() uses GOT rebind for
	// exactly this reason.
	orig_xpc_dictionary_create_reply = (xpc_object_t (*)(xpc_object_t))xpc_dictionary_create_reply;
	orig_xpc_pipe_routine_reply = (int (*)(xpc_object_t))xpc_pipe_routine_reply;
	orig_bind = bind;
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, (void *)xpc_dictionary_create_reply, (void *)new_xpc_dictionary_create_reply, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, (void *)xpc_pipe_routine_reply, (void *)new_xpc_pipe_routine_reply, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, (void *)bind, (void *)new_bind, NULL);
}

// ---------------------------------------------------------------------------
// RootHide-style "no-injection" mode: temporary global hide + bare spawn
// ---------------------------------------------------------------------------

static bool gNoInjectActive = false;
static int gNoInjectRefCount = 0;
static pthread_mutex_t gNoInjectLock = PTHREAD_MUTEX_INITIALIZER;

static void app_hide_run_jbctl(const char *command, const char *arg)
{
	// jbctl carries the bindfs-allow entitlement + root; host a local jbserver so
	// it can talk to us, same pattern as ensure_fakelib_mounted().
	systemwide_domain_set_enabled(true);
	mach_port_t serverPort = jbserver_local_start();
	jbctl_earlyboot(serverPort, "internal", command, arg, NULL);
	jbserver_local_stop();
}

// Actual (reversible) hide/restore bodies, shared by the no-inject refcount
// path and the "jailbreak app resurrection" path.

static void app_hide_do_hide(void)
{
	// Unmount fakelib FIRST so the re-entrant jbctl spawn below runs without
	// systemhook injection (same proven pattern as ensure_fakelib_mounted()).
	unmount("/usr/lib", MNT_FORCE);

	// Quarantine the jailbreak files a bare app can still see (the "suspicious
	// files" under /var/mobile/Library). Pure file-rename, no uicache.
	app_hide_run_jbctl("audit", "hide");

	// Remove the /var/jb symlink last.
	unlink("/var/jb");
}

static void app_hide_do_restore(void)
{
	const char *jbroot = gSystemInfo.jailbreakInfo.rootPath;
	if (jbroot && jbroot[0]) {
		unlink("/var/jb");
		symlink(jbroot, "/var/jb");
	}

	// Restore the quarantined files, then remount fakelib.
	app_hide_run_jbctl("audit", "restore");
	app_hide_run_jbctl("fakelib", "mount");
}

void app_hide_global_hide(void)
{
	// Reference-counted: multiple no-inject apps may run concurrently. The
	// actual hide only runs when the jailbreak isn't already hidden (i.e. the
	// first no-inject app, or the first after a jailbreak-app resurrection).
	pthread_mutex_lock(&gNoInjectLock);
	gNoInjectRefCount++;
	int refcount = gNoInjectRefCount;
	bool wasHidden = gNoInjectActive;
	gNoInjectActive = true;
	pthread_mutex_unlock(&gNoInjectLock);
	app_hide_log([NSString stringWithFormat:@"global_hide: refcount now %d", refcount]);
	if (wasHidden) return;

	app_hide_do_hide();
}

void app_hide_global_restore(void)
{
	// Only restore once the LAST hidden app has exited.
	pthread_mutex_lock(&gNoInjectLock);
	if (gNoInjectRefCount <= 0) {
		pthread_mutex_unlock(&gNoInjectLock);
		app_hide_log(@"global_restore: refcount already 0 (no-op)");
		return;
	}
	gNoInjectRefCount--;
	int refcount = gNoInjectRefCount;
	if (refcount > 0) {
		pthread_mutex_unlock(&gNoInjectLock);
		app_hide_log([NSString stringWithFormat:@"global_restore: refcount now %d (skip, still hidden)", refcount]);
		return;
	}
	gNoInjectActive = false;
	pthread_mutex_unlock(&gNoInjectLock);
	app_hide_log(@"global_restore: refcount 0, restoring jailbreak");

	app_hide_do_restore();
}

bool app_hide_is_currently_hidden(void)
{
	pthread_mutex_lock(&gNoInjectLock);
	bool hidden = gNoInjectActive;
	pthread_mutex_unlock(&gNoInjectLock);
	return hidden;
}

bool app_hide_is_jailbreak_app(const char *path)
{
	// A "jailbreak app" is an app bundle (contains ".app/") installed inside
	// the jailbreak root itself (Sileo, Filza, Terminal, ...). It may be
	// launched via the /var/jb/ symlink OR via the fully-resolved preboot path,
	// so accept both. Requiring ".app/" also excludes jailbreak binaries like
	// jbctl (spawned re-entrantly during hide/restore) from a false resurrect.
	if (!path) return false;
	if (!strstr(path, ".app/")) return false;
	if (strncmp(path, "/var/jb/", 8) == 0) return true;
	const char *jbroot = gSystemInfo.jailbreakInfo.rootPath;
	if (jbroot && jbroot[0]) {
		size_t len = strlen(jbroot);
		if (len > 0 && strncmp(path, jbroot, len) == 0) return true;
	}
	return false;
}

void app_hide_resurrect_for_jb_app(void)
{
	// "Jailbreak app resurrection": a jailbreak app was spawned while the
	// jailbreak was hidden (a no-inject app is running). Restore the jailbreak
	// so the jailbreak app can run. The no-inject refcount is left intact (those
	// apps are still running); only the hidden state is cleared, and we do NOT
	// re-hide later (accepted limitation).
	pthread_mutex_lock(&gNoInjectLock);
	bool wasHidden = gNoInjectActive;
	gNoInjectActive = false;
	pthread_mutex_unlock(&gNoInjectLock);
	if (!wasHidden) return;
	app_hide_log(@"resurrect: jailbreak app spawned while hidden, restoring jailbreak");
	app_hide_do_restore();
}

// Query a pid's app state (proc_pidinfo flavor 22 = PROC_PIDT_APPSTATE), a
// direct foreground/background signal that does NOT need the task port (unlike
// task_policy_get, which needs task_for_pid and is denied from launchd).
// Returns the raw app state, or -1 if it can't be queried.
static int app_hide_get_app_state(pid_t pid)
{
	// struct proc_pidappstateinfo is just { uint32_t app_state; }.
	uint32_t app_state = 0;
	if (proc_pidinfo(pid, 22 /* PROC_PIDT_APPSTATE */, 0, &app_state, sizeof(app_state)) != sizeof(app_state)) {
		return -1;
	}
	return (int)app_state;
}

void app_hide_check_role_after_spawn(pid_t pid)
{
	if (pid <= 0) return;
	// The app state is assigned shortly after spawn: foreground apps become
	// PROC_APPSTATE_ACTIVE (1), background apps stay background/suspended/nonui.
	// Give the system a moment, then undo the hide if this turned out to be a
	// background launch (so a background refresh doesn't leave the jailbreak
	// hidden until the app exits).
	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 500 * NSEC_PER_MSEC),
		dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
			int appState = app_hide_get_app_state(pid);
			app_hide_log([NSString stringWithFormat:@"appstate_check: pid %d app_state=%d", pid, appState]);
			// 1 = PROC_APPSTATE_ACTIVE (foreground). Any other real value (2
			// inactive / 3 background / 4 suspended / 5 nonui) is a background
			// launch: undo the hide.
			if (appState > 0 && appState != 1) {
				app_hide_log([NSString stringWithFormat:@"appstate_check: pid %d is background, restoring jailbreak", pid]);
				app_hide_global_restore();
			}
		});
}

void app_hide_watch_exit(pid_t pid)
{
	if (pid <= 0) return;

	dispatch_source_t source = dispatch_source_create(DISPATCH_SOURCE_TYPE_PROC, (uintptr_t)pid, DISPATCH_PROC_EXIT,
		dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0));
	dispatch_source_set_event_handler(source, ^{
		app_hide_log([NSString stringWithFormat:@"watch_exit: pid %d exited", pid]);
		app_hide_remove_pid(pid);
		app_hide_global_restore();
		dispatch_source_cancel(source);
	});
	dispatch_resume(source);
}
