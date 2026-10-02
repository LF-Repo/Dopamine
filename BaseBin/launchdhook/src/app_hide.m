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
#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <pthread.h>
#include <xpc/xpc.h>
#include <errno.h>
#include <arpa/inet.h>
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
	}
	free(pidp);
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
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, (void *)xpc_dictionary_create_reply, (void *)new_xpc_dictionary_create_reply, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, (void *)xpc_pipe_routine_reply, (void *)new_xpc_pipe_routine_reply, NULL);
}

// ---------------------------------------------------------------------------
// RootHide-style "no-injection" mode: temporary global hide + bare spawn
// ---------------------------------------------------------------------------

static bool gNoInjectActive = false;

void app_hide_global_hide(void)
{
	if (gNoInjectActive) return;
	gNoInjectActive = true;

	// Remove the /var/jb symlink and unmount fakelib so a bare (uninjected) app
	// sees a clean system. Both are global — this is the "global destruction"
	// tradeoff of no-injection hiding, but it is exactly what RootHide avoids by
	// relocating the root; here we only apply it while a hidden app is running.
	unlink("/var/jb");
	unmount("/usr/lib", MNT_FORCE);
}

void app_hide_global_restore(void)
{
	if (!gNoInjectActive) return;
	gNoInjectActive = false;

	const char *jbroot = gSystemInfo.jailbreakInfo.rootPath;
	if (jbroot && jbroot[0]) {
		unlink("/var/jb");
		symlink(jbroot, "/var/jb");
	}

	// Remount fakelib. launchd (pid 1) lacks the com.apple.private.bindfs-allow
	// entitlement, so a direct bindfs mount() fails here. Host a local jbserver
	// and let jbctl do the mount, exactly like ensure_fakelib_mounted() does.
	systemwide_domain_set_enabled(true);
	mach_port_t serverPort = jbserver_local_start();
	jbctl_earlyboot(serverPort, "internal", "fakelib", "mount", NULL);
	jbserver_local_stop();
}

void app_hide_watch_exit(pid_t pid)
{
	if (pid <= 0) return;

	dispatch_source_t source = dispatch_source_create(DISPATCH_SOURCE_TYPE_PROC, (uintptr_t)pid, DISPATCH_PROC_EXIT,
		dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0));
	dispatch_source_set_event_handler(source, ^{
		app_hide_global_restore();
		dispatch_source_cancel(source);
	});
	dispatch_resume(source);
}
