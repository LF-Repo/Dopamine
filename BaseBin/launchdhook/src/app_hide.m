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
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>

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

// Cap the diagnostic log. Both the spawn hook (twice per spawn) and the 5s
// watchdog write here, and the watchdog in particular would otherwise grow the
// file for as long as any app stays hidden — this is an append-only log on the
// user's data volume, so it needs a ceiling the way DopamineAppHide.log already
// has one. APP_HIDE_LOG_PATH itself lives in app_hide.h, shared with spawn_hook.
#define APP_HIDE_LOG_MAX_SIZE (512 * 1024)

static void app_hide_log(NSString *msg)
{
	FILE *f = fopen(APP_HIDE_LOG_PATH, "a");
	if (!f) return;
	fprintf(f, "%s\n", msg.UTF8String);
	fclose(f);

	// Truncate in place once the file crosses the cap. Keeping the most recent
	// entries is the useful direction: the watchdog's repeated lines are the bulk
	// of the growth, and the state transitions that matter are the newest ones.
	struct stat st;
	if (stat(APP_HIDE_LOG_PATH, &st) == 0 && st.st_size > APP_HIDE_LOG_MAX_SIZE) {
		// Truncate to zero rather than seeking: a partial tail from a large write
		// is not worth preserving, and starting clean avoids shipping a helper to
		// copy the tail out.
		truncate(APP_HIDE_LOG_PATH, 0);
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

// The watchdog that re-derives the hide state (defined near the bottom of this
// file). app_hide_init() starts it; declared here because that call site comes
// first.
static void app_hide_start_watchdog(void);

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

	// Start the hide watchdog unconditionally, not only once a no-inject app has
	// been launched. Its reverse check ("/var/jb is missing but nothing needs the
	// hide") is the only thing that can repair a jailbreak stranded by a previous
	// boot or a crashed app, and that damage is already present before any app is
	// spawned — so waiting for the first spawn would leave a stuck device stuck.
	// The timer early-outs unless something is actually wrong, and dispatch_once
	// makes the later per-spawn starts no-ops.
	//
	// Deferred briefly so the first tick does not race launchd's own startup work
	// at this point in the boot sequence.
	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC),
		dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
			app_hide_start_watchdog();
		});
}

// ---------------------------------------------------------------------------
// RootHide-style "no-injection" mode: temporary global hide + bare spawn
// ---------------------------------------------------------------------------

// The set of no-inject app pids that are currently running, which is what the
// hide state must actually follow. This used to be a bare int refcount, but the
// count and the real world drifted apart in ways that left the jailbreak stuck
// hidden with nothing left to restore it (see app_hide_should_stay_hidden_locked
// below).
//
// The sets are plain ints (pids, not NSNumber) so that every decision below can
// be made under a single plain mutex, with no Objective-C runtime calls while
// the lock is held. That matters: this code runs inside launchd (pid 1), where a
// deadlock is a full userspace hang.
static pid_t *gNoInjectPids = NULL;
static size_t gNoInjectPidCount = 0;
static size_t gNoInjectPidCapacity = 0;
static bool gNoInjectActive = false;
// Number of hides that have started but whose app pid isn't known yet. The hide
// must be in effect *before* the app is bare-spawned, so there is an unavoidable
// window where the state is "hidden" while the tracked set is still empty. Without
// this counter the watchdog reads that window as "hidden with nothing running" and
// restores on top of the hide that is still executing.
static int gNoInjectHidePending = 0;
static pthread_mutex_t gNoInjectLock = PTHREAD_MUTEX_INITIALIZER;

// Serialises the hide/restore bodies themselves. They rename files, unmount and
// remount /usr/lib and block on jbctl, so two of them must never interleave —
// that would leave files half-quarantined and fakelib in the wrong state.
static pthread_mutex_t gNoInjectActionLock = PTHREAD_MUTEX_INITIALIZER;

// Guarded by gNoInjectLock. Callers must have validated the pid > 0.
static bool app_hide_pid_in_set(const pid_t *pids, size_t count, pid_t pid)
{
	for (size_t i = 0; i < count; i++) {
		if (pids[i] == pid) return true;
	}
	return false;
}

static void app_hide_set_insert(pid_t pid)
{
	if (app_hide_pid_in_set(gNoInjectPids, gNoInjectPidCount, pid)) return;
	if (gNoInjectPidCount == gNoInjectPidCapacity) {
		size_t newCapacity = gNoInjectPidCapacity ? gNoInjectPidCapacity * 2 : 8;
		pid_t *newPids = realloc(gNoInjectPids, newCapacity * sizeof(pid_t));
		if (!newPids) return; // out of memory: lose the bookkeeping, not launchd
		gNoInjectPids = newPids;
		gNoInjectPidCapacity = newCapacity;
	}
	gNoInjectPids[gNoInjectPidCount++] = pid;
}

// Returns true if the pid was tracked.
static bool app_hide_set_remove(pid_t pid)
{
	for (size_t i = 0; i < gNoInjectPidCount; i++) {
		if (gNoInjectPids[i] != pid) continue;
		gNoInjectPids[i] = gNoInjectPids[gNoInjectPidCount - 1];
		gNoInjectPidCount--;
		return true;
	}
	return false;
}

// Reap pids that have already exited, so a crashed no-inject app cannot leave a
// stale entry pinning the hide on. Caller must hold gNoInjectLock.
static void app_hide_reap_dead_pids_locked(void)
{
	size_t i = 0;
	while (i < gNoInjectPidCount) {
		pid_t pid = gNoInjectPids[i];
		if (pid <= 1 || (kill(pid, 0) != 0 && errno == ESRCH)) {
			gNoInjectPids[i] = gNoInjectPids[gNoInjectPidCount - 1];
			gNoInjectPidCount--;
			continue;
		}
		i++;
	}
}

// The restore condition, evaluated entirely under gNoInjectLock: stay hidden if
// and only if at least one tracked no-inject app is still alive.
//
// This is the invariant the old refcount got wrong. Decrementing a counter on
// exit assumed every hide had exactly one matching restore, but two paths could
// restore out from under it (the jb-app resurrection, and the background-launch
// check), so the count could stay above zero forever with nothing running to
// bring it back down. Asking the process table instead cannot drift.
//
// kill(pid, 0) delivers no signal; it only reports whether the pid still exists.
static bool app_hide_should_stay_hidden_locked(void)
{
	// A hide whose pid isn't known yet is still in progress, so the empty set here
	// is not evidence that anything finished.
	if (gNoInjectHidePending > 0) return true;
	for (size_t i = 0; i < gNoInjectPidCount; i++) {
		pid_t pid = gNoInjectPids[i];
		if (pid <= 1) continue;
		if (kill(pid, 0) != 0 && errno == ESRCH) continue;
		return true;
	}
	return false;
}

// Pids of jailbreak apps running "resurrected" (restored while the jailbreak was
// hidden). Killed before the jailbreak is re-hidden so they don't keep writing
// into the real jbroot after /var/jb is removed.
static NSMutableSet *gJailbreakAppPids = nil;
static pthread_mutex_t gJailbreakAppLock = PTHREAD_MUTEX_INITIALIZER;

static void app_hide_kill_jailbreak_apps(void);

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
	// Kill running jailbreak apps first, so they don't keep writing into the
	// real jbroot after /var/jb is removed below.
	app_hide_kill_jailbreak_apps();

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

// Record that a no-inject app was spawned. Called right after the bare spawn, so
// by the time this runs the pid exists and the watchdog can verify it. Also closes
// the pending window opened by app_hide_global_hide().
void app_hide_note_pid(pid_t pid)
{
	if (pid <= 0) return;
	pthread_mutex_lock(&gNoInjectLock);
	app_hide_set_insert(pid);
	if (gNoInjectHidePending > 0) gNoInjectHidePending--;
	pthread_mutex_unlock(&gNoInjectLock);
}

// A no-inject app was launched but never got a pid. Close the pending window so
// the watchdog can restore the jailbreak for an app that does not exist.
void app_hide_abort_pending_hide(void)
{
	pthread_mutex_lock(&gNoInjectLock);
	if (gNoInjectHidePending > 0) gNoInjectHidePending--;
	pthread_mutex_unlock(&gNoInjectLock);
}

// Re-evaluate whether the jailbreak should be hidden right now, and restore it
// if not. This is the single place that decides to un-hide, so the exit watcher,
// the watchdog and the background-launch check can never disagree.
//
// Must not be called with gNoInjectLock held.
static void app_hide_reconcile(const char *reason)
{
	pthread_mutex_lock(&gNoInjectLock);
	if (!gNoInjectActive) {
		pthread_mutex_unlock(&gNoInjectLock);
		return;
	}
	app_hide_reap_dead_pids_locked();
	if (app_hide_should_stay_hidden_locked()) {
		int tracked = (int)gNoInjectPidCount;
		pthread_mutex_unlock(&gNoInjectLock);
		app_hide_log([NSString stringWithFormat:@"reconcile(%@): staying hidden, %d no-inject app(s) alive", reason, tracked]);
		return;
	}
	gNoInjectActive = false;
	gNoInjectPidCount = 0;
	gNoInjectHidePending = 0;
	pthread_mutex_unlock(&gNoInjectLock);

	// Take the action lock only after releasing gNoInjectLock: gNoInjectLock is a
	// plain leaf lock, and taking it while waiting for a blocking jbctl call in
	// the other order would serialise every spawn behind the hide.
	pthread_mutex_lock(&gNoInjectActionLock);
	app_hide_log([NSString stringWithFormat:@"reconcile(%@): no no-inject app left, restoring jailbreak", reason]);
	app_hide_do_restore();
	pthread_mutex_unlock(&gNoInjectActionLock);
}

void app_hide_global_hide(void)
{
	pthread_mutex_lock(&gNoInjectLock);
	bool wasHidden = gNoInjectActive;
	gNoInjectActive = true;
	// Hide before spawning (the app must not see /var/jb), so until its pid is
	// recorded the set is legitimately empty. Mark that so the watchdog waits.
	if (!wasHidden) gNoInjectHidePending++;
	pthread_mutex_unlock(&gNoInjectLock);
	if (wasHidden) return;

	pthread_mutex_lock(&gNoInjectActionLock);
	app_hide_do_hide();
	pthread_mutex_unlock(&gNoInjectActionLock);
}

void app_hide_global_restore(void)
{
	// Restore once the LAST hidden app is gone. The decision is delegated to the
	// same reconcile path the watchdog uses, so an external restore request and a
	// spontaneous one can't double-decrement or skip.
	app_hide_reconcile("restore");
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

// Read an app bundle's CFBundleIdentifier from its launch path (.../X.app/X).
static NSString *app_hide_bundle_id(const char *path)
{
	if (!path) return nil;
	NSString *result = nil;
	@autoreleasepool {
		NSString *p = [NSString stringWithUTF8String:path];
		NSRange r = [p rangeOfString:@".app/"];
		if (r.location != NSNotFound) {
			NSString *appPath = [p substringToIndex:r.location + 4];
			NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
			                      [appPath stringByAppendingPathComponent:@"Info.plist"]];
			id bundleID = info[@"CFBundleIdentifier"];
			if ([bundleID isKindOfClass:[NSString class]]) result = [bundleID copy];
		}
	}
	return result;
}

// The Settings app (Preferences.app, stock path /Applications/Preferences.app)
// is effectively a jailbreak app: it is where every tweak's settings bundle is
// listed from (/var/jb/Library/PreferenceBundles + PreferencePanes). While the
// jailbreak is globally hidden it shows NO tweak settings at all, so it has to
// resurrect the jailbreak exactly like Sileo does.
bool app_hide_is_settings_app(const char *path)
{
	if (!path) return false;
	if (!strstr(path, ".app/")) return false;
	// Path-based fallback, in case Info.plist can't be read.
	if (strstr(path, "/Applications/Preferences.app/") != NULL) return true;
	static NSString *settingsBundleID = @"com.apple.Preferences";
	return [app_hide_bundle_id(path) isEqualToString:settingsBundleID];
}

void app_hide_resurrect_for_jb_app(void)
{
	// "Jailbreak app resurrection": a jailbreak app was spawned while the
	// jailbreak was hidden (a no-inject app is running). Restore the jailbreak
	// so the jailbreak app can run.
	//
	// The still-running no-inject apps stay tracked. That matters: if we dropped
	// them here, then when they exited the watchdog would see an empty set and
	// "restore" a jailbreak that was already visible (a harmless extra unmount
	// race), but if we kept a stale count instead, the next restore request would
	// decrement a counter nothing else would ever bring back to zero and the
	// jailbreak would stay hidden forever with no way out. Keeping the pids means
	// one exit re-hides nothing by itself, and the resurrection is the only thing
	// that un-hides until the apps are gone.
	pthread_mutex_lock(&gNoInjectLock);
	bool wasHidden = gNoInjectActive;
	gNoInjectActive = false;
	// The apps are still running, so the hide is suspended, not finished: reset
	// the pending window and keep the pids for the watchdog to reason about.
	gNoInjectHidePending = 0;
	pthread_mutex_unlock(&gNoInjectLock);
	if (!wasHidden) return;
	app_hide_log(@"resurrect: jailbreak app spawned while hidden, restoring jailbreak");
	pthread_mutex_lock(&gNoInjectActionLock);
	app_hide_do_restore();
	pthread_mutex_unlock(&gNoInjectActionLock);
}

void app_hide_track_jailbreak_app(pid_t pid)
{
	if (pid <= 0) return;
	pthread_mutex_lock(&gJailbreakAppLock);
	if (!gJailbreakAppPids) gJailbreakAppPids = [NSMutableSet set];
	[gJailbreakAppPids addObject:@(pid)];
	pthread_mutex_unlock(&gJailbreakAppLock);
}

// Kill the "resurrected" apps by scanning the process table, so this does not
// depend on transient pid bookkeeping (pids get reused, and the tracked list is
// cleared on every re-hide, which used to leave a still-running app behind).
//
// Two things must die before /var/jb disappears:
//   1. jailbreak apps (Sileo, Filza, ...): they keep writing into the real
//      jbroot once /var/jb is gone, which is a real corruption risk;
//   2. Settings.app: it caches the (empty) tweak list it read while the jailbreak
//      was hidden, so without a kill it would come back with no tweak settings.
//
// Matching is by real executable path via proc_pidpath(): jailbreak apps live
// under <jbroot>/Applications/*.app, Settings at /Applications/Preferences.app.
// Helper processes (PreferencesAgent, ...) live inside a .app but are not the app
// executable itself — however killing them with the app is harmless and matches
// what the user asked for, so anything whose path is inside a matching .app goes.
static BOOL app_hide_path_is_resurrected_app(const char *path)
{
	if (!path) return NO;
	if (app_hide_is_settings_app(path)) return YES;
	if (!strstr(path, ".app/")) return NO;

	// Any app running from the jailbreak root's Applications folder.
	const char *jbroot = gSystemInfo.jailbreakInfo.rootPath;
	if (jbroot && jbroot[0]) {
		size_t len = strlen(jbroot);
		if (len > 0 && strncmp(path, jbroot, len) == 0 && strstr(path, "/Applications/")) {
			return YES;
		}
	}
	if (strncmp(path, "/var/jb/", 8) == 0 && strstr(path, "/Applications/")) {
		return YES;
	}
	return NO;
}

static void app_hide_kill_resurrected_apps(void)
{
	int byteCount = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
	if (byteCount <= 0) return;

	pid_t *pids = malloc((size_t)byteCount);
	if (!pids) return;
	byteCount = proc_listpids(PROC_ALL_PIDS, 0, pids, byteCount);
	if (byteCount <= 0) {
		free(pids);
		return;
	}

	int n = byteCount / (int)sizeof(pid_t);
	for (int i = 0; i < n; i++) {
		pid_t pid = pids[i];
		if (pid <= 1) continue; // never touch launchd

		char path[4 * MAXPATHLEN] = {0};
		if (proc_pidpath(pid, path, sizeof(path)) <= 0) continue;
		if (!app_hide_path_is_resurrected_app(path)) continue;

		if (kill(pid, SIGKILL) == 0) {
			app_hide_log([NSString stringWithFormat:@"kill resurrected app pid %d (%s)", pid, path]);
		}
	}
	free(pids);
}

static void app_hide_kill_jailbreak_apps(void)
{
	app_hide_kill_resurrected_apps();

	pthread_mutex_lock(&gJailbreakAppLock);
	NSArray *pids = [gJailbreakAppPids allObjects];
	[gJailbreakAppPids removeAllObjects];
	pthread_mutex_unlock(&gJailbreakAppLock);
	for (NSNumber *pidNum in pids) {
		pid_t pid = pidNum.intValue;
		if (pid > 0 && kill(pid, SIGKILL) == 0) {
			app_hide_log([NSString stringWithFormat:@"kill jailbreak app pid %d", pid]);
		}
	}
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

// Watchdog: periodically re-derive the hide state from the set of live no-inject
// apps.
//
// This replaces a one-shot 500 ms post-spawn check that read PROC_PIDT_APPSTATE
// exactly once and restored on anything other than PROC_APPSTATE_ACTIVE. That was
// unreliable in both directions: a normal foreground app legitimately reports
// "inactive"/"nonui" while it is still launching, so a good launch could be torn
// down mid-startup, and a genuinely background app that happened to report ACTIVE
// at that instant was never corrected. Re-asking "is anything tracked still alive"
// cannot misfire that way, and it also repairs a hide that was stranded by a
// missed exit event or a crashed app.
static void app_hide_start_watchdog(void)
{
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
			dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
		// 5s is frequent enough that a crashed app is recovered quickly, and rare
		// enough that this costs nothing: the body returns immediately unless
		// something is actually wrong.
		dispatch_source_set_timer(timer, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC),
			5 * NSEC_PER_SEC, 1 * NSEC_PER_SEC);
		dispatch_source_set_event_handler(timer, ^{
			// Two independent checks, because a hide can go wrong in two ways:

			// 1. We believe we are hidden but nothing needs us to be. This is the
			//    stranded case: a missed exit event, or a restore that was skipped
			//    because bookkeeping disagreed with reality. Left alone it hides
			//    /var/jb indefinitely, which is exactly "tweaks disappeared".
			if (app_hide_is_currently_hidden()) {
				app_hide_reconcile("watchdog");
				return;
			}

			// 2. We believe we are visible but the files say otherwise: /var/jb
			//    is gone while no no-inject app is running. Only the watchdog can
			//    notice this, because our own flag was already cleared by whatever
			//    restored it — including a restore that ran before it finished.
			//    Re-running the restore is safe: it is idempotent, and the audit
			//    restore skips any file that is already back in place.
			//
			//    Requires a known jbroot: on a device that was never bootstrapped
			//    (or before the jailbreak is applied) /var/jb is legitimately
			//    absent, and acting on that would spawn jbctl every 5s forever
			//    doing nothing.
			const char *jbroot = gSystemInfo.jailbreakInfo.rootPath;
			if (jbroot && jbroot[0] && access("/var/jb", F_OK) != 0) {
				app_hide_log(@"watchdog: /var/jb missing while not hidden, re-restoring");
				pthread_mutex_lock(&gNoInjectActionLock);
				app_hide_do_restore();
				pthread_mutex_unlock(&gNoInjectActionLock);
			}
		});
		dispatch_resume(timer);
	});
}

void app_hide_check_role_after_spawn(pid_t pid)
{
	if (pid <= 0) return;
	// Ensure the watchdog exists as soon as the first no-inject app is launched.
	app_hide_start_watchdog();

	// Give the system a moment to assign the app state, then log it for diagnosis.
	// The decision to restore is deliberately NOT made here: a single early
	// sample cannot distinguish "still launching" from "background launch", and
	// guessing wrong is what left the jailbreak stuck hidden. The watchdog owns
	// that decision, using liveness instead of a racy one-shot state read.
	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 500 * NSEC_PER_MSEC),
		dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
			int appState = app_hide_get_app_state(pid);
			app_hide_log([NSString stringWithFormat:@"appstate_check: pid %d app_state=%d (advisory)", pid, appState]);
		});
}

void app_hide_watch_exit(pid_t pid)
{
	if (pid <= 0) return;

	// Make sure the watchdog is running whenever an app is tracked.
	app_hide_start_watchdog();

	dispatch_source_t source = dispatch_source_create(DISPATCH_SOURCE_TYPE_PROC, (uintptr_t)pid, DISPATCH_PROC_EXIT,
		dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0));
	dispatch_source_set_event_handler(source, ^{
		app_hide_log([NSString stringWithFormat:@"watch_exit: pid %d exited", pid]);
		app_hide_remove_pid(pid);
		// Drop the pid from the tracked set, then re-derive the hide state. If it
		// was the last live no-inject app this restores; if others are still
		// running, the jailbreak stays hidden and nothing else happens.
		pthread_mutex_lock(&gNoInjectLock);
		app_hide_set_remove(pid);
		pthread_mutex_unlock(&gNoInjectLock);
		app_hide_reconcile("exit");
		dispatch_source_cancel(source);
	});
	dispatch_resume(source);
}
