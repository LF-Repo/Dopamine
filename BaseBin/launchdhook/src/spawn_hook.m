#include <spawn.h>
#include "../systemhook/src/common/common.h"
#include "../systemhook/src/common/envbuf.h"
#include "boomerang.h"
#include "crashreporter.h"
#include "update.h"
#include <libjailbreak/util.h>
#import <libjailbreak/jbclient_xpc.h>
#include <substrate.h>
#include <mach-o/dyld.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <litehook.h>
#include "jbserver/jbserver_local.h"
#include "hookd_provider.h"
#include "app_hide.h"
#import <Foundation/Foundation.h>
#include <mach/mach.h>
#include <mach/task.h>
extern char **environ;

// Private XNU spawn coalition info (bsd/sys/spawn_internal.h). Used to read the
// coalition role at spawn time (pre-spawn) to tell foreground/background apart.
struct _posix_spawn_coalition_info {
	int psci_role;		/* COALITION_ROLE_* */
	uint64_t psci_id;	/* coalition id */
	int psci_order;
};

void abort_with_reason(uint32_t reason_namespace, uint64_t reason_code, const char *reason_string, uint64_t reason_flags);

extern int systemwide_trust_file_by_path(const char *path);
extern int platform_set_process_debugged(uint64_t pid, bool fullyDebugged);
extern void systemwide_domain_set_enabled(bool enabled);

#define LOG_PROCESS_LAUNCHES 0

#define INJECTION_RULES_PATH "/var/mobile/Library/Preferences/.DopamineInjectionRules.plist"

#define APP_HIDE_RULES_PATH "/var/mobile/Library/Preferences/.DopamineAppHideRules.plist"

static bool should_hide_environment(const char *executablePath)
{
    if (!executablePath) return false;

    @autoreleasepool {
        NSString *path = [NSString stringWithUTF8String:executablePath];
        NSRange appRange = [path rangeOfString:@".app/"];
        if (appRange.location == NSNotFound) return false;

        NSString *appPath = [path substringToIndex:appRange.location + 4];
        NSString *infoPlistPath = [appPath stringByAppendingPathComponent:@"Info.plist"];
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
        NSString *bundleID = info[@"CFBundleIdentifier"];
        if (!bundleID) return false;

        NSDictionary *rules = [NSDictionary dictionaryWithContentsOfFile:@APP_HIDE_RULES_PATH];
        NSDictionary *appRule = rules[bundleID];
        BOOL hideEnv = [appRule[@"HideEnvironment"] boolValue];
        FILE *f = fopen("/var/mobile/Documents/noinject_log.txt", "a");
        if (f) { fprintf(f, "hide_env: %s = %d\n", bundleID.UTF8String, hideEnv); fclose(f); }
        return hideEnv;
    }
}

// RootHide-style "no-injection" mode: when HideNoInject is YES, don't inject
// systemhook at all — instead the jailbreak is hidden globally (remove /var/jb,
// unmount fakelib) while the app runs, then restored on exit.
static bool should_hide_no_inject(const char *executablePath)
{
    if (!executablePath) return false;

    @autoreleasepool {
        NSString *path = [NSString stringWithUTF8String:executablePath];
        NSRange appRange = [path rangeOfString:@".app/"];
        if (appRange.location == NSNotFound) return false;

        NSString *appPath = [path substringToIndex:appRange.location + 4];
        NSString *infoPlistPath = [appPath stringByAppendingPathComponent:@"Info.plist"];
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
        NSString *bundleID = info[@"CFBundleIdentifier"];
        if (!bundleID) return false;

        NSDictionary *rules = [NSDictionary dictionaryWithContentsOfFile:@APP_HIDE_RULES_PATH];
        NSDictionary *appRule = rules[bundleID];
        BOOL noInject = [appRule[@"HideNoInject"] boolValue];
        FILE *f = fopen("/var/mobile/Documents/noinject_log.txt", "a");
        if (f) { fprintf(f, "no_inject: %s = %d\n", bundleID.UTF8String, noInject); fclose(f); }
        return noInject;
    }
}

extern bool gInEarlyBoot;
extern bool gFreeBootLogoBeforeBackboardd;
void free_boot_logo(void);

void early_boot_done(void)
{
	gInEarlyBoot = false;
}

void ensure_fakelib_mounted(void)
{
	struct statfs fsb;
	if (statfs("/usr/lib", &fsb) != 0) return;
	if (strcmp(fsb.f_mntonname, "/usr/lib") != 0) {
		systemwide_domain_set_enabled(true);

		// The jailbreak server is not reachable at this point in the launchd lifecycle
		// So we need to host our own, just so that jbctl can talk to it
		mach_port_t serverPort = jbserver_local_start();
		jbctl_earlyboot(serverPort, "internal", "fakelib", "mount", NULL);
		jbserver_local_stop();

		// Note down that the jailbreak was hidden
		// So that after the userspace reboot, we can unmount fakelib again
		setenv("DOPAMINE_IS_HIDDEN", "1", true);
	}
}

static bool should_block_injection(const char *executablePath)
{
	if (!executablePath) return false;

	@autoreleasepool {
		NSString *path = [NSString stringWithUTF8String:executablePath];

		// Only handle executables inside an App bundle (…/XXX.app/XXX)
		NSRange appRange = [path rangeOfString:@".app/"];
		if (appRange.location == NSNotFound) {
			return false;
		}

		// Extract the .app directory path
		NSString *appPath = [path substringToIndex:appRange.location + 4];
		NSString *infoPlistPath = [appPath stringByAppendingPathComponent:@"Info.plist"];

		// Read Bundle ID
		NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
		NSString *bundleID = info[@"CFBundleIdentifier"];
		if (!bundleID) {
			return false;
		}

		// Read block rules
		NSDictionary *rules = [NSDictionary dictionaryWithContentsOfFile:@INJECTION_RULES_PATH];
		if (!rules) {
			return false;
		}

		NSDictionary *appRule = rules[bundleID];
		if (!appRule) {
			return false;
		}

		NSNumber *block = appRule[@"BlockInjection"];
		if (block && [block boolValue]) {
			return true;
		}
	}

	return false;
}

int __posix_spawn_orig_wrapper(pid_t *restrict pid, const char *restrict path,
					   struct _posix_spawn_args_desc *desc,
					   char *const argv[restrict],
					   char *const envp[restrict])
{
	// we need to disable the crash reporter during the orig call
	// otherwise the child process inherits the exception ports
	// and this would trip jailbreak detections
	crashreporter_pause();	
	int r = __posix_spawn_inline(pid, path, desc, argv, envp);
	crashreporter_resume();

	return r;
}

int __posix_spawn_hook(pid_t *restrict pid, const char *restrict path,
					   struct _posix_spawn_args_desc *desc,
					   char *const argv[restrict],
					   char *const envp[restrict])
{
	if (path) {
		char executablePath[1024];
		uint32_t bufsize = sizeof(executablePath);
		_NSGetExecutablePath(&executablePath[0], &bufsize);
		if (!strcmp(path, executablePath)) {
			// This spawn will perform a userspace reboot...
			// Instead of the ordinary hook, we want to reinsert this dylib
			// This has already been done in envp so we only need to call the original posix_spawn

			// We are back in "early boot" for the remainder of this launchd instance
			// Mainly so we don't lock up while spawning boomerang
			gInEarlyBoot = true;

			hookd_provider_teardown();

			// If the jailbreak is currently hidden, fakelib is not mounted
			// It needs to be mounted to regain launchd code execution after the userspace reboot
			ensure_fakelib_mounted();

#if LOG_PROCESS_LAUNCHES
			FILE *f = fopen("/var/mobile/launch_log.txt", "a");
			fprintf(f, "==== USERSPACE REBOOT ====\n");
			fclose(f);
#endif

			// Before the userspace reboot, we want to stash the primitives into boomerang
			boomerang_stashPrimitives();

			// Fix Xcode debugging being broken after the userspace reboot
			unmount("/Developer", MNT_FORCE);

			// If there is a pending jailbreak update, apply it now
			const char *stagedJailbreakUpdate = getenv("STAGED_JAILBREAK_UPDATE");
			if (stagedJailbreakUpdate) {
				int r = jbupdate_basebin(stagedJailbreakUpdate);
				if (r != 0) {
					char msg[1000];
					snprintf(msg, 1000, "Failed updating basebin (error %d).", r);
					abort_with_reason(7, 1, msg, 0);
				}
				unsetenv("STAGED_JAILBREAK_UPDATE");
			}

			// Always use environ instead of envp, as boomerang_stashPrimitives calls setenv
			// setenv / unsetenv can sometimes cause environ to get reallocated
			// In that case envp may point to garbage or be empty
			// Say goodbye to this process
			return __posix_spawn_orig_wrapper(pid, path, desc, argv, environ);
		}
	}

#if LOG_PROCESS_LAUNCHES
	if (path) {
		FILE *f = fopen("/var/mobile/launch_log.txt", "a");
		fprintf(f, "%s", path);
		int ai = 0;
		while (argv) {
			if (argv[ai]) {
				if (ai >= 1) {
					fprintf(f, " %s", argv[ai]);
				}
				ai++;
			}
			else {
				break;
			}
		}
		fprintf(f, "\n");
		fclose(f);

		// if (!strcmp(path, "/usr/libexec/xpcproxy")) {
		// 	const char *tmpBlacklist[] = {
		// 		"com.apple.logd"
		// 	};
		// 	size_t blacklistCount = sizeof(tmpBlacklist) / sizeof(tmpBlacklist[0]);
		// 	for (size_t i = 0; i < blacklistCount; i++)
		// 	{
		// 		if (!strcmp(tmpBlacklist[i], firstArg)) {
		// 			FILE *f = fopen("/var/mobile/launch_log.txt", "a");
		// 			fprintf(f, "blocked injection %s\n", firstArg);
		// 			fclose(f);
		// 			return __posix_spawn_orig_wrapper(pid, path, file_actions, desc, envp);
		// 		}
		// 	}
		// }
	}
#endif

	// We can't support injection into processes that get spawned before the launchd XPC server is up
	// (Technically we could but there is little reason to, since it requires additional work)
	if (gInEarlyBoot) {
		if (!strcmp(path, "/usr/libexec/xpcproxy")) {
			// The spawned process being xpcproxy indicates that the launchd XPC server is up
			// All processes spawned including this one should be injected into
			early_boot_done();
		}
		else {
			return __posix_spawn_orig_wrapper(pid, path, desc, argv, envp);
		}
	}

	// If we're drawing a boot logo, free up it's resources before backboardd starts
	if (gFreeBootLogoBeforeBackboardd) {
		if (!strcmp(path, "/usr/libexec/xpcproxy")) {
			if (argv[0]) {
				if (argv[1]) {
					if (!strcmp(argv[1], "com.apple.backboardd\n")) {
						free_boot_logo();
						gFreeBootLogoBeforeBackboardd = false;
					}
				}
			}
		}
	}

	// "Jailbreak app resurrection": if the jailbreak is currently hidden (a
	// no-inject app is running) and a jailbreak app (under /var/jb/) is being
	// spawned, restore the jailbreak, spawn it directly, and track its pid so it
	// can be killed when the jailbreak is re-hidden. No re-hide on exit.
	if (path && app_hide_is_currently_hidden() && app_hide_is_jailbreak_app(path)) {
		app_hide_resurrect_for_jb_app();
		pid_t jbPid = 0;
		int r = posix_spawn_hook_shared(&jbPid, path, desc, argv, envp, __posix_spawn_orig_wrapper, systemwide_trust_file_by_path, platform_set_process_debugged, jbsetting(jetsamMultiplier));
		if (pid) *pid = jbPid;
		if (r == 0) {
			app_hide_track_jailbreak_app(jbPid);
		}
		return r;
	}

	// Check whether this App is on the injection block list
	if (path && should_block_injection(path)) {
		return __posix_spawn_orig_wrapper(pid, path, desc, argv, envp);
	}



  if (path && should_hide_environment(path)) {
		if (should_hide_no_inject(path)) {
			// RootHide-style no-injection mode: temporarily hide the jailbreak
			// globally (remove /var/jb + unmount fakelib), bare-spawn the app
			// (no systemhook injection at all), and restore when it exits.
			app_hide_global_hide();
			// Diagnostic: log the spawn coalition role (a pre-spawn foreground/
			// background signal) so we can learn which role values map to each.
			if (desc && desc->coal_info) {
				FILE *f = fopen("/var/mobile/Documents/noinject_log.txt", "a");
				if (f) { fprintf(f, "spawn coal role=%d id=%llu\n", desc->coal_info->psci_role, desc->coal_info->psci_id); fclose(f); }
			} else {
				FILE *f = fopen("/var/mobile/Documents/noinject_log.txt", "a");
				if (f) { fprintf(f, "spawn coal info NULL\n"); fclose(f); }
			}
			pid_t *blacklistedPidp = (pid_t *)app_hide_alloc_pid();
			int r = __posix_spawn_orig_wrapper(blacklistedPidp, path, desc, argv, (char *const *)envp);
			pid_t childPid = *blacklistedPidp;
			if (pid) *pid = childPid;
			app_hide_commit_pid(blacklistedPidp);
			if (r == 0) {
				app_hide_watch_exit(childPid);
				app_hide_check_role_after_spawn(childPid);
			} else {
				app_hide_global_restore();
			}
			return r;
		}

		// ★ 按 App 隐藏（per-app hide）：
		// 只注入 systemhook（干净路径 /usr/lib/systemhook.dylib），并打上 DOPAMINE_APP_HIDE=1。
		// systemhook 的构造器看到这个标记后走 hidejb 分支：在 *本进程内* 隐藏 /var/jb、
		// 真实 jailbreak root、fakelib 挂载以及 amfi developer_mode 状态，且不加载任何 tweak。
		// 不再做全局隐藏（不卸载 fakelib、不删除 /var/jb、不搬移文件），其它越狱进程不受影响。

		char **envc = envbuf_mutcopy((const char **)envp);
		envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", HOOK_DYLIB_PATH);
		envbuf_setenv(&envc, "DOPAMINE_APP_HIDE", "1");
		envbuf_unsetenv(&envc, "_SafeMode");
		envbuf_unsetenv(&envc, "_MSSafeMode");

		// __posix_spawn_orig_wrapper 内部已做 crashreporter_pause/resume，
		// 避免子进程继承异常端口而被越狱检测发现。
		// 同时把这个隐藏 App 的 pid 标记进黑名单（RootHide 式进程隐藏）：
		// launchd 的 XPC 回复钩子会据此过滤它的进程/coalition 枚举结果。
		pid_t *blacklistedPidp = (pid_t *)app_hide_alloc_pid();
		int r = __posix_spawn_orig_wrapper(blacklistedPidp, path, desc, argv, envc);
		envbuf_free(envc);
		if (pid) *pid = *blacklistedPidp;
		app_hide_commit_pid(blacklistedPidp);

		return r;
	}



	return posix_spawn_hook_shared(pid, path, desc, argv, envp, __posix_spawn_orig_wrapper, systemwide_trust_file_by_path, platform_set_process_debugged, jbsetting(jetsamMultiplier));
}

void initSpawnHooks(void)
{
	litehook_hook_function(__posix_spawn, __posix_spawn_hook);
}