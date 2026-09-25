#include <spawn.h>
#include "../systemhook/src/common/common.h"
#include "boomerang.h"
#include "crashreporter.h"
#include "update.h"
#include <libjailbreak/util.h>
#include <substrate.h>
#include <mach-o/dyld.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <litehook.h>
#include "jbserver/jbserver_local.h"
#include "hookd_provider.h"
#import <Foundation/Foundation.h>
#import "app_hide_monitor.h"
#include <mach/mach.h>
#include <mach/task.h>
extern char **environ;

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
        return [appRule[@"HideEnvironment"] boolValue];
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

// Check whether this App is on the injection block list
	if (path && should_block_injection(path)) {
		return __posix_spawn_orig_wrapper(pid, path, desc, argv, envp);
	}



  if (path && should_hide_environment(path)) {
		// 目标 App：挂起它，同步 hide，再放行
		bool didSuspend = false;
		short originalFlags = 0;
		if (desc && desc->attrp) {
			if (posix_spawnattr_getflags(&desc->attrp, &originalFlags) == 0) {
				if (!(originalFlags & POSIX_SPAWN_START_SUSPENDED)) {
					posix_spawnattr_setflags(&desc->attrp, originalFlags | POSIX_SPAWN_START_SUSPENDED);
					didSuspend = true;
				}
			}
		}

		// ★ 关键：在 spawn 之前清空 launchd 自己的异常端口
		// 这样目标 App 从 fork 那一刻起就不会继承 crashreporter 的端口
		exception_mask_t savedMasks[EXC_TYPES_COUNT];
		mach_port_t savedPorts[EXC_TYPES_COUNT];
		exception_behavior_t savedBehaviors[EXC_TYPES_COUNT];
		thread_state_flavor_t savedFlavors[EXC_TYPES_COUNT];
		mach_msg_type_number_t savedCount = EXC_TYPES_COUNT;

		kern_return_t kr = task_get_exception_ports(mach_task_self(),
			EXC_MASK_ALL, savedMasks, &savedCount, savedPorts, savedBehaviors, savedFlavors);

		bool restoreNeeded = false;
		if (kr == KERN_SUCCESS && savedCount > 0) {
			task_set_exception_ports(mach_task_self(), EXC_MASK_ALL,
				MACH_PORT_NULL, EXCEPTION_DEFAULT, 0);
			restoreNeeded = true;
		}

		// 不注入 systemhook，直接调用原始 posix_spawn
		int r = __posix_spawn_orig_wrapper(pid, path, desc, argv, envp);

		// 恢复 launchd 自己的异常端口
		if (restoreNeeded) {
			for (mach_msg_type_number_t i = 0; i < savedCount; i++) {
				task_set_exception_ports(mach_task_self(), savedMasks[i],
					savedPorts[i], savedBehaviors[i], savedFlavors[i]);
			}
		}

		// 恢复 attr 原始 flags
		if (didSuspend) {
			posix_spawnattr_setflags(&desc->attrp, originalFlags);
		}

		if (r != 0) return r;

		app_hide_perform_hide_sync();

		if (didSuspend && pid && *pid > 0) {
			kill(*pid, SIGCONT);
		}

		return r;
	}

	return posix_spawn_hook_shared(pid, path, desc, argv, envp, __posix_spawn_orig_wrapper, systemwide_trust_file_by_path, platform_set_process_debugged, jbsetting(jetsamMultiplier));
}

void initSpawnHooks(void)
{
	litehook_hook_function(__posix_spawn, __posix_spawn_hook);
}