// hidejb.c
//
// Per-process jailbreak hiding for Dopamine (rootless).
//
// Replaces the old "app_hide_monitor" approach (which *globally* unmounted
// fakelib, deleted /var/jb and physically moved files into a quarantine dir)
// with a RootHide-style, per-process filesystem virtualization that keeps the
// rootless /var/jb layout intact.
//
// In a "hidden" app this hooks (from inside that one process only):
//   - file syscalls:        hide /var/jb, the real jbroot, jailbreak files/prefs
//                           (the rules live in hidejb_rules.c),
//   - readdir:              filter jailbreak entries out of directory listings,
//   - dyld image enumeration/dlopen/dladdr/dlsym: hide the injected dylibs & symbols,
//   - csops:                clear CS_DEBUGGED / set hardening flags,
//   - sysctl:               hide amfi developer-mode flag,
//   - LSApplicationWorkspace/UIApplication canOpenURL: hide jailbreak URL schemes.
//
// The path-matching rules are in a SEPARATE compilation unit (hidejb_rules.c)
// so Clang -Os cannot inline them into the hooks (which otherwise mis-compiles
// a strncmp and crashes).
//

#include "hidejb.h"
#include "hidejb_rules.h"

#include <litehook.h>
#include <substrate.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <mach/task.h>
#include <dispatch/dispatch.h>
#include <libjailbreak/codesign.h>
#include <objc/runtime.h>
#include <objc/message.h>

#ifndef SYS_csops
#define SYS_csops 0xA9
#endif
#ifndef SYS_csops_audittoken
#define SYS_csops_audittoken 0xAA
#endif

static bool gEnabled = false;

// Indices of injected jailbreak dylibs (systemhook, libellekit, ...) in the
// dyld image list. _dyld_get_image_name returns a benign name for these.
static uint32_t gHiddenImageIndices[8] = {0};
static uint32_t gHiddenImageCount = 0;

bool hidejb_enabled(void)
{
	return getenv("DOPAMINE_APP_HIDE") != NULL;
}

#pragma mark - fopen (non-variadic; open/openat are deliberately NOT hooked —
// hooking the variadic open() via MSHookFunction kept crashing on arm64, and
// fopen covers the common "fopen(\"/var/jb/...\")" check without a variadic ABI)

static FILE *(*orig_fopen)(const char *, const char *);
static FILE *hidejb_fopen(const char *path, const char *mode)
{
	if (gEnabled && hidejb_rules_path_is_jailbreak(path)) { errno = ENOENT; return NULL; }
	return orig_fopen(path, mode);
}

#pragma mark - stat family

static int (*orig_stat)(const char *, struct stat *);
static int hidejb_stat(const char *path, struct stat *buf)
{
	if (gEnabled && hidejb_rules_path_is_jailbreak(path)) { errno = ENOENT; return -1; }
	return orig_stat(path, buf);
}

static int (*orig_lstat)(const char *, struct stat *);
static int hidejb_lstat(const char *path, struct stat *buf)
{
	if (gEnabled && hidejb_rules_path_is_jailbreak(path)) { errno = ENOENT; return -1; }
	return orig_lstat(path, buf);
}

static int (*orig_fstatat)(int, const char *, struct stat *, int);
static int hidejb_fstatat(int fd, const char *path, struct stat *buf, int flag)
{
	if (gEnabled && hidejb_rules_path_is_jailbreak(path)) { errno = ENOENT; return -1; }
	return orig_fstatat(fd, path, buf, flag);
}

#pragma mark - access family

static int (*orig_access)(const char *, int);
static int hidejb_access(const char *path, int mode)
{
	if (gEnabled && hidejb_rules_path_is_jailbreak(path)) { errno = ENOENT; return -1; }
	return orig_access(path, mode);
}

static int (*orig_faccessat)(int, const char *, int, int);
static int hidejb_faccessat(int fd, const char *path, int mode, int flag)
{
	if (gEnabled && hidejb_rules_path_is_jailbreak(path)) { errno = ENOENT; return -1; }
	return orig_faccessat(fd, path, mode, flag);
}

#pragma mark - realpath / readlink

static char *(*orig_realpath)(const char *restrict, char *restrict);
static char *hidejb_realpath(const char *restrict path, char *restrict resolved)
{
	if (gEnabled && hidejb_rules_path_is_jailbreak(path)) { errno = ENOENT; return NULL; }
	return orig_realpath(path, resolved);
}

static ssize_t (*orig_readlink)(const char *, char *, size_t);
static ssize_t hidejb_readlink(const char *path, char *buf, size_t bufsize)
{
	if (gEnabled && hidejb_rules_path_is_jailbreak(path)) { errno = ENOENT; return -1; }
	return orig_readlink(path, buf, bufsize);
}

static ssize_t (*orig_readlinkat)(int, const char *, char *, size_t);
static ssize_t hidejb_readlinkat(int fd, const char *path, char *buf, size_t bufsize)
{
	if (gEnabled && hidejb_rules_path_is_jailbreak(path)) { errno = ENOENT; return -1; }
	return orig_readlinkat(fd, path, buf, bufsize);
}

#pragma mark - opendir / readdir (filter directory listings too)

static DIR *(*orig_opendir)(const char *);
static DIR *hidejb_opendir(const char *dirname)
{
	if (gEnabled && hidejb_rules_path_is_jailbreak(dirname)) { errno = ENOENT; return NULL; }
	return orig_opendir(dirname);
}

static struct dirent *(*orig_readdir)(DIR *);
static struct dirent *hidejb_readdir(DIR *dirp)
{
	if (!gEnabled || !dirp) return orig_readdir(dirp);

	int fd = dirfd(dirp);
	if (fd < 0) return orig_readdir(dirp);

	char dirpath[PATH_MAX] = {0};
	if (fcntl(fd, F_GETPATH, dirpath) != 0) return orig_readdir(dirp);

	while (1) {
		struct dirent *e = orig_readdir(dirp);
		if (!e) return NULL;
		char full[PATH_MAX * 2];
		snprintf(full, sizeof(full), "%s/%s", dirpath, e->d_name);
		if (!hidejb_rules_path_is_jailbreak(full)) return e;
		// else skip this entry
	}
}

#pragma mark - statfs (hide the fakelib bind mount over /usr/lib)

static int (*orig_statfs)(const char *, struct statfs *);
static int hidejb_statfs(const char *path, struct statfs *buf)
{
	if (gEnabled && path) {
		if (strcmp(path, "/usr/lib") == 0 || strncmp(path, "/usr/lib/", 9) == 0) {
			return orig_statfs("/", buf);
		}
	}
	return orig_statfs(path, buf);
}

#pragma mark - sysctl (hide amfi developer-mode flag)

static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t);
static int hidejb_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen)
{
	if (gEnabled && name && strcmp(name, "security.mac.amfi.developer_mode_status") == 0) {
		if (oldp && oldlenp && *oldlenp >= sizeof(int)) {
			*(int *)oldp = 1;
			*oldlenp = sizeof(int);
			return 0;
		}
	}
	return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

#pragma mark - dyld image enumeration (hide the injected dylibs)

static const char *(*orig_dyld_get_image_name)(uint32_t);

static bool hidejb_is_hidden_image_index(uint32_t i)
{
	for (uint32_t k = 0; k < gHiddenImageCount; k++) {
		if (gHiddenImageIndices[k] == i) return true;
	}
	return false;
}

// SAFE variant: keep dyld's real image count and indices unchanged, and only
// rename the hidden images to a benign path. Remapping indices (returning a
// reduced count) broke apps that resolve symbols/images by index, so we never
// shift indices — we only lie about the *name* of the jailbreak dylibs.
static const char *hidejb_dyld_get_image_name(uint32_t index)
{
	if (gEnabled && hidejb_is_hidden_image_index(index)) {
		return "/usr/lib/libSystem.B.dylib";
	}
	return orig_dyld_get_image_name(index);
}

#pragma mark - dlopen / dladdr (hide the injected dylibs)

static void *(*orig_dlopen)(const char *, int);
static void *hidejb_dlopen(const char *path, int mode)
{
	if (gEnabled && path) {
		if (strstr(path, "systemhook") || strstr(path, "libellekit") ||
		    strstr(path, "CydiaSubstrate") || strstr(path, "libjailbreak") ||
		    strstr(path, "TweakLoader")) {
			return NULL;
		}
	}
	return orig_dlopen(path, mode);
}

static int (*orig_dladdr)(const void *, Dl_info *);
static int hidejb_dladdr(const void *addr, Dl_info *info)
{
	int r = orig_dladdr(addr, info);
	if (gEnabled && r != 0 && info && info->dli_fname) {
		if (strstr(info->dli_fname, "systemhook") || strstr(info->dli_fname, "libellekit") ||
		    strstr(info->dli_fname, "CydiaSubstrate") || strstr(info->dli_fname, "libjailbreak") ||
		    strstr(info->dli_fname, "TweakLoader")) {
			return 0;
		}
	}
	return r;
}

static void *(*orig_dlsym)(void *, const char *);
static const char *kJailbreakSymbolMarkers[] = {
	"MSHookFunction", "MSHookMessageEx", "MSHookMemory", "MSFindSymbol",
	"jbclient_", "libjailbreak_", "jailbreakd", "Dopamine", "dopamine",
	"hidejb_", "rootlesshooks", "procursus",
	NULL
};
static void *hidejb_dlsym(void *handle, const char *symbol)
{
	if (gEnabled && symbol) {
		for (int i = 0; kJailbreakSymbolMarkers[i]; i++) {
			if (strstr(symbol, kJailbreakSymbolMarkers[i])) return NULL;
		}
	}
	return orig_dlsym(handle, symbol);
}

#pragma mark - (task_for_pid/task_name_for_pid deliberately NOT hooked)
// Hooking task_for_pid/task_name_for_pid to return KERN_FAILURE for self broke
// IOHIDEventSystemClient (UIKit's HID event-fetch thread calls task_for_pid on
// ITSELF and asserts on failure), and it does not actually hide "task port was
// additionally referenced" (that is a send-right refcount issue caused by the
// injector, not by the app calling task_for_pid). Leave them unhooked.

#pragma mark - csops (hide the debug/invalid code-signature flags) [arm64]

#ifndef __arm64e__
static int hidejb_csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize)
{
	int rv = syscall(SYS_csops, pid, ops, useraddr, usersize);
	if (rv != 0) return rv;
	if (ops == CS_OPS_STATUS) {
		if (useraddr && usersize == sizeof(uint32_t)) {
			uint32_t *csflag = (uint32_t *)useraddr;
			// Look like a normally-signed, hardened app again.
			*csflag |= CS_VALID | CS_HARD | CS_KILL | CS_RESTRICT | CS_ENFORCEMENT | CS_REQUIRE_LV;
			*csflag &= ~(CS_DEBUGGED | CS_GET_TASK_ALLOW);
		}
	}
	return rv;
}

static int hidejb_csops_audittoken(pid_t pid, unsigned int ops, void *useraddr, size_t usersize, audit_token_t *token)
{
	int rv = syscall(SYS_csops_audittoken, pid, ops, useraddr, usersize, token);
	if (rv != 0) return rv;
	if (ops == CS_OPS_STATUS) {
		if (useraddr && usersize == sizeof(uint32_t)) {
			uint32_t *csflag = (uint32_t *)useraddr;
			*csflag |= CS_VALID | CS_HARD | CS_KILL | CS_RESTRICT | CS_ENFORCEMENT | CS_REQUIRE_LV;
			*csflag &= ~(CS_DEBUGGED | CS_GET_TASK_ALLOW);
		}
	}
	return rv;
}
#endif

#pragma mark - URL scheme hiding (per-app canOpenURL: hook, RootHide-style)

static BOOL (*orig_UIApp_canOpenURL)(id, SEL, id) = NULL;
static BOOL (*orig_LS_canOpenURL)(id, SEL, id) = NULL;

static const char *kJailbreakSchemes[] = {
	// jailbreak apps
	"sileo", "zebra", "filza", "apt-repo", "cydia", "sileo-nano",
	"icleaner", "saily", "chromatic", "misaka", "cowabunga",
	// Filza's file-provider / OAuth schemes
	"db-lmvo0l08204d0a0", "boxsdk-810yk37nbrpwaee5907xc4iz8c1ay3my",
	"com.googleusercontent.apps.802910049260-0hf6uv6nsj21itl94v66tphcqnfl172r",
	// other detector apps
	"reveil", "82flex", "postbox", "santander",
	NULL
};

static BOOL is_jailbreak_scheme(id url)
{
	if (!url) return NO;
	id schemeObj = ((id (*)(id, SEL))objc_msgSend)(url, sel_registerName("scheme"));
	if (!schemeObj) return NO;
	const char *s = ((const char *(*)(id, SEL))objc_msgSend)(schemeObj, sel_registerName("UTF8String"));
	if (!s) return NO;
	for (int i = 0; kJailbreakSchemes[i]; i++) {
		if (strcasecmp(s, kJailbreakSchemes[i]) == 0) return YES;
	}
	return NO;
}

static BOOL hide_UIApp_canOpenURL(id self, SEL _cmd, id url)
{
	if (gEnabled && is_jailbreak_scheme(url)) return NO;
	return orig_UIApp_canOpenURL(self, _cmd, url);
}

static BOOL hide_LS_canOpenURL(id self, SEL _cmd, id url)
{
	if (gEnabled && is_jailbreak_scheme(url)) return NO;
	return orig_LS_canOpenURL(self, _cmd, url);
}

// Swizzle -canOpenURL: on a class (best-effort; retried later if not loaded yet).
static void swizzle_canOpenURL(const char *className, IMP newImp, IMP *origOut)
{
	Class cls = objc_getClass(className);
	if (!cls) return;
	Method m = class_getInstanceMethod(cls, sel_registerName("canOpenURL:"));
	if (!m) return;
	if (*origOut == NULL) {
		*origOut = method_getImplementation(m);
		method_setImplementation(m, newImp);
	}
}

static void hidejb_swizzle_url_schemes_impl(void *ctx)
{
	swizzle_canOpenURL("UIApplication", (IMP)hide_UIApp_canOpenURL, (IMP *)&orig_UIApp_canOpenURL);
	swizzle_canOpenURL("LSApplicationWorkspace", (IMP)hide_LS_canOpenURL, (IMP *)&orig_LS_canOpenURL);
}

static void hidejb_swizzle_url_schemes(void)
{
	hidejb_swizzle_url_schemes_impl(NULL);
	// Retry shortly after launch (main queue) in case the classes are lazily loaded.
	dispatch_after_f(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC),
					 dispatch_get_main_queue(), NULL, hidejb_swizzle_url_schemes_impl);
}

#pragma mark - init

void hidejb_init(const char *jbroot)
{
	if (!hidejb_enabled()) return;

	gEnabled = true;

	hidejb_rules_set_jbroot(jbroot);
	hidejb_rules_set_self_bundle_id();

	{
		uint32_t n = _dyld_image_count();
		for (uint32_t i = 0; i < n; i++) {
			const char *name = _dyld_get_image_name(i);
			if (!name) continue;
			if (strstr(name, "systemhook") || strstr(name, "libellekit") || strstr(name, "CydiaSubstrate")) {
				if (gHiddenImageCount < sizeof(gHiddenImageIndices)/sizeof(gHiddenImageIndices[0])) {
					gHiddenImageIndices[gHiddenImageCount++] = i;
				}
			}
		}
	}

	// ★ Instruction-replace the shared-cache functions (MSHookFunction) so that
	// ALL callers — including Foundation/UIKit internals — go through our hooks.
	// litehook_rebind_symbol only rewrites the app's own GOT entries, so it misses
	// the internal stat/access/open calls that NSFileManager & friends make.
	MSHookFunction((void *)fopen,        (void *)hidejb_fopen,        (void **)&orig_fopen);
	MSHookFunction((void *)stat,         (void *)hidejb_stat,         (void **)&orig_stat);
	MSHookFunction((void *)lstat,        (void *)hidejb_lstat,        (void **)&orig_lstat);
	MSHookFunction((void *)fstatat,      (void *)hidejb_fstatat,      (void **)&orig_fstatat);
	MSHookFunction((void *)access,       (void *)hidejb_access,       (void **)&orig_access);
	MSHookFunction((void *)faccessat,    (void *)hidejb_faccessat,    (void **)&orig_faccessat);
	MSHookFunction((void *)realpath,     (void *)hidejb_realpath,     (void **)&orig_realpath);
	MSHookFunction((void *)readlink,     (void *)hidejb_readlink,     (void **)&orig_readlink);
	MSHookFunction((void *)readlinkat,   (void *)hidejb_readlinkat,   (void **)&orig_readlinkat);
	MSHookFunction((void *)opendir,      (void *)hidejb_opendir,      (void **)&orig_opendir);
	MSHookFunction((void *)readdir,      (void *)hidejb_readdir,      (void **)&orig_readdir);
	MSHookFunction((void *)statfs,       (void *)hidejb_statfs,       (void **)&orig_statfs);
	MSHookFunction((void *)sysctlbyname, (void *)hidejb_sysctlbyname, (void **)&orig_sysctlbyname);

	MSHookFunction((void *)_dyld_get_image_name,        (void *)hidejb_dyld_get_image_name,        (void **)&orig_dyld_get_image_name);
	MSHookFunction((void *)dlopen,                      (void *)hidejb_dlopen,                      (void **)&orig_dlopen);
	MSHookFunction((void *)dladdr,                      (void *)hidejb_dladdr,                      (void **)&orig_dladdr);
	MSHookFunction((void *)dlsym,                       (void *)hidejb_dlsym,                       (void **)&orig_dlsym);

#ifndef __arm64e__
	// csops: keep the inline-syscall style (matches systemhook/main.c).
	litehook_hook_function((void *)csops,           (void *)hidejb_csops);
	litehook_hook_function((void *)csops_audittoken, (void *)hidejb_csops_audittoken);
#endif

	hidejb_swizzle_url_schemes();
}
