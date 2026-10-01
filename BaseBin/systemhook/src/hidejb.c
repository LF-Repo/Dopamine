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
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/vm_region.h>

// <mach/mach_vm.h> is an "#error unsupported" stub in the iOS SDK, so the
// mach_vm entry points are declared by hand (same as common/private.h does).
extern kern_return_t mach_vm_region_recurse(vm_map_read_t target_task, mach_vm_address_t *address, mach_vm_size_t *size, natural_t *nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t *infoCnt);
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

// NOTE: resolving the directory path with fcntl(F_GETPATH) on *every* entry was
// a disaster: F_GETPATH is a syscall and fcntl is itself hooked by dyld's
// MachOMerger, so directory iteration (which Foundation does constantly while
// loading bundles) became ~30x slower and tripped the launch watchdog on big
// apps (QQ used 31s of CPU with only 1s of it in the app itself).
// We now resolve it once per DIR and skip filtering entirely for directories
// that cannot contain hidden entries.
static DIR *gLastDirp = NULL;
static bool gLastDirFilter = false;
static char gLastDirPath[PATH_MAX] = {0};

static struct dirent *(*orig_readdir)(DIR *);
static struct dirent *hidejb_readdir(DIR *dirp)
{
	if (!gEnabled || !dirp) return orig_readdir(dirp);

	if (dirp != gLastDirp) {
		gLastDirp = dirp;
		gLastDirFilter = false;
		gLastDirPath[0] = '\0';
		int fd = dirfd(dirp);
		if (fd >= 0) {
			char p[PATH_MAX] = {0};
			if (fcntl(fd, F_GETPATH, p) == 0 && p[0]) {
				strlcpy(gLastDirPath, p, sizeof(gLastDirPath));
				gLastDirFilter = hidejb_rules_dir_may_hide_entries(p);
			}
		}
	}
	if (!gLastDirFilter) return orig_readdir(dirp);

	// Copy once (not per entry) so a concurrent readdir on another DIR cannot
	// rewrite the cached path while we are filtering entries of this one.
	char dirpath[PATH_MAX];
	strlcpy(dirpath, gLastDirPath, sizeof(dirpath));
	if (!dirpath[0]) return orig_readdir(dirp);

	for (;;) {
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

// --- dyld_all_image_infos patching (the RootHide trick) ---------------------
// Hooking _dyld_get_image_name only fools callers that go through that one
// accessor. A detector that reads dyld_all_image_infos directly (through
// task_info(TASK_DYLD_INFO) or _dyld_get_all_image_infos()) still sees the
// injected dylibs, which is how the anti-tamper SDKs find the injection.
// So we ALSO rewrite the path pointer inside dyld's own info array, i.e. we
// change the data rather than the accessor. We verify the memory is writable
// first and bail out entirely if anything looks unexpected.

static bool hidejb_range_is_writable(const void *addr, size_t size)
{
	if (!addr || !size) return false;

	mach_vm_address_t regionAddr = (mach_vm_address_t)addr;
	mach_vm_size_t regionSize = 0;
	uint32_t depth = 0;
	vm_region_submap_info_data_64_t info;
	mach_msg_type_number_t infoCount = VM_REGION_SUBMAP_INFO_COUNT_64;
	kern_return_t kr = mach_vm_region_recurse(mach_task_self(), &regionAddr, &regionSize,
											  &depth, (vm_region_recurse_info_t)&info, &infoCount);
	if (kr != KERN_SUCCESS) return false;
	if (!(info.protection & VM_PROT_WRITE)) return false;

	// The whole range must live inside this one region.
	mach_vm_address_t start = (mach_vm_address_t)addr;
	return start >= regionAddr && (start + size) <= (regionAddr + regionSize);
}

static void hidejb_patch_all_image_infos(void)
{
	task_dyld_info_data_t dyldInfo;
	uint32_t count = TASK_DYLD_INFO_COUNT;
	if (task_info(mach_task_self_, TASK_DYLD_INFO, (task_info_t)&dyldInfo, &count) != KERN_SUCCESS) return;

	struct dyld_all_image_infos *infos = (struct dyld_all_image_infos *)dyldInfo.all_image_info_addr;
	if (!infos || !infos->infoArray || infos->infoArrayCount == 0) return;
	if (infos->infoArrayCount > 8192) return;

	size_t arrSize = sizeof(struct dyld_image_info) * infos->infoArrayCount;
	if (!hidejb_range_is_writable(infos->infoArray, arrSize)) return;

	struct dyld_image_info *arr = (struct dyld_image_info *)infos->infoArray;
	for (uint32_t i = 0; i < infos->infoArrayCount; i++) {
		const char *p = arr[i].imageFilePath;
		if (!p) continue;
		if (hidejb_rules_path_has_marker(p)) {
			arr[i].imageFilePath = "/usr/lib/libSystem.B.dylib";
		}
	}
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
	void *result = orig_dlopen(path, mode);
	// Adding an image makes dyld rebuild/reallocate its info array, which would
	// undo the path rewrite below, so re-apply it after every dlopen.
	if (gEnabled) hidejb_patch_all_image_infos();
	return result;
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

	// Rewrite the paths inside dyld's own image array as well, so detectors that
	// bypass _dyld_get_image_name still cannot see the injected dylibs.
	hidejb_patch_all_image_infos();

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
