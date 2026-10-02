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
// dyld image list, plus a UNIQUE benign path per entry.
//
// NOTE: these paths must be unique. Pointing every hidden image at the same
// real path ("/usr/lib/libSystem.B.dylib") made two images share one path, which
// confuses CFBundle's "image path -> bundle" cache and made Foundation spin in
// repeated bundle/version resolution (this tripped QQ's launch watchdog with
// 31s+ of pure userspace CPU, stranding threads in
// _CFBundleGetBundleVersionForURL -> _CFIterateDirectory).
#define HIDE_MAX_IMAGES 8
static uint32_t gHiddenImageIndices[HIDE_MAX_IMAGES] = {0};
static uint32_t gHiddenImageCount = 0;
static char gHiddenImageFakePaths[HIDE_MAX_IMAGES][40];
// Once the Mach-O header's LC_ID_DYLIB has been rewritten in place, this holds
// a pointer to that very string, so the image list, _dyld_get_image_name() and
// the binary's own self-description all read back the SAME bytes.
static const char *gHiddenImageFakePtrs[HIDE_MAX_IMAGES] = {0};

// mach_vm.h is an "#error unsupported" stub in the iOS SDK, so declare by hand
// (same as common/private.h does for the other mach_vm entry points).
extern kern_return_t mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
#ifndef VM_PROT_COPY
#define VM_PROT_COPY 0x10
#endif

static const char *hidejb_fake_path_for_slot(uint32_t slot)
{
	if (slot >= HIDE_MAX_IMAGES) return NULL;
	if (!gHiddenImageFakePaths[slot][0]) {
		snprintf(gHiddenImageFakePaths[slot], sizeof(gHiddenImageFakePaths[slot]),
		         "/usr/lib/libSystem.B.%u.dylib", slot);
	}
	return gHiddenImageFakePaths[slot];
}

static int hidejb_hidden_slot_for_index(uint32_t realIndex)
{
	for (uint32_t k = 0; k < gHiddenImageCount; k++) {
		if (gHiddenImageIndices[k] == realIndex) return (int)k;
	}
	return -1;
}

static int hidejb_register_hidden_index(uint32_t realIndex)
{
	int slot = hidejb_hidden_slot_for_index(realIndex);
	if (slot >= 0) return slot;
	if (gHiddenImageCount >= HIDE_MAX_IMAGES) return -1;
	gHiddenImageIndices[gHiddenImageCount] = realIndex;
	return (int)gHiddenImageCount++;
}

static bool hidejb_is_hidden_image_index(uint32_t i)
{
	return hidejb_hidden_slot_for_index(i) >= 0;
}

#pragma mark - LC_ID_DYLIB consistency rewrite (the RootHide trick)

// Find the name string of an image's LC_ID_DYLIB (the dylib's own
// self-description, e.g. "@loader_path/systemhook.dylib").
static char *hidejb_image_id_dylib_name(const struct mach_header *header)
{
	if (!header) return NULL;

	const struct mach_header_64 *mh = (const struct mach_header_64 *)header;
	if (mh->magic != MH_MAGIC_64) return NULL;

	const uint8_t *p = (const uint8_t *)mh + sizeof(struct mach_header_64);
	for (uint32_t i = 0; i < mh->ncmds; i++) {
		const struct load_command *lc = (const struct load_command *)p;
		if (lc->cmdsize < sizeof(struct load_command)) return NULL;
		if (lc->cmd == LC_ID_DYLIB) {
			const struct dylib_command *dc = (const struct dylib_command *)lc;
			if (dc->dylib.name.offset >= lc->cmdsize) return NULL;
			return (char *)lc + dc->dylib.name.offset;
		}
		p += lc->cmdsize;
	}
	return NULL;
}

// Overwrite an image's LC_ID_DYLIB name IN PLACE with a benign string that fits
// in the original allocation, and return a pointer to it.
//
// Why this matters: faking only dyld_all_image_infos / _dyld_get_image_name
// leaves the binary itself still saying "systemhook.dylib" / "libellekit.dylib",
// so an anti-tamper SDK that compares the two sees a contradiction and
// self-destructs (that is exactly how the banking app was crashing). Rewriting
// the header removes the contradiction instead of papering over it.
//
// Safety: the write never exceeds the length of the original NUL-terminated
// string, we never touch bytes past our own NUL, and if anything is unexpected
// (no LC_ID_DYLIB, no room, page not made writable) we simply skip this image.
static const char *hidejb_rewrite_id_dylib(const struct mach_header *header, uint32_t slot)
{
	char *name = hidejb_image_id_dylib_name(header);
	if (!name || !name[0]) return NULL;

	size_t origLen = strlen(name);
	if (origLen < 12 || origLen > 512) return NULL;

	char fake[64];
	snprintf(fake, sizeof(fake), "/usr/lib/libsystem_%u.dylib", slot);
	size_t fakeLen = strlen(fake);
	if (fakeLen > origLen) {
		snprintf(fake, sizeof(fake), "libsystem_%u.dylib", slot);
		fakeLen = strlen(fake);
		if (fakeLen > origLen) return NULL;
	}

	uintptr_t start = (uintptr_t)name;
	uintptr_t pageStart = start & ~(uintptr_t)0x3FFF;
	uintptr_t pageEnd = (start + fakeLen + 1 + 0x3FFFu) & ~(uintptr_t)0x3FFF;
	if (mach_vm_protect(mach_task_self(), pageStart, pageEnd - pageStart, FALSE,
						VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS) {
		return NULL;
	}

	memcpy(name, fake, fakeLen);
	name[fakeLen] = '\0';

	// Restore the original page protection. LC_ID_DYLIB lives in the load-command
	// area at the start of the Mach-O, i.e. in __TEXT, which is normally r-x.
	// Leaving a writable code page behind is itself a tamper signal.
	mach_vm_protect(mach_task_self(), pageStart, pageEnd - pageStart, FALSE,
					VM_PROT_READ | VM_PROT_EXECUTE);
	return name;
}

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

// Resolving a directory's path costs a fcntl syscall (and fcntl is itself hooked
// by dyld's MachOMerger), so it is cached per (thread, DIR) and never done per
// entry. The cache is thread-local: with many threads enumerating directories at
// once, a shared cache was rewritten under another thread's feet, which could
// make us filter entries against the WRONG directory path.
static __thread DIR *tLastDirp = NULL;
static __thread bool tLastDirFilter = false;
static __thread char tLastDirPath[PATH_MAX];

static struct dirent *(*orig_readdir)(DIR *);
static struct dirent *hidejb_readdir(DIR *dirp)
{
	if (!gEnabled || !dirp) return orig_readdir(dirp);

	if (dirp != tLastDirp) {
		tLastDirp = dirp;
		tLastDirFilter = false;
		tLastDirPath[0] = '\0';
		int fd = dirfd(dirp);
		if (fd >= 0) {
			char p[PATH_MAX] = {0};
			if (fcntl(fd, F_GETPATH, p) == 0 && p[0]) {
				strlcpy(tLastDirPath, p, sizeof(tLastDirPath));
				tLastDirFilter = hidejb_rules_dir_may_hide_entries(p);
			}
		}
	}
	if (!tLastDirFilter || !tLastDirPath[0]) return orig_readdir(dirp);

	for (;;) {
		struct dirent *e = orig_readdir(dirp);
		if (!e) return NULL;
		// Decide from (directory, entry name) — building the full path with
		// snprintf here is what made recursive enumeration ~30x too slow.
		if (!hidejb_rules_dir_hides_entry(tLastDirPath, e->d_name)) return e;
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

// SAFE variant: keep dyld's real image count and indices unchanged, and only
// rename the hidden images to a unique benign path. Remapping indices
// (returning a reduced count) broke apps that resolve symbols/images by index,
// so we never shift indices — we only lie about the *name* of the jailbreak
// dylibs, and each fake name is unique (see the note on gHiddenImageFakePaths).
static const char *hidejb_dyld_get_image_name(uint32_t index)
{
	if (gEnabled) {
		int slot = hidejb_hidden_slot_for_index(index);
		if (slot >= 0) {
			// Prefer the rewritten copy inside the Mach-O header itself, so this
			// accessor and the binary's LC_ID_DYLIB agree byte for byte.
			if (gHiddenImageFakePtrs[slot]) return gHiddenImageFakePtrs[slot];
			const char *fake = hidejb_fake_path_for_slot((uint32_t)slot);
			if (fake) return fake;
		}
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
		if (!hidejb_rules_path_has_marker(p)) continue;

		int slot = hidejb_register_hidden_index(i);
		if (slot < 0) continue;

		// Rewrite the binary's own LC_ID_DYLIB first, then point the image list
		// at that same string.
		const char *inHeader = hidejb_rewrite_id_dylib(_dyld_get_image_header(i), (uint32_t)slot);
		if (inHeader) {
			gHiddenImageFakePtrs[slot] = inHeader;
			arr[i].imageFilePath = inHeader;
			continue;
		}

		// Could not patch the header (unexpected layout / page not writable).
		// Fall back to a unique fake path; the inconsistency stays, but at least
		// the name is hidden and nothing was left half-modified.
		const char *fake = hidejb_fake_path_for_slot((uint32_t)slot);
		if (fake) arr[i].imageFilePath = fake;
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
	return orig_dlopen(path, mode);
}

static int (*orig_dladdr)(const void *, Dl_info *);
static int hidejb_dladdr(const void *addr, Dl_info *info)
{
	int r = orig_dladdr(addr, info);
	if (gEnabled && r != 0 && info && info->dli_fname) {
		if (hidejb_rules_path_has_marker(info->dli_fname)) {
			// Keep the call SUCCEEDING. Returning 0 for an address that is inside
			// a mapped image is itself an inconsistency an anti-tamper SDK can
			// notice; instead just hand back the same benign name everything
			// else reports.
			const char *fake = NULL;
			if (info->dli_fbase) {
				uint32_t n = _dyld_image_count();
				for (uint32_t i = 0; i < n; i++) {
					if (_dyld_get_image_header(i) == (const struct mach_header *)info->dli_fbase) {
						int slot = hidejb_hidden_slot_for_index(i);
						if (slot >= 0) fake = gHiddenImageFakePtrs[slot];
						break;
					}
				}
			}
			info->dli_fname = fake ? fake : "/usr/lib/libsystem.dylib";
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

#pragma mark - runtime hook-group switch (diagnostics)

// Create  /var/jb/basebin/hidejb_off.txt  (via Filza) containing any of these
// letters, then do a userspace reboot, to disable that hook group for testing:
//   f = all file hooks (equivalent to 1+2+3+4+5)
//   d = dyld image hiding — ON by default now (it also rewrites the image's own
//       LC_ID_DYLIB so nothing contradicts). Write `d` to turn it OFF.
//   l = dlopen/dladdr/dlsym
//   c = csops
//   s = sysctlbyname
//   u = URL scheme swizzle
//   --- finer split of the file hooks, for pinpointing which one breaks an app:
//   1 = stat / lstat / fstatat / access / faccessat   (path queries)
//   2 = opendir / readdir   — ALREADY OFF BY DEFAULT; write `E` to re-enable.
//   3 = realpath / readlink / readlinkat              (path resolution)
//   4 = fopen
//   5 = statfs
// This exists so a crashing app can be bisected on-device without rebuilding.
#define HIDE_OFF_FILE     (1u << 0)
#define HIDE_OFF_DYLD     (1u << 1)
#define HIDE_OFF_DL       (1u << 2)
#define HIDE_OFF_CSOPS    (1u << 3)
#define HIDE_OFF_SYSCTL   (1u << 4)
#define HIDE_OFF_URL      (1u << 5)
#define HIDE_OFF_F_QUERY  (1u << 6)
#define HIDE_OFF_F_DIR    (1u << 7)
#define HIDE_OFF_F_PATH   (1u << 8)
#define HIDE_OFF_F_FOPEN  (1u << 9)
#define HIDE_OFF_F_STATFS (1u << 10)

// Only group 2 (opendir/readdir) is OFF BY DEFAULT: hiding entries / returning
// NULL for whole directories made a large app's own directory bookkeeping go out
// of sync (QQ burned 31s+ of CPU and got killed by the launch watchdog).
// `d` (dyld image hiding) is ON again now that it rewrites the image's own
// LC_ID_DYLIB, so the image list and the binary agree instead of contradicting
// each other. Write `2` to disable group 2 explicitly, `E` to re-enable it, and
// `d` to switch image hiding back off.
static uint32_t gDisabled = HIDE_OFF_F_DIR;

static void hidejb_load_disable_switch(const char *jbroot)
{
	if (!jbroot || !jbroot[0]) return;

	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/basebin/hidejb_off.txt", jbroot);

	int fd = open(path, O_RDONLY);
	if (fd < 0) return;

	char buf[128] = {0};
	ssize_t n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0) return;

	for (ssize_t i = 0; i < n; i++) {
		switch (buf[i]) {
			case 'f': gDisabled |= HIDE_OFF_FILE;   break;
			case 'd': gDisabled |= HIDE_OFF_DYLD;   break;
			case 'l': gDisabled |= HIDE_OFF_DL;     break;
			case 'c': gDisabled |= HIDE_OFF_CSOPS;  break;
			case 's': gDisabled |= HIDE_OFF_SYSCTL; break;
			case 'u': gDisabled |= HIDE_OFF_URL;      break;
			case '1': gDisabled |= HIDE_OFF_F_QUERY;  break;
			case '2': gDisabled |= HIDE_OFF_F_DIR;    break;
			case '3': gDisabled |= HIDE_OFF_F_PATH;   break;
			case '4': gDisabled |= HIDE_OFF_F_FOPEN;  break;
			case '5': gDisabled |= HIDE_OFF_F_STATFS; break;
			case 'D': gDisabled &= ~HIDE_OFF_DYLD;    break; // re-enable image hiding
			case 'E': gDisabled &= ~HIDE_OFF_F_DIR;   break; // re-enable opendir/readdir filtering
		}
	}
}

#pragma mark - init

void hidejb_init(const char *jbroot)
{
	if (!hidejb_enabled()) return;

	gEnabled = true;

	hidejb_rules_set_jbroot(jbroot);
	hidejb_rules_set_self_bundle_id();

	hidejb_load_disable_switch(jbroot);

	if (!(gDisabled & HIDE_OFF_DYLD)) {
		uint32_t n = _dyld_image_count();
		for (uint32_t i = 0; i < n; i++) {
			const char *name = _dyld_get_image_name(i);
			if (!name) continue;
			if (strstr(name, "systemhook") || strstr(name, "libellekit") || strstr(name, "CydiaSubstrate")) {
				hidejb_register_hidden_index(i);
			}
		}

		// Rewrite the paths inside dyld's own image array as well, so detectors
		// that bypass _dyld_get_image_name still cannot see the injected dylibs.
		hidejb_patch_all_image_infos();
	}

	// ★ Instruction-replace the shared-cache functions (MSHookFunction) so that
	// ALL callers — including Foundation/UIKit internals — go through our hooks.
	// litehook_rebind_symbol only rewrites the app's own GOT entries, so it misses
	// the internal stat/access/open calls that NSFileManager & friends make.
	if (!(gDisabled & (HIDE_OFF_FILE | HIDE_OFF_F_QUERY))) {
	MSHookFunction((void *)stat,         (void *)hidejb_stat,         (void **)&orig_stat);
	MSHookFunction((void *)lstat,        (void *)hidejb_lstat,        (void **)&orig_lstat);
	MSHookFunction((void *)fstatat,      (void *)hidejb_fstatat,      (void **)&orig_fstatat);
	MSHookFunction((void *)access,       (void *)hidejb_access,       (void **)&orig_access);
	MSHookFunction((void *)faccessat,    (void *)hidejb_faccessat,    (void **)&orig_faccessat);
	}
	if (!(gDisabled & (HIDE_OFF_FILE | HIDE_OFF_F_DIR))) {
	MSHookFunction((void *)opendir,      (void *)hidejb_opendir,      (void **)&orig_opendir);
	MSHookFunction((void *)readdir,      (void *)hidejb_readdir,      (void **)&orig_readdir);
	}
	if (!(gDisabled & (HIDE_OFF_FILE | HIDE_OFF_F_PATH))) {
	MSHookFunction((void *)realpath,     (void *)hidejb_realpath,     (void **)&orig_realpath);
	MSHookFunction((void *)readlink,     (void *)hidejb_readlink,     (void **)&orig_readlink);
	MSHookFunction((void *)readlinkat,   (void *)hidejb_readlinkat,   (void **)&orig_readlinkat);
	}
	if (!(gDisabled & (HIDE_OFF_FILE | HIDE_OFF_F_FOPEN))) {
	MSHookFunction((void *)fopen,        (void *)hidejb_fopen,        (void **)&orig_fopen);
	}
	if (!(gDisabled & (HIDE_OFF_FILE | HIDE_OFF_F_STATFS))) {
	MSHookFunction((void *)statfs,       (void *)hidejb_statfs,       (void **)&orig_statfs);
	}
	if (!(gDisabled & HIDE_OFF_SYSCTL)) {
	MSHookFunction((void *)sysctlbyname, (void *)hidejb_sysctlbyname, (void **)&orig_sysctlbyname);
	}

	if (!(gDisabled & HIDE_OFF_DYLD)) {
	MSHookFunction((void *)_dyld_get_image_name,        (void *)hidejb_dyld_get_image_name,        (void **)&orig_dyld_get_image_name);
	}
	if (!(gDisabled & HIDE_OFF_DL)) {
	MSHookFunction((void *)dlopen,                      (void *)hidejb_dlopen,                      (void **)&orig_dlopen);
	MSHookFunction((void *)dladdr,                      (void *)hidejb_dladdr,                      (void **)&orig_dladdr);
	MSHookFunction((void *)dlsym,                       (void *)hidejb_dlsym,                       (void **)&orig_dlsym);
	}

#ifndef __arm64e__
	if (!(gDisabled & HIDE_OFF_CSOPS)) {
	// csops: keep the inline-syscall style (matches systemhook/main.c).
	litehook_hook_function((void *)csops,           (void *)hidejb_csops);
	litehook_hook_function((void *)csops_audittoken, (void *)hidejb_csops_audittoken);
	}
#endif

	if (!(gDisabled & HIDE_OFF_URL)) {
	hidejb_swizzle_url_schemes();
	}
}
