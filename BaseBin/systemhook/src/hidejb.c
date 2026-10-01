// hidejb.c
//
// Per-process jailbreak hiding for Dopamine (rootless).
//
// This is the replacement for the old "app_hide_monitor" approach, which used to
// *globally* hide the jailbreak (unmount fakelib, delete the /var/jb symlink,
// move files out of /var/mobile/Library into a quarantine dir) whenever a
// "hidden" app was running. That approach was destructive, racy (2s poll loop)
// and easily detectable, and it broke every other jailbreak process at once.
//
// The approach below mirrors what RootHide does, but is scoped per-app and keeps
// the rootless /var/jb layout intact:
//
//   1. launchdhook spawns a "hidden" app with
//      DYLD_INSERT_LIBRARIES=/usr/lib/systemhook.dylib (the same clean fakelib
//      path systemhook is always injected from) plus DOPAMINE_APP_HIDE=1.
//
//   2. systemhook's constructor sees DOPAMINE_APP_HIDE=1 and calls hidejb_init()
//      instead of the normal full-injection path. hidejb then, *from this
//      process's point of view*:
//        - hides /var/jb + the real jailbreak root from file syscalls,
//        - hides jailbreak files/prefs (systemhook.dylib, Dopamine prefs, ...),
//        - hides the injected systemhook.dylib from dyld image enumeration,
//          dlopen/dladdr,
//        - hides the amfi developer-mode flag and the CS_DEBUGGED csflag.
//
//   3. DOPAMINE_APP_HIDE stays in environ, so children spawned by the app
//      (WebKit helpers, extensions, ...) re-enter hide mode as well.
//
// What this deliberately does NOT do (kept for a follow-up):
//   - defeat raw syscall(SYS_open/.../SYS_csops) detections (needs a kernel patch),
//   - filter getfsstat() mount table entries (only statfs is hooked),
//   - hide URL schemes per-app (still done globally via Info.plist rewriting).
//

#include "hidejb.h"

#include <litehook.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <limits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/message.h>
#include <libjailbreak/codesign.h>

// csops syscall numbers (see common/private.h)
#ifndef SYS_csops
#define SYS_csops 0xA9
#endif
#ifndef SYS_csops_audittoken
#define SYS_csops_audittoken 0xAA
#endif

static bool gEnabled = false;
static char gJbRootReal[PATH_MAX] = {0};

// Index of systemhook.dylib in the dyld image list (hidden from enumeration).
static uint32_t gHiddenImageIndex = UINT32_MAX;

bool hidejb_enabled(void)
{
	return getenv("DOPAMINE_APP_HIDE") != NULL;
}

// Substrings that mark a path as jailbreak-related. File syscalls for any path
// containing one of these are made to fail with ENOENT.
static const char *gJailbreakPathMarkers[] = {
	"systemhook",
	"libjailbreak",
	"TweakLoader",
	"ellekit",
	"libellekit",
	"libsubstrate",
	"CydiaSubstrate",
	"forkfix",
	"com.opa334.Dopamine",
	".Dopamine",
	"DopamineAppHide",
	".installed_dopamine",
	"DopamineCrashReporterDisabled",
};

// True when `path` points at (or anywhere inside) the jailbreak root, or names
// a known jailbreak file/preference. Only absolute paths are considered.
static bool path_is_jailbreak(const char *path)
{
	if (!path || path[0] != '/') return false;

	// 1) canonical rootless symlink
	if (strcmp(path, "/var/jb") == 0) return true;
	if (strncmp(path, "/var/jb/", 8) == 0) return true;

	// 2) resolved jbroot (e.g. /private/preboot/<boot-uuid>/procursus)
	if (gJbRootReal[0]) {
		size_t n = strlen(gJbRootReal);
		if (strncmp(path, gJbRootReal, n) == 0 && (path[n] == '/' || path[n] == '\0')) return true;
	}

	// 3) "procursus" path component (rootless bootstrap dir name), so the real
	//    preboot path is hidden even if resolution above failed.
	const char *p = path;
	while (*p) {
		const char *slash = strchr(p, '/');
		size_t len = slash ? (size_t)(slash - p) : strlen(p);
		if (len == 9 && strncmp(p, "procursus", 9) == 0) return true;
		if (!slash) break;
		p = slash + 1;
	}

	// 4) known jailbreak files / prefs / dylib names anywhere in the path.
	for (size_t i = 0; i < sizeof(gJailbreakPathMarkers)/sizeof(gJailbreakPathMarkers[0]); i++) {
		if (strstr(path, gJailbreakPathMarkers[i])) return true;
	}

	return false;
}

#pragma mark - open / openat

static int (*orig_open)(const char *, int, ...);
static int hidejb_open(const char *path, int flags, ...)
{
	if (gEnabled && path_is_jailbreak(path)) { errno = ENOENT; return -1; }
	va_list ap;
	va_start(ap, flags);
	int mode = va_arg(ap, int);
	va_end(ap);
	return orig_open(path, flags, mode);
}

static int (*orig_openat)(int, const char *, int, ...);
static int hidejb_openat(int fd, const char *path, int flags, ...)
{
	if (gEnabled && path_is_jailbreak(path)) { errno = ENOENT; return -1; }
	va_list ap;
	va_start(ap, flags);
	int mode = va_arg(ap, int);
	va_end(ap);
	return orig_openat(fd, path, flags, mode);
}

#pragma mark - stat family

static int (*orig_stat)(const char *, struct stat *);
static int hidejb_stat(const char *path, struct stat *buf)
{
	if (gEnabled && path_is_jailbreak(path)) { errno = ENOENT; return -1; }
	return orig_stat(path, buf);
}

static int (*orig_lstat)(const char *, struct stat *);
static int hidejb_lstat(const char *path, struct stat *buf)
{
	if (gEnabled && path_is_jailbreak(path)) { errno = ENOENT; return -1; }
	return orig_lstat(path, buf);
}

static int (*orig_fstatat)(int, const char *, struct stat *, int);
static int hidejb_fstatat(int fd, const char *path, struct stat *buf, int flag)
{
	if (gEnabled && path_is_jailbreak(path)) { errno = ENOENT; return -1; }
	return orig_fstatat(fd, path, buf, flag);
}

#pragma mark - access family

static int (*orig_access)(const char *, int);
static int hidejb_access(const char *path, int mode)
{
	if (gEnabled && path_is_jailbreak(path)) { errno = ENOENT; return -1; }
	return orig_access(path, mode);
}

static int (*orig_faccessat)(int, const char *, int, int);
static int hidejb_faccessat(int fd, const char *path, int mode, int flag)
{
	if (gEnabled && path_is_jailbreak(path)) { errno = ENOENT; return -1; }
	return orig_faccessat(fd, path, mode, flag);
}

#pragma mark - realpath / readlink

static char *(*orig_realpath)(const char *restrict, char *restrict);
static char *hidejb_realpath(const char *restrict path, char *restrict resolved)
{
	if (gEnabled && path_is_jailbreak(path)) { errno = ENOENT; return NULL; }
	return orig_realpath(path, resolved);
}

static ssize_t (*orig_readlink)(const char *, char *, size_t);
static ssize_t hidejb_readlink(const char *path, char *buf, size_t bufsize)
{
	if (gEnabled && path_is_jailbreak(path)) { errno = ENOENT; return -1; }
	return orig_readlink(path, buf, bufsize);
}

static ssize_t (*orig_readlinkat)(int, const char *, char *, size_t);
static ssize_t hidejb_readlinkat(int fd, const char *path, char *buf, size_t bufsize)
{
	if (gEnabled && path_is_jailbreak(path)) { errno = ENOENT; return -1; }
	return orig_readlinkat(fd, path, buf, bufsize);
}

#pragma mark - opendir

static DIR *(*orig_opendir)(const char *);
static DIR *hidejb_opendir(const char *dirname)
{
	if (gEnabled && path_is_jailbreak(dirname)) { errno = ENOENT; return NULL; }
	return orig_opendir(dirname);
}

#pragma mark - statfs (hide the fakelib bind mount over /usr/lib)

static int (*orig_statfs)(const char *, struct statfs *);
static int hidejb_statfs(const char *path, struct statfs *buf)
{
	if (gEnabled && path) {
		// On a stock device /usr/lib sits on the root fs, so statfs("/usr/lib")
		// reports f_mntonname == "/". On a jailbroken device fakelib bind-mounts
		// <jbroot>/basebin/.fakelib over /usr/lib, so f_mntonname == "/usr/lib"
		// — a classic jailbreak tell. Report the root fs instead.
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

#pragma mark - dyld image enumeration (hide the injected systemhook.dylib)

static uint32_t (*orig_dyld_image_count)(void);
static const char *(*orig_dyld_get_image_name)(uint32_t);
static const struct mach_header *(*orig_dyld_get_image_header)(uint32_t);
static intptr_t (*orig_dyld_get_image_vmaddr_slide)(uint32_t);

static uint32_t hidejb_dyld_image_count(void)
{
	uint32_t n = orig_dyld_image_count();
	if (gEnabled && gHiddenImageIndex != UINT32_MAX && gHiddenImageIndex < n) {
		return n - 1;
	}
	return n;
}

static uint32_t hidejb_remap_image_index(uint32_t index)
{
	if (gEnabled && gHiddenImageIndex != UINT32_MAX && index >= gHiddenImageIndex) {
		index++;
	}
	return index;
}

static const char *hidejb_dyld_get_image_name(uint32_t index)
{
	return orig_dyld_get_image_name(hidejb_remap_image_index(index));
}

static const struct mach_header *hidejb_dyld_get_image_header(uint32_t index)
{
	return orig_dyld_get_image_header(hidejb_remap_image_index(index));
}

static intptr_t hidejb_dyld_get_image_vmaddr_slide(uint32_t index)
{
	return orig_dyld_get_image_vmaddr_slide(hidejb_remap_image_index(index));
}

#pragma mark - dlopen / dladdr (hide the injected systemhook.dylib)

static void *(*orig_dlopen)(const char *, int);
static void *hidejb_dlopen(const char *path, int mode)
{
	if (gEnabled && path && strstr(path, "systemhook.dylib")) {
		// Pretend the injected dylib is not loaded (dlopen(..., RTLD_NOLOAD) → NULL).
		return NULL;
	}
	return orig_dlopen(path, mode);
}

static int (*orig_dladdr)(const void *, Dl_info *);
static int hidejb_dladdr(const void *addr, Dl_info *info)
{
	int r = orig_dladdr(addr, info);
	if (gEnabled && r != 0 && info && info->dli_fname && strstr(info->dli_fname, "systemhook.dylib")) {
		return 0; // report "not in any known image"
	}
	return r;
}

#pragma mark - csops (hide the debug/invalid code-signature flags) [arm64]

#ifndef __arm64e__
static int hidejb_csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize)
{
	int rv = syscall(SYS_csops, pid, ops, useraddr, usersize);
	if (rv != 0) return rv;
	if (ops == CS_OPS_STATUS) {
		if (useraddr && usersize == sizeof(uint32_t)) {
			uint32_t *csflag = (uint32_t *)useraddr;
			*csflag |= CS_VALID;
			*csflag &= ~CS_DEBUGGED; // always hide, never re-add
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
			*csflag |= CS_VALID;
			*csflag &= ~CS_DEBUGGED;
		}
	}
	return rv;
}
#endif

#pragma mark - init

void hidejb_init(const char *jbroot)
{
	if (!hidejb_enabled()) return;

	gEnabled = true;

	// Resolve the canonical jbroot so we can hide /private/preboot/<uuid>/procursus
	// in addition to the /var/jb symlink.
	if (jbroot && jbroot[0]) {
		char resolved[PATH_MAX] = {0};
		if (realpath(jbroot, resolved)) {
			strlcpy(gJbRootReal, resolved, sizeof(gJbRootReal));
		} else {
			strlcpy(gJbRootReal, jbroot, sizeof(gJbRootReal));
		}
	}

	// Locate systemhook.dylib in the dyld image list (before we hide it).
	{
		uint32_t n = _dyld_image_count();
		for (uint32_t i = 0; i < n; i++) {
			const char *name = _dyld_get_image_name(i);
			if (name && strstr(name, "systemhook")) {
				gHiddenImageIndex = i;
				break;
			}
		}
	}

	// ★ Capture the original implementations BEFORE rebinding the symbols.
	orig_open         = open;
	orig_openat       = openat;
	orig_stat         = stat;
	orig_lstat        = lstat;
	orig_fstatat      = fstatat;
	orig_access       = access;
	orig_faccessat    = faccessat;
	orig_realpath     = realpath;
	orig_readlink     = readlink;
	orig_readlinkat   = readlinkat;
	orig_opendir      = opendir;
	orig_statfs       = statfs;
	orig_sysctlbyname = sysctlbyname;

	orig_dyld_image_count          = _dyld_image_count;
	orig_dyld_get_image_name       = _dyld_get_image_name;
	orig_dyld_get_image_header     = _dyld_get_image_header;
	orig_dyld_get_image_vmaddr_slide = _dyld_get_image_vmaddr_slide;
	orig_dlopen                    = dlopen;
	orig_dladdr                    = dladdr;

	// Rebind (intercept) the app's calls to these libc/libdyld functions. This
	// only affects symbol lookups in loaded images; it does NOT patch the shared
	// cache, so libc/libdyld's own internal calls are untouched (no re-entrancy).
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, (void *)open,         (void *)hidejb_open, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, (void *)openat,       (void *)hidejb_openat, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, (void *)stat,         (void *)hidejb_stat, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, (void *)lstat,        (void *)hidejb_lstat, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, (void *)fstatat,      (void *)hidejb_fstatat, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, (void *)access,       (void *)hidejb_access, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, (void *)faccessat,    (void *)hidejb_faccessat, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, (void *)realpath,     (void *)hidejb_realpath, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, (void *)readlink,     (void *)hidejb_readlink, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, (void *)readlinkat,   (void *)hidejb_readlinkat, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, (void *)opendir,      (void *)hidejb_opendir, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, (void *)statfs,       (void *)hidejb_statfs, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, (void *)sysctlbyname, (void *)hidejb_sysctlbyname, NULL);

	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, (void *)_dyld_image_count,          (void *)hidejb_dyld_image_count, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, (void *)_dyld_get_image_name,       (void *)hidejb_dyld_get_image_name, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, (void *)_dyld_get_image_header,     (void *)hidejb_dyld_get_image_header, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, (void *)_dyld_get_image_vmaddr_slide, (void *)hidejb_dyld_get_image_vmaddr_slide, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, (void *)dlopen,                     (void *)hidejb_dlopen, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, (void *)dladdr,                     (void *)hidejb_dladdr, NULL);

	// csops: use instruction replacement (matching systemhook/main.c) so the
	// "original" is reached via an inline syscall, covering direct csops() calls.
#ifndef __arm64e__
	litehook_hook_function((void *)csops,           (void *)hidejb_csops);
	litehook_hook_function((void *)csops_audittoken, (void *)hidejb_csops_audittoken);
#endif
}
