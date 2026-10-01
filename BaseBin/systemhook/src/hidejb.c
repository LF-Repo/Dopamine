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
//      instead of the normal full-injection path. hidejb hooks the libc
//      filesystem functions so that, *from this process's point of view*,
//      /var/jb and the real jailbreak root simply do not exist, and the
//      fakelib bind mount over /usr/lib is reported as part of the root fs.
//
//   3. DOPAMINE_APP_HIDE stays in environ, so children spawned by the app
//      (WebKit helpers, extensions, ...) re-enter hide mode as well.
//
// What this deliberately does NOT do (kept for a follow-up):
//   - hide the hide-dylib from dyld_image_count (the image path is already the
//     clean "/usr/lib/systemhook.dylib", so no /var/jb path leaks there),
//   - filter getfsstat() mount table entries (only statfs is hooked),
//   - defeat raw syscall(SYS_open/...) detections (needs a kernel patch).
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

static bool gEnabled = false;
static char gJbRootReal[PATH_MAX] = {0};

bool hidejb_enabled(void)
{
	return getenv("DOPAMINE_APP_HIDE") != NULL;
}

// True when `path` points at (or anywhere inside) the jailbreak root.
// Only absolute paths are considered: a sandboxed app's relative paths resolve
// against its own container, so they can never reach /var/jb by accident.
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

static int (*orig_sysctlbyname)(const char *, void *, size_t *, const void *, size_t);
static int hidejb_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, const void *newp, size_t newlen)
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

	// ★ Capture the original implementations BEFORE rebinding the symbols.
	// litehook_rebind_symbol only rewrites the lazy/non-lazy symbol pointers
	// (fishhook style); it leaves the original shared-cache code intact, so the
	// saved pointers below still point at the real functions.
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

	// Rebind (intercept) the app's calls to these libc functions. This only
	// affects symbol lookups in loaded images; it does NOT patch the shared
	// cache, so libc's own internal calls are untouched (no re-entrancy).
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
}
