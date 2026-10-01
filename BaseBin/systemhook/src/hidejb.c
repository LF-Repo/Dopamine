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
//                           (port of DOEnvironmentManager's library-audit rules),
//   - readdir:              filter jailbreak entries out of directory listings,
//   - dyld image enumeration/dlopen/dladdr: hide the injected systemhook.dylib,
//   - csops:                clear CS_DEBUGGED / set CS_VALID (code signature),
//   - sysctl:               hide amfi developer-mode flag,
//   - LSApplicationWorkspace canOpenURL: hide jailbreak URL schemes (per-app).
//

#include "hidejb.h"

#include <litehook.h>
#include <substrate.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <limits.h>
#include <dirent.h>
#include <arpa/inet.h>
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
static char gJbRootReal[PATH_MAX] = {0};
static char gSelfBundleID[256] = {0};

// Indices of injected jailbreak dylibs (systemhook, libellekit, ...) in the
// dyld image list. These are hidden from _dyld_image_count/_dyld_get_image_name.
static uint32_t gHiddenImageIndices[8] = {0};
static uint32_t gHiddenImageCount = 0;

bool hidejb_enabled(void)
{
	return getenv("DOPAMINE_APP_HIDE") != NULL;
}

static bool str_in_list(const char *s, const char *const *list)
{
	if (!s || !list) return false;
	for (; *list; list++) {
		if (strcmp(s, *list) == 0) return true;
	}
	return false;
}

static bool str_has_any_prefix(const char *s, const char *const *prefixes)
{
	if (!s || !prefixes) return false;
	for (; *prefixes; prefixes++) {
		if (strncmp(s, *prefixes, strlen(*prefixes)) == 0) return true;
	}
	return false;
}

static bool is_self_bundle_name(const char *name)
{
	if (!gSelfBundleID[0] || !name) return false;
	if (strcmp(name, gSelfBundleID) == 0) return true;
	size_t n = strlen(gSelfBundleID);
	return strncmp(name, gSelfBundleID, n) == 0 && name[n] == '.';
}

#pragma mark - library-audit rule table (ported from DOEnvironmentManager)

typedef struct {
	const char *dir;
	bool default_blacklist;
	const char *const *whitelist;
	const char *const *blacklist;
	const char *const *whitelist_prefix; // simplified whitelistRegex (prefixes)
} hide_dir_rule_t;

static const char *const kApplePrefixes[]        = { "com.apple.", "systemgroup.com.apple.", NULL };
static const char *const kAppleOnlyPrefixes[]    = { "com.apple.", NULL };
static const char *const kCachesPrefixes[]       = { "com.apple.", "TelephonyUI-", "FamilyMarquee", NULL };

static const char *const kLibWhitelist[] = {
	"Accessibility", "CoreBrightness", "Keyboard", "Preferences", "Voicemail",
	"Accounts", "CoreDuet", "KeyboardServices", "PrivacyAccounting", "WatchConnectivity",
	"AddressBook", "CoreFollowUp", "LASD", "Recents", "Weather",
	"AggregateDictionary", "CountryModeling", "Reminders", "WebClips", "CrashReporter",
	"Logs", "ReplayKit", "WebKit", "Application Support", "MediaRemote",
	"Safari", "Caches", "SplashBoard", "MobileInstallation", "SoftwareUpdate",
	"BulletinBoard", "MobileContainerManager", "TCC", "Settings", "Cookies",
	"Passes", "UserNotifications", "ApplicationSync", "DataDeliveryServices", "MediaStream",
	"SafeHarbor", "Wallet", "Maps", "Phone", NULL
};
static const char *const kLibBlacklist[] = { "Sileo", "Filza", "Flex3", "SBSettings", "iCleaner", NULL };

static const char *const kPrefsWhitelist[] = {
	".GlobalPreferences.plist", ".GlobalPreferences_m.plist", "bluetoothaudiod.plist",
	"NetworkInterfaces.plist", "OSThermalStatus.plist", "preferences.plist",
	"osanalyticshelper.plist", "UserEventAgent.plist", "wifid.plist", "dprivacyd.plist",
	"silhouette.plist", "nfcd.plist", "ptpcamerad.plist", "mobile_storage_proxy.plist", NULL
};
static const char *const kPrefsBlacklist[] = {
	"com.roothide.manager.plist", "com.opa334.Dopamine.roothide.plist",
	"com.opa334.Dopamine.plist", "com.tigisoftware.Filza.plist", "com.xina.jailbreak.plist",
	"org.coolstar.SileoStore.plist", "ru.domo.cocoatop64.plist", "ws.hbang.Terminal.plist",
	"xyz.willy.Zebra.plist", "com.apple.terminal.plist", NULL
};

static const char *const kAppSupportBlacklist[] = { "xyz.willy.Zebra", NULL };

static const char *const kContainersBlacklist[] = {
	"xyz.willy.Zebra", "com.tigisoftware.Filza", "org.coolstar.SileoStore", "com.apple.Terminal", NULL
};

static const char *const kPublicInfoBlacklist[] = { "Flex3Patches.plist", NULL };

static const char *const kSnapshotsBlacklist[] = {
	"com.roothide.manager", "com.opa334.Dopamine.roothide", "com.opa334.Dopamine",
	"com.tigisoftware.Filza", "org.coolstar.SileoStore", "ru.domo.cocoatop64",
	"ws.hbang.Terminal", "xyz.willy.Zebra", "com.apple.Terminal", NULL
};

static const char *const kCachesWhitelist[] = {
	"CloudKit", "GameKit", "GeoServices", "FamilyCircle", "PassKit",
	"VoiceServices", "VoiceTrigger", "Backup", "ssu", NULL
};
static const char *const kCachesBlacklist[] = {
	"com.opa334.Dopamine", "com.tigisoftware.Filza", "org.coolstar.SileoStore",
	"ws.hbang.Terminal", "xyz.willy.Zebra", "Cephei", "com.apple.Terminal",
	"GDFileManagerCache.sqlite", "GDFileManagerCache.sqlite-shm", "GDFileManagerCache.sqlite-wal",
	"ImageTables", "SentryCrash", "io.sentry", "com.hackemist.SDImageCache", NULL
};

static const char *const kSavedStateBlacklist[] = {
	"com.opa334.Dopamine.savedState", "com.tigisoftware.Filza.savedState",
	"org.coolstar.SileoStore.savedState", "ws.hbang.Terminal.savedState",
	"xyz.willy.Zebra.savedState", "ru.domo.cocoatop64.savedState", "com.apple.Terminal.savedState", NULL
};

static const char *const kWebKitWhitelist[] = { "Databases", "LocalStorage", NULL };
static const char *const kWebKitBlacklist[] = { "xyz.willy.Zebra", NULL };

static const char *const kCookiesWhitelist[] = { "Cookies.binarycookies", NULL };
static const char *const kCookiesBlacklist[] = { "com.johncoates.Flex.binarycookies", NULL };

static const char *const kHTTPStoragesBlacklist[] = {
	"com.opa334.Dopamine", "com.tigisoftware.Filza", "org.coolstar.SileoStore",
	"ws.hbang.Terminal", "xyz.willy.Zebra", NULL
};

static const char *const kDocumentsBlacklist[] = { "DumpDecrypter", "Dumplpa", NULL };

static const char *const kMobileBlacklist[] = {
	".DO-NOT-DELETE-Cowabunga", ".Derootifier", "Helix", ".ssh", ".cache", NULL
};

static const hide_dir_rule_t gHideRules[] = {
	{ "/var/mobile/Library", false, kLibWhitelist, kLibBlacklist, NULL },
	{ "/var/mobile/Library/Preferences", true, kPrefsWhitelist, kPrefsBlacklist, kApplePrefixes },
	{ "/var/mobile/Library/Application Support", false, NULL, kAppSupportBlacklist, NULL },
	{ "/var/mobile/Library/Application Support/Containers", true, NULL, kContainersBlacklist, NULL },
	{ "/var/mobile/Library/UserConfigurationProfiles/PublicInfo", false, NULL, kPublicInfoBlacklist, NULL },
	{ "/var/mobile/Library/SplashBoard/Snapshots", true, NULL, kSnapshotsBlacklist, kAppleOnlyPrefixes },
	{ "/var/mobile/Library/Caches", true, kCachesWhitelist, kCachesBlacklist, kCachesPrefixes },
	{ "/var/mobile/Library/Saved Application State", true, NULL, kSavedStateBlacklist, kAppleOnlyPrefixes },
	{ "/var/mobile/Library/WebKit", false, kWebKitWhitelist, kWebKitBlacklist, kAppleOnlyPrefixes },
	{ "/var/mobile/Library/Cookies", true, kCookiesWhitelist, kCookiesBlacklist, kAppleOnlyPrefixes },
	{ "/var/mobile/Library/HTTPStorages", true, NULL, kHTTPStoragesBlacklist, kAppleOnlyPrefixes },
	{ "/var/mobile/Documents", false, NULL, kDocumentsBlacklist, NULL },
	{ "/var/mobile", false, NULL, kMobileBlacklist, NULL },
};

// True when `path` (a child of one of the rule dirs) should be hidden per the
// DOEnvironmentManager library-audit rules.
// noinline: this is called from variadic hooks (hidejb_open/openat); inlining it
// there breaks register allocation (the variadic args leak into strncmp).
static bool __attribute__((noinline)) path_is_blacklisted_by_rules(const char *path)
{
	if (!path || path[0] != '/') return false;

	for (size_t r = 0; r < sizeof(gHideRules)/sizeof(gHideRules[0]); r++) {
		const hide_dir_rule_t *rule = &gHideRules[r];
		size_t dlen = strlen(rule->dir);
		if (strncmp(path, rule->dir, dlen) != 0 || path[dlen] != '/') continue;

		const char *name = path + dlen + 1;
		const char *slash = strchr(name, '/');
		char namebuf[256];
		size_t nlen = slash ? (size_t)(slash - name) : strlen(name);
		if (nlen == 0 || nlen >= sizeof(namebuf)) continue;
		memcpy(namebuf, name, nlen);
		namebuf[nlen] = '\0';

		// never hide "." / ".." (readdir always yields them)
		if (nlen == 1 && namebuf[0] == '.') continue;
		if (nlen == 2 && namebuf[0] == '.' && namebuf[1] == '.') continue;

		if (str_in_list(namebuf, rule->blacklist)) return true;          // explicit blacklist
		if (str_has_any_prefix(namebuf, rule->whitelist_prefix)) continue; // regex whitelist
		if (str_in_list(namebuf, rule->whitelist)) continue;             // exact whitelist
		if (rule->default_blacklist) {
			if (is_self_bundle_name(namebuf)) continue; // never hide our own traces
			return true; // hide anything not whitelisted
		}
	}

	return false;
}

// Substrings that mark a path as jailbreak-related (dylib names, markers).
static const char *gJailbreakPathMarkers[] = {
	"systemhook",
	"libjailbreak",
	"TweakLoader",
	"ellekit",
	"libellekit",
	"libsubstrate",
	"CydiaSubstrate",
	"forkfix",
	".installed_dopamine",
};

// True when `path` points at (or anywhere inside) the jailbreak root, or names
// a known jailbreak file/preference. Only absolute paths are considered.
// noinline: see path_is_blacklisted_by_rules (variadic-hook register bug).
static bool __attribute__((noinline)) path_is_jailbreak(const char *path)
{
	if (!path || path[0] != '/') return false;

	if (strcmp(path, "/var/jb") == 0) return true;
	if (strncmp(path, "/var/jb/", 8) == 0) return true;

	if (gJbRootReal[0]) {
		size_t n = strlen(gJbRootReal);
		if (strncmp(path, gJbRootReal, n) == 0 && (path[n] == '/' || path[n] == '\0')) return true;
	}

	const char *p = path;
	while (*p) {
		const char *slash = strchr(p, '/');
		size_t len = slash ? (size_t)(slash - p) : strlen(p);
		if (len == 9 && strncmp(p, "procursus", 9) == 0) return true;
		if (!slash) break;
		p = slash + 1;
	}

	for (size_t i = 0; i < sizeof(gJailbreakPathMarkers)/sizeof(gJailbreakPathMarkers[0]); i++) {
		if (strstr(path, gJailbreakPathMarkers[i])) return true;
	}

	if (path_is_blacklisted_by_rules(path)) return true;

	return false;
}

#pragma mark - open / openat

static int (*orig_open)(const char *, int, ...);
// NOTE: declared non-variadic on purpose. open() is variadic, but on arm64 the
// optional `mode` is always passed in x2, so a fixed 3-arg signature is ABI-
// identical. Keeping it non-variadic avoids the va_list save area, which was
// causing the compiler to mis-allocate registers inside the inlined path check
// (the "strncmp(path, flags, mode)" crash).
static int hidejb_open(const char *path, int flags, int mode)
{
	if (gEnabled && path_is_jailbreak(path)) { errno = ENOENT; return -1; }
	return orig_open(path, flags, mode);
}

static int (*orig_openat)(int, const char *, int, ...);
static int hidejb_openat(int fd, const char *path, int flags, int mode)
{
	if (gEnabled && path_is_jailbreak(path)) { errno = ENOENT; return -1; }
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

#pragma mark - opendir / readdir (filter directory listings too)

static DIR *(*orig_opendir)(const char *);
static DIR *hidejb_opendir(const char *dirname)
{
	if (gEnabled && path_is_jailbreak(dirname)) { errno = ENOENT; return NULL; }
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
		if (!path_is_jailbreak(full)) return e;
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

#pragma mark - dyld image enumeration (hide the injected systemhook.dylib)

static uint32_t (*orig_dyld_image_count)(void);
static const char *(*orig_dyld_get_image_name)(uint32_t);
static const struct mach_header *(*orig_dyld_get_image_header)(uint32_t);
static intptr_t (*orig_dyld_get_image_vmaddr_slide)(uint32_t);

static bool hidejb_is_hidden_image_index(uint32_t i)
{
	for (uint32_t k = 0; k < gHiddenImageCount; k++) {
		if (gHiddenImageIndices[k] == i) return true;
	}
	return false;
}

static uint32_t hidejb_dyld_image_count(void)
{
	uint32_t n = orig_dyld_image_count();
	if (gEnabled && gHiddenImageCount) {
		uint32_t hidden = 0;
		for (uint32_t i = 0; i < n; i++) {
			if (hidejb_is_hidden_image_index(i)) hidden++;
		}
		return n - hidden;
	}
	return n;
}

// Map a "virtual" (visible) image index back to its real index, skipping hidden images.
static uint32_t hidejb_remap_image_index(uint32_t virtualIndex)
{
	uint32_t realIndex = 0;
	while (1) {
		if (!hidejb_is_hidden_image_index(realIndex)) {
			if (virtualIndex == 0) return realIndex;
			virtualIndex--;
		}
		realIndex++;
	}
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

#pragma mark - task_for_pid (hide "process task port was obtained")

static kern_return_t (*orig_task_for_pid)(mach_port_name_t, int, mach_port_name_t *);
static kern_return_t hidejb_task_for_pid(mach_port_name_t target, int pid, mach_port_name_t *t)
{
	if (gEnabled && pid == getpid()) {
		if (t) *t = MACH_PORT_NULL;
		return KERN_FAILURE;
	}
	return orig_task_for_pid(target, pid, t);
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

// Read our own bundle id via csops(CS_OPS_IDENTITY) so "default-blacklist"
// rules never hide the hidden app's own preferences/caches.
static void get_self_bundle_id(void)
{
	struct { uint32_t magic; uint32_t length; } header = {0};
	if (csops(getpid(), CS_OPS_IDENTITY, &header, sizeof(header)) != 0 && errno != ERANGE) return;
	uint32_t len = ntohl(header.length);
	if (len == 0 || len > 4096) return;
	char *buf = malloc(len);
	if (!buf) return;
	if (csops(getpid(), CS_OPS_IDENTITY, buf, len) == 0) {
		strlcpy(gSelfBundleID, buf + sizeof(header), sizeof(gSelfBundleID));
	}
	free(buf);
}

void hidejb_init(const char *jbroot)
{
	if (!hidejb_enabled()) return;

	gEnabled = true;

	if (jbroot && jbroot[0]) {
		char resolved[PATH_MAX] = {0};
		if (realpath(jbroot, resolved)) {
			strlcpy(gJbRootReal, resolved, sizeof(gJbRootReal));
		} else {
			strlcpy(gJbRootReal, jbroot, sizeof(gJbRootReal));
		}
	}

	get_self_bundle_id();

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
	MSHookFunction((void *)open,         (void *)hidejb_open,         (void **)&orig_open);
	MSHookFunction((void *)openat,       (void *)hidejb_openat,       (void **)&orig_openat);
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

	MSHookFunction((void *)_dyld_image_count,           (void *)hidejb_dyld_image_count,           (void **)&orig_dyld_image_count);
	MSHookFunction((void *)_dyld_get_image_name,        (void *)hidejb_dyld_get_image_name,        (void **)&orig_dyld_get_image_name);
	MSHookFunction((void *)_dyld_get_image_header,      (void *)hidejb_dyld_get_image_header,      (void **)&orig_dyld_get_image_header);
	MSHookFunction((void *)_dyld_get_image_vmaddr_slide, (void *)hidejb_dyld_get_image_vmaddr_slide, (void **)&orig_dyld_get_image_vmaddr_slide);
	MSHookFunction((void *)dlopen,                      (void *)hidejb_dlopen,                      (void **)&orig_dlopen);
	MSHookFunction((void *)dladdr,                      (void *)hidejb_dladdr,                      (void **)&orig_dladdr);
	MSHookFunction((void *)task_for_pid,                (void *)hidejb_task_for_pid,                (void **)&orig_task_for_pid);

#ifndef __arm64e__
	// csops: keep the inline-syscall style (matches systemhook/main.c).
	litehook_hook_function((void *)csops,           (void *)hidejb_csops);
	litehook_hook_function((void *)csops_audittoken, (void *)hidejb_csops_audittoken);
#endif

	hidejb_swizzle_url_schemes();
}
