// hidejb_rules.c
//
// The jailbreak path-matching rules for the per-app hide, kept in a SEPARATE
// compilation unit from hidejb.c.
//
// Rationale: Clang -Os has a register-allocation bug when the complex string
// matching below is inlined into the variadic/fixed-arg hook functions in
// hidejb.c — it ends up calling strncmp with the hook's `flags`/`mode` arguments
// instead of the string arguments, crashing. A separate translation unit makes
// inlining impossible (no LTO is used), so the bug cannot occur.
//

#include "hidejb_rules.h"

#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <mach/message.h>
#include <libjailbreak/codesign.h>

// The whole path-matching module is compiled unoptimized: Clang -Os miscompiles
// this string-matching code (register-allocation bug) regardless of inlining.
#pragma clang optimize off

static char gJbRootReal[PATH_MAX] = {0};
static char gSelfBundleID[256] = {0};

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

static const char *const kApplePrefixes[]     = { "com.apple.", "systemgroup.com.apple.", NULL };
static const char *const kAppleOnlyPrefixes[] = { "com.apple.", NULL };
static const char *const kCachesPrefixes[]    = { "com.apple.", "TelephonyUI-", "FamilyMarquee", NULL };

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

// Decides whether one rule hides a single path component sitting directly under
// rule->dir. `name`/`nlen` may point into the middle of a longer path, so the
// component is copied into a bounded buffer first.
// `allowDefaultBlacklist`: for a single-path query we apply the full rule
// (including "hide everything not whitelisted"); for a *directory listing* we
// must not, because dropping most entries out of a listing makes an app's
// index/cache inconsistent (QQ spun until the launch watchdog killed it).
static bool __attribute__((optnone)) rule_hides_name(const hide_dir_rule_t *rule, const char *name, size_t nlen, bool allowDefaultBlacklist)
{
	if (nlen == 0 || nlen >= 256) return false;

	char namebuf[256];
	memcpy(namebuf, name, nlen);
	namebuf[nlen] = '\0';

	if (nlen == 1 && namebuf[0] == '.') return false;
	if (nlen == 2 && namebuf[0] == '.' && namebuf[1] == '.') return false;

	if (str_in_list(namebuf, rule->blacklist)) return true;
	if (str_has_any_prefix(namebuf, rule->whitelist_prefix)) return false;
	if (str_in_list(namebuf, rule->whitelist)) return false;
	if (allowDefaultBlacklist && rule->default_blacklist) {
		if (is_self_bundle_name(namebuf)) return false;
		return true;
	}
	return false;
}

// optnone: Clang -Os miscompiles this string-matching body (register-allocation
// bug). Even in this separate TU the -Os codegen is unsafe, so disable all
// optimization on the path-matching functions.
static bool __attribute__((optnone)) path_is_blacklisted_by_rules(const char *path)
{
	if (!path || path[0] != '/') return false;

	for (size_t r = 0; r < sizeof(gHideRules)/sizeof(gHideRules[0]); r++) {
		const hide_dir_rule_t *rule = &gHideRules[r];
		size_t dlen = strlen(rule->dir);
		if (strncmp(path, rule->dir, dlen) != 0 || path[dlen] != '/') continue;

		const char *name = path + dlen + 1;
		const char *slash = strchr(name, '/');
		size_t nlen = slash ? (size_t)(slash - name) : strlen(name);

		if (rule_hides_name(rule, name, nlen, true)) return true;
	}

	return false;
}

static const char *gJailbreakPathMarkers[] = {
	"systemhook",
	"libjailbreak",
	"TweakLoader",
	"TweakInject",
	"ellekit",
	"libellekit",
	"libsubstrate",
	"CydiaSubstrate",
	"libsubstitute",
	"libhooker",
	"MobileSubstrate",
	"forkfix",
	".installed_dopamine",
};

// NOTE: this function runs on *every* file syscall in a hidden process
// (stat/access/fopen/opendir/readdir/realpath/...), so it is deliberately a
// straight sequence of cheap rejects that bail out as early as possible. An
// earlier version ran a 13-marker strstr() scan plus a 13-rule loop over the
// full path for every call; because this file is compiled -O0 (see below), that
// cost ~90us per call and made large apps (QQ: 195MB binary, hundreds of
// bundles) spend 31s of CPU in the hooks during launch, tripping the
// scene-create watchdog (0x8BADF00D).
bool __attribute__((optnone)) hidejb_rules_path_is_jailbreak(const char *path)
{
	if (!path || path[0] != '/') return false;

	// /var is a symlink to /private/var, so detectors often report the same path
	// with the /private/var prefix. Normalize it so /var/jb and the rule table
	// (which use /var/...) still match.
	if (strncmp(path, "/private/var/", 13) == 0) path += 8;

	// ---- hot-path fast rejects -------------------------------------------------
	// These subtrees can never match a hide rule (all rules live under
	// /var/mobile) and never contain a jailbreak library.
	if (strncmp(path, "/var/containers/", 16) == 0) return false; // app bundles
	if (strncmp(path, "/System/", 8) == 0) return false;
	if (strncmp(path, "/Applications/", 14) == 0) return false;
	if (strncmp(path, "/Developer/", 11) == 0) return false;

	// /var/jb
	if (path[1] == 'v' && path[2] == 'a' && path[3] == 'r' && path[4] == '/' &&
	    path[5] == 'j' && path[6] == 'b' && (path[7] == '/' || path[7] == '\0')) return true;

	// The real jbroot always lives under /private/preboot.
	if (strncmp(path, "/private/preboot", 16) == 0) return true;
	if (gJbRootReal[0]) {
		size_t n = strlen(gJbRootReal);
		if (strncmp(path, gJbRootReal, n) == 0 && (path[n] == '/' || path[n] == '\0')) return true;
	}

	// The fakelib bind mount makes the jailbreak dylibs show up in /usr/lib.
	// Only the basename can carry a marker, so check that instead of scanning
	// the whole path 13 times.
	if (strncmp(path, "/usr/lib/", 9) == 0) {
		const char *base = strrchr(path, '/');
		base = base ? base + 1 : path;
		for (size_t i = 0; i < sizeof(gJailbreakPathMarkers)/sizeof(gJailbreakPathMarkers[0]); i++) {
			if (strstr(base, gJailbreakPathMarkers[i])) return true;
		}
		return false;
	}

	// Every hide rule is under /var/mobile. The vast majority of /var/mobile
	// paths a running app touches are its own container
	// (/var/mobile/Containers/...), which no rule can match, so screen on the
	// second component first: only /var/mobile/Library, /var/mobile/Documents
	// and the handful of dotfiles in the /var/mobile blacklist can be hidden.
	if (strncmp(path, "/var/mobile/", 12) == 0) {
		const char *comp = path + 12;
		size_t n = 0;
		while (comp[n] && comp[n] != '/') n++;

		if ((n == 7 && strncmp(comp, "Library", 7) == 0) ||
		    (n == 9 && strncmp(comp, "Documents", 9) == 0)) {
			return path_is_blacklisted_by_rules(path);
		}

		static const char *const kMobileRootBlacklist[] = {
			".DO-NOT-DELETE-Cowabunga", ".Derootifier", "Helix", ".ssh", ".cache", NULL
		};
		for (size_t i = 0; kMobileRootBlacklist[i]; i++) {
			const char *b = kMobileRootBlacklist[i];
			if (strlen(b) == n && strncmp(comp, b, n) == 0) return true;
		}
		return false;
	}

	// Anything else (rare): only an embedded jailbreak marker matters.
	for (size_t i = 0; i < sizeof(gJailbreakPathMarkers)/sizeof(gJailbreakPathMarkers[0]); i++) {
		if (strstr(path, gJailbreakPathMarkers[i])) return true;
	}
	return false;
}

// True when the basename of `path` carries a jailbreak marker.
bool __attribute__((optnone)) hidejb_rules_path_has_marker(const char *path)
{
	if (!path || !path[0]) return false;
	const char *base = strrchr(path, '/');
	base = base ? base + 1 : path;
	for (size_t i = 0; i < sizeof(gJailbreakPathMarkers)/sizeof(gJailbreakPathMarkers[0]); i++) {
		if (strstr(base, gJailbreakPathMarkers[i])) return true;
	}
	return false;
}

// Cheap per-entry decision for the readdir hook: `entryName` is a component
// sitting directly inside `dirpath`.
//
// The readdir hook used to build the full path with snprintf() and then run
// hidejb_rules_path_is_jailbreak() on it for EVERY directory entry. When an app
// recursively enumerates a large tree (QQ: Foundation walking
// /var/mobile/Library via subpathsAtPath/enumeratorAtPath), that is hundreds of
// thousands of snprintf + full-path matches, and it burned 31s+ of CPU and
// tripped the launch watchdog. Deciding from (dirpath, entryName) directly
// avoids building the path at all.
bool __attribute__((optnone)) hidejb_rules_dir_hides_entry(const char *dirpath, const char *entryName)
{
	if (!dirpath || !entryName || !entryName[0]) return false;
	if (strncmp(dirpath, "/private/var/", 13) == 0) dirpath += 8;

	// Jailbreak library locations: decided purely by markers in the entry name.
	if (strncmp(dirpath, "/usr/lib", 8) == 0 ||
	    strncmp(dirpath, "/var/jb", 7) == 0 ||
	    strncmp(dirpath, "/private/preboot", 16) == 0 ||
	    (gJbRootReal[0] && strncmp(dirpath, gJbRootReal, strlen(gJbRootReal)) == 0)) {
		return hidejb_rules_path_has_marker(entryName);
	}

	// Rule table: only the rule whose dir IS this directory can hide the entry.
	// (An ancestor rule that wanted to hide this directory would have hidden the
	// directory itself, so readdir would never have been reached for it.)
	for (size_t r = 0; r < sizeof(gHideRules)/sizeof(gHideRules[0]); r++) {
		const hide_dir_rule_t *rule = &gHideRules[r];
		if (strcmp(dirpath, rule->dir) != 0) continue;
		// Listings only drop names from the rule's EXPLICIT blacklist. Applying
		// default_blacklist here would strip whole subtrees out of a listing
		// (e.g. /var/mobile/Library/Caches/*), which made QQ spin in its own
		// directory/bundle bookkeeping until the launch watchdog killed it.
		if (rule_hides_name(rule, entryName, strlen(entryName), false)) return true;
	}
	return false;
}

// True when `dirpath` is a directory that could contain entries which
// hidejb_rules_path_is_jailbreak() would hide. The readdir hook uses this to
// skip entry filtering (and the per-directory fcntl) for all other directories,
// which is the overwhelming majority.
bool __attribute__((optnone)) hidejb_rules_dir_may_hide_entries(const char *dirpath)
{
	if (!dirpath || dirpath[0] != '/') return false;
	if (strncmp(dirpath, "/private/var/", 13) == 0) dirpath += 8;

	if (strncmp(dirpath, "/usr/lib", 8) == 0) return true;
	if (strncmp(dirpath, "/var/jb", 7) == 0) return true;
	if (strncmp(dirpath, "/private/preboot", 16) == 0) return true;
	if (gJbRootReal[0]) {
		size_t n = strlen(gJbRootReal);
		if (strncmp(dirpath, gJbRootReal, n) == 0) return true;
	}

	// The rule table only matches entries directly under /var/mobile, or under
	// /var/mobile/Library and /var/mobile/Documents.
	if (strcmp(dirpath, "/var/mobile") == 0) return true;
	if (strncmp(dirpath, "/var/mobile/Library", 19) == 0) return true;
	if (strncmp(dirpath, "/var/mobile/Documents", 21) == 0) return true;
	return false;
}

void hidejb_rules_set_jbroot(const char *jbroot)
{
	if (jbroot && jbroot[0]) {
		char resolved[PATH_MAX] = {0};
		if (realpath(jbroot, resolved)) {
			strlcpy(gJbRootReal, resolved, sizeof(gJbRootReal));
		} else {
			strlcpy(gJbRootReal, jbroot, sizeof(gJbRootReal));
		}
	}
}

void hidejb_rules_set_self_bundle_id(void)
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
