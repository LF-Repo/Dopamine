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
		char namebuf[256];
		size_t nlen = slash ? (size_t)(slash - name) : strlen(name);
		if (nlen == 0 || nlen >= sizeof(namebuf)) continue;
		memcpy(namebuf, name, nlen);
		namebuf[nlen] = '\0';

		if (nlen == 1 && namebuf[0] == '.') continue;
		if (nlen == 2 && namebuf[0] == '.' && namebuf[1] == '.') continue;

		if (str_in_list(namebuf, rule->blacklist)) return true;
		if (str_has_any_prefix(namebuf, rule->whitelist_prefix)) continue;
		if (str_in_list(namebuf, rule->whitelist)) continue;
		if (rule->default_blacklist) {
			if (is_self_bundle_name(namebuf)) continue;
			return true;
		}
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

bool __attribute__((optnone)) hidejb_rules_path_is_jailbreak(const char *path)
{
	if (!path || path[0] != '/') return false;

	// /var is a symlink to /private/var, so detectors often report the same path
	// with the /private/var prefix. Normalize it so /var/jb and the rule table
	// (which use /var/...) still match.
	if (strncmp(path, "/private/var/", 13) == 0) path += 8;

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
