#include "jbsettings.h"
#include <libjailbreak/info.h>
#include <libjailbreak/jbroot.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <dispatch/dispatch.h>

// The jailbreak settings live in gSystemInfo, which is plain in-memory state and
// resets to zero whenever launchd restarts (userspace reboot, re-jailbreak).
// Without a copy on disk the UI reads them back as "off" even though the user
// turned them on, which is what made the spinlock toggle appear to switch itself
// off. Persist them under the jbroot so they survive with the rest of the jailbreak.
#define JBSETTINGS_PLIST "/basebin/.jbsettings.plist"

// NOTE: JBROOT_PATH allocates its buffer with alloca() in the *caller's* stack
// frame, so it must never be returned from a function — the pointer dangles the
// moment that frame dies. That is exactly what made this flaky: fopen() below
// sometimes opened a path built from clobbered stack bytes, failed, and left the
// settings at their zeroed defaults, which looked like the toggle turning itself
// off. Build the path into a static buffer instead.
static const char *jbsettings_path(void)
{
	static char path[PATH_MAX];
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		path[0] = '\0';
		const char *jbroot = get_jbroot();
		if (!jbroot) return;
		strlcpy(path, jbroot, sizeof(path));
		strlcat(path, JBSETTINGS_PLIST, sizeof(path));
	});
	return path[0] ? path : NULL;
}

// Guards the one-shot load and lets read access repair a reset gSystemInfo.
// Boomerang serialises the whole struct across a userspace reboot, and any code
// that zeroes it (or an older boomerang that predates a new field) would leave
// the settings at their defaults for the rest of the session. Reloading on read
// makes that self-healing instead of permanent.
static bool gJBSettingsLoaded = false;

static bool jbsettings_memoryIsZeroed(void)
{
	return !jbsetting(markAppsAsDebugged)
	    && jbsetting(jetsamMultiplier) == 0
	    && jbsetting(noInjectRestoreMultiplier) == 0
	    && !jbsetting(spinlockFixEnhanced);
}

void jbsettings_load(void)
{
	if (gJBSettingsLoaded) return;

	const char *path = jbsettings_path();
	if (!path) return;

	FILE *f = fopen(path, "rb");
	if (!f) {
		// Diagnostic: the file is absent. Recorded once per launchd start so a
		// fresh install that never touched a setting is distinguishable from a
		// settings file that went missing.
		FILE *log = fopen("/var/mobile/Documents/noinject_log.txt", "a");
		if (log) { fprintf(log, "jbsettings_load: NO FILE at %s\n", path); fclose(log); }
		return;
	}

	long size = -1;
	if (fseek(f, 0, SEEK_END) == 0) size = ftell(f);
	if (size <= 0 || size > 4096) { fclose(f); return; }
	rewind(f);

	unsigned char buf[4096];
	size_t got = fread(buf, 1, (size_t)size, f);
	if (got != (size_t)size) { fclose(f); return; }
	fclose(f);

	CFDataRef data = CFDataCreate(kCFAllocatorDefault, buf, (CFIndex)size);
	if (!data) return;

	CFPropertyListRef plist = CFPropertyListCreateWithData(kCFAllocatorDefault, data, kCFPropertyListImmutable, NULL, NULL);
	CFRelease(data);
	if (!plist || CFGetTypeID(plist) != CFDictionaryGetTypeID()) {
		if (plist) CFRelease(plist);
		return;
	}

	CFDictionaryRef dict = (CFDictionaryRef)plist;

	CFBooleanRef boolValue = CFDictionaryGetValue(dict, CFSTR("markAppsAsDebugged"));
	if (boolValue && CFGetTypeID(boolValue) == CFBooleanGetTypeID()) {
		gSystemInfo.jailbreakSettings.markAppsAsDebugged = CFBooleanGetValue(boolValue);
	}

	CFNumberRef numValue = CFDictionaryGetValue(dict, CFSTR("jetsamMultiplier"));
	if (numValue && CFGetTypeID(numValue) == CFNumberGetTypeID()) {
		double d = 0;
		if (CFNumberGetValue(numValue, kCFNumberDoubleType, &d)) {
			gSystemInfo.jailbreakSettings.jetsamMultiplier = d;
		}
	}

	numValue = CFDictionaryGetValue(dict, CFSTR("noInjectRestoreMultiplier"));
	if (numValue && CFGetTypeID(numValue) == CFNumberGetTypeID()) {
		double d = 0;
		if (CFNumberGetValue(numValue, kCFNumberDoubleType, &d)) {
			gSystemInfo.jailbreakSettings.noInjectRestoreMultiplier = d;
		}
	}

	boolValue = CFDictionaryGetValue(dict, CFSTR("spinlockFixEnhanced"));
	if (boolValue && CFGetTypeID(boolValue) == CFBooleanGetTypeID()) {
		gSystemInfo.jailbreakSettings.spinlockFixEnhanced = CFBooleanGetValue(boolValue);
	}

	// Diagnostic: what was actually restored, so a "toggle turned itself off" or
	// "hide did nothing" report can be tied to a missing/zeroed value.
	FILE *log = fopen("/var/mobile/Documents/noinject_log.txt", "a");
	if (log) {
		fprintf(log, "jbsettings_load: OK spinlock=%d jetsam=%.2f restoreMult=%.2f debugged=%d\n",
				(int)jbsetting(spinlockFixEnhanced),
				jbsetting(jetsamMultiplier),
				jbsetting(noInjectRestoreMultiplier),
				(int)jbsetting(markAppsAsDebugged));
		fclose(log);
	}

	CFRelease(plist);
	gJBSettingsLoaded = true;
}

static void jbsettings_save(void)
{
	const char *path = jbsettings_path();
	if (!path) return;

	CFMutableDictionaryRef dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (!dict) return;

	CFDictionarySetValue(dict, CFSTR("markAppsAsDebugged"),
		jbsetting(markAppsAsDebugged) ? kCFBooleanTrue : kCFBooleanFalse);

	double jetsam = jbsetting(jetsamMultiplier);
	CFNumberRef jetsamNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberDoubleType, &jetsam);
	if (jetsamNum) {
		CFDictionarySetValue(dict, CFSTR("jetsamMultiplier"), jetsamNum);
		CFRelease(jetsamNum);
	}

	double restoreMult = jbsetting(noInjectRestoreMultiplier);
	CFNumberRef restoreNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberDoubleType, &restoreMult);
	if (restoreNum) {
		CFDictionarySetValue(dict, CFSTR("noInjectRestoreMultiplier"), restoreNum);
		CFRelease(restoreNum);
	}

	CFDictionarySetValue(dict, CFSTR("spinlockFixEnhanced"),
		jbsetting(spinlockFixEnhanced) ? kCFBooleanTrue : kCFBooleanFalse);

	CFDataRef data = CFPropertyListCreateData(kCFAllocatorDefault, dict,
		kCFPropertyListBinaryFormat_v1_0, 0, NULL);
	CFRelease(dict);
	if (!data) return;

	// Write to a sibling temp file and rename over the real one. Writing the
	// target directly means an interruption mid-write (launchd restart, kill,
	// disk pressure) leaves a truncated plist behind, and load() then fails to
	// parse it and silently keeps every setting at its zeroed default. That is
	// the "my configuration disappeared by itself" symptom.
	char tmpPath[PATH_MAX];
	strlcpy(tmpPath, path, sizeof(tmpPath));
	strlcat(tmpPath, ".tmp", sizeof(tmpPath));

	FILE *f = fopen(tmpPath, "wb");
	if (f) {
		size_t len = (size_t)CFDataGetLength(data);
		size_t wrote = fwrite(CFDataGetBytePtr(data), 1, len, f);
		int flushOk = (fflush(f) == 0);
		int closeOk = (fclose(f) == 0);
		// f is closed unconditionally above, so the failure path must not close it
		// again; it only discards the partial file.
		if (wrote == len && flushOk && closeOk && rename(tmpPath, path) == 0) {
			// renamed atomically over the previous plist
		}
		else {
			unlink(tmpPath);
		}
	}
	CFRelease(data);
}

int jbsettings_get(const char *key, xpc_object_t *valueOut)
{
	if (!key || !valueOut) return -1;

	// Self-heal: if the in-memory copy looks zeroed, try the disk again. A
	// boomerang round trip across a userspace reboot can hand back a struct
	// without these fields, and without this the UI would read defaults forever.
	if (jbsettings_memoryIsZeroed()) {
		gJBSettingsLoaded = false;
		jbsettings_load();
	}

	if (!strcmp(key, "markAppsAsDebugged")) {
		*valueOut = xpc_bool_create(jbsetting(markAppsAsDebugged));
		return 0;
	}
	else if (!strcmp(key, "jetsamMultiplier")) {
		*valueOut = xpc_double_create(jbsetting(jetsamMultiplier));
		return 0;
	}
	else if (!strcmp(key, "spinlockFixEnhanced")) {
		*valueOut = xpc_bool_create(jbsetting(spinlockFixEnhanced));
		return 0;
	}
	else if (!strcmp(key, "noInjectRestoreMultiplier")) {
		*valueOut = xpc_double_create(jbsetting(noInjectRestoreMultiplier));
		return 0;
	}
	return -1;
}

int jbsettings_set(const char *key, xpc_object_t value)
{
	if (!key || !value) return -1;

	if (!strcmp(key, "markAppsAsDebugged") && xpc_get_type(value) == XPC_TYPE_BOOL) {
		gSystemInfo.jailbreakSettings.markAppsAsDebugged = xpc_bool_get_value(value);
		jbsettings_save();
		return 0;
	}
	else if (!strcmp(key, "jetsamMultiplier") && xpc_get_type(value) == XPC_TYPE_DOUBLE) {
		gSystemInfo.jailbreakSettings.jetsamMultiplier = xpc_double_get_value(value);
		jbsettings_save();
		return 0;
	}
	else if (!strcmp(key, "spinlockFixEnhanced") && xpc_get_type(value) == XPC_TYPE_BOOL) {
		gSystemInfo.jailbreakSettings.spinlockFixEnhanced = xpc_bool_get_value(value);
		jbsettings_save();
		return 0;
	}
	else if (!strcmp(key, "noInjectRestoreMultiplier") && xpc_get_type(value) == XPC_TYPE_DOUBLE) {
		gSystemInfo.jailbreakSettings.noInjectRestoreMultiplier = xpc_double_get_value(value);
		jbsettings_save();
		return 0;
	}
	return -1;
}
