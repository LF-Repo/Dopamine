#import <Foundation/Foundation.h>
#import <substrate.h>
#import <objc/objc.h>
#import <libroot.h>
#import <fcntl.h>
#import <libjailbreak/jbclient_xpc.h>

bool string_has_prefix(const char *str, const char* prefix)
{
	if (!str || !prefix) {
		return false;
	}

	size_t str_len = strlen(str);
	size_t prefix_len = strlen(prefix);

	if (str_len < prefix_len) {
		return false;
	}

	return !strncmp(str, prefix, prefix_len);
}

@interface XBSnapshotContainerIdentity : NSObject <NSCopying>
@property (nonatomic, readonly, copy) NSString* bundleIdentifier;
- (NSString*)snapshotContainerPath;
@end

%hook XBSnapshotContainerIdentity

- (NSString *)snapshotContainerPath
{
	NSString *path = %orig;
	if([path hasPrefix:@"/var/mobile/Library/SplashBoard/Snapshots/"] && ![self.bundleIdentifier hasPrefix:@"com.apple."]) {
		return JBROOT_PATH_NSSTRING(path);
	}
	return path;
}

%end

%hookf(int, fcntl, int fildes, int cmd, ...) {
	if (cmd == F_SETPROTECTIONCLASS) {
		char filePath[PATH_MAX];
		if (fcntl(fildes, F_GETPATH, filePath) != -1) {
			// Skip setting protection class on jailbreak apps, this doesn't work and causes snapshots to not be saved correctly
			if (string_has_prefix(filePath, JBROOT_PATH_CSTRING("/var/mobile/Library/SplashBoard/Snapshots"))) {
				return 0;
			}
		}
	}

	va_list a;
	va_start(a, cmd);
	const char *arg1 = va_arg(a, void *);
	const void *arg2 = va_arg(a, void *);
	const void *arg3 = va_arg(a, void *);
	const void *arg4 = va_arg(a, void *);
	const void *arg5 = va_arg(a, void *);
	const void *arg6 = va_arg(a, void *);
	const void *arg7 = va_arg(a, void *);
	const void *arg8 = va_arg(a, void *);
	const void *arg9 = va_arg(a, void *);
	const void *arg10 = va_arg(a, void *);
	va_end(a);
	return %orig(fildes, cmd, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);
}

// ---------------------------------------------------------------------------
// Foreground/background aware hide: while a "HideNoInject" app is in the
// foreground, tell launchd to hide the jailbreak; once it goes to the
// background (or SpringBoard/home screen), tell launchd to restore it so Sileo
// etc. keep working.
// ---------------------------------------------------------------------------

static BOOL is_no_inject_bundle_id(NSString *bundleID)
{
	if (bundleID.length == 0) return NO;
	NSDictionary *rules = [NSDictionary dictionaryWithContentsOfFile:
		@"/var/mobile/Library/Preferences/.DopamineAppHideRules.plist"];
	NSDictionary *appRule = rules[bundleID];
	return [appRule[@"HideNoInject"] boolValue];
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"

static NSString *frontmost_bundle_id(void)
{
	// FBProcessManager.frontmostApplicationProcess is the live frontmost process.
	Class pmClass = NSClassFromString(@"FBProcessManager");
	if (pmClass && [pmClass respondsToSelector:@selector(sharedInstance)]) {
		id pm = [pmClass performSelector:@selector(sharedInstance)];
		if (pm) {
			SEL pmSels[] = { @selector(frontmostApplicationProcess), @selector(currentProcess) };
			for (int i = 0; i < 2; i++) {
				if ([pm respondsToSelector:pmSels[i]]) {
					id proc = [pm performSelector:pmSels[i]];
					if (proc && [proc respondsToSelector:@selector(bundleIdentifier)]) {
						NSString *bid = [proc performSelector:@selector(bundleIdentifier)];
						if (bid.length) return bid;
					}
				}
			}
		}
	}

	// SpringBoard frontmost application (fallback).
	id springBoard = [NSClassFromString(@"SpringBoard") performSelector:@selector(sharedApplication)];
	if (springBoard) {
		SEL sbSels[] = { @selector(frontmostApplication), @selector(_frontmostApplication) };
		for (int i = 0; i < 2; i++) {
			if ([springBoard respondsToSelector:sbSels[i]]) {
				id frontmost = [springBoard performSelector:sbSels[i]];
				if (frontmost && [frontmost respondsToSelector:@selector(bundleIdentifier)]) {
					NSString *bid = [frontmost performSelector:@selector(bundleIdentifier)];
					if (bid.length) return bid;
				}
			}
		}
	}
	return @"";
}

#pragma clang diagnostic pop

static NSString *gLastFrontmostBundleID = @"";
static BOOL gLastShouldHide = NO;
static BOOL gLastActed = NO;
static int gStableCount = 0;
static dispatch_source_t gForegroundTimer = NULL;

static void check_foreground_app(void)
{
	NSString *bundleID = frontmost_bundle_id();
	BOOL shouldHide = is_no_inject_bundle_id(bundleID);

	BOOL changed = (![bundleID isEqualToString:gLastFrontmostBundleID] || shouldHide != gLastShouldHide);
	gLastFrontmostBundleID = bundleID;
	gLastShouldHide = shouldHide;

	if (changed) {
		// Frontmost app (or its hide rule) changed: reset the debounce so we
		// never act on a transient state (e.g. the spawn hook just hid while
		// SpringBoard hasn't yet marked the app frontmost).
		gStableCount = 0;
		gLastActed = NO;
		return;
	}

	if (gLastActed) return;

	// Require 3 stable polls (~1.5s) before acting. This also makes the state
	// self-healing: if the hide got stuck, a stable "not hidden" frontmost will
	// restore it after ~1.5s.
	gStableCount++;
	if (gStableCount < 3) return;

	gLastActed = YES;
	jbclient_set_app_hidden(shouldHide);
}

static void start_foreground_polling(void)
{
	if (gForegroundTimer) return;
	// Delay startup well past the jailbreak/userspace-reboot window so we never
	// act on a transitional frontmost app during boot (this was hiding the
	// jailbreak right after it finished and breaking "Updating Bundled Packages").
	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 15 * NSEC_PER_SEC),
		dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0), ^{
		if (gForegroundTimer) return;
		gForegroundTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
			dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0));
		dispatch_source_set_timer(gForegroundTimer, dispatch_time(DISPATCH_TIME_NOW, 0),
			500 * NSEC_PER_MSEC, 100 * NSEC_PER_MSEC);
		dispatch_source_set_event_handler(gForegroundTimer, ^{
			check_foreground_app();
		});
		dispatch_resume(gForegroundTimer);
	});
}

void springboardInit(void)
{
	%init();
	start_foreground_polling();
}
