#import <Foundation/Foundation.h>
#import <libjailbreak/util.h>
#import <libjailbreak/jbclient_xpc.h>
#import <libroot.h>
#import <objc/runtime.h>

%hookf(NSURL *, _LSGetInboxURLForBundleIdentifier, NSString *bundleIdentifier)
{
	NSURL *origURL = %orig;
	if (![bundleIdentifier hasPrefix:@"com.apple"] && [origURL.path hasPrefix:@"/var/mobile/Library/Application Support/Containers/"]) {
		return [NSURL fileURLWithPath:JBROOT_PATH_NSSTRING(origURL.path)];
	}
	return origURL;
}

%hookf(int, _LSServer_RebuildApplicationDatabases)
{
	int r = %orig;

	dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
		// Ensure jailbreak apps are readded to icon cache after the system reloads it
		// A bit hacky, but works
		const char *uicachePath = JBROOT_PATH_CSTRING("/usr/bin/uicache");
		if (!access(uicachePath, F_OK)) {
			exec_cmd(uicachePath, "-a", NULL);
		}
	});

	return r;
}

// ---------------------------------------------------------------------------
// RootHide-style URL scheme hiding for "hidden" apps (ported from
// roothidehooks/lsd.x). lsd is injected by systemhook, so we can filter
// canOpenURL:/openURL: for blacklisted pids without injecting the app itself.
// ---------------------------------------------------------------------------

@interface LSApplicationProxy : NSObject
+ (id)applicationProxyForIdentifier:(id)arg1;
- (NSURL*)bundleURL;
- (NSString*)bundleIdentifier;
@end

@interface LSApplicationWorkspace : NSObject
+ (LSApplicationWorkspace*)defaultWorkspace;
- (NSArray*)applicationsAvailableForHandlingURLScheme:(NSString*)scheme;
@end

static BOOL isJailbreakBundleIdentifier(NSString *bundleID)
{
	static NSSet<NSString *> *set = nil;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		set = [NSSet setWithArray:@[
			@"org.coolstar.SileoStore",
			@"xyz.willy.Zebra",
			@"com.tigisoftware.Filza",
			@"com.opa334.Dopamine",
			@"com.opa334.Dopamine.roothide",
			@"ws.hbang.Terminal",
			@"ws.hbang.NewTerm",
			@"ru.domo.cocoatop64",
			@"com.opa334.TrollStore",
		]];
	});
	return bundleID.length > 0 && [set containsObject:bundleID];
}

// TrollStore / jailbreak utility apps have bundle ids that vary, so also match
// on the .app directory name (same idea as the fork's hideJailbreakURLSchemes).
static BOOL isJailbreakAppName(NSString *appName)
{
	static NSSet<NSString *> *set = nil;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		set = [NSSet setWithArray:@[
			@"Sileo.app", @"Zebra.app", @"Filza.app", @"NewTerm.app",
			@"CocoaTop.app", @"Dopamine.app", @"TrollStore.app",
			@"Reveil.app", @"PostBox.app", @"Santander.app", @"Cowabunga.app",
			@"misaka.app", @"iCleaner.app", @"iCleanerPro.app",
		]];
	});
	return appName.length > 0 && [set containsObject:appName];
}

static BOOL isJailbreakURLScheme(NSString *scheme)
{
	if (scheme.length == 0) return NO;

	NSArray *apps = [[NSClassFromString(@"LSApplicationWorkspace") defaultWorkspace]
		applicationsAvailableForHandlingURLScheme:scheme];
	for (id app in apps) {
		NSString *bundleID = [app performSelector:@selector(bundleIdentifier)];
		if (isJailbreakBundleIdentifier(bundleID)) {
			return YES;
		}

		NSURL *bundleURL = [app performSelector:@selector(bundleURL)];
		if (isJailbreakAppName(bundleURL.lastPathComponent)) {
			return YES;
		}
	}
	return NO;
}

static const void *kBlockSchemeTagKey = &kBlockSchemeTagKey;

%hook _LSCanOpenURLManager

-(void*)getIsURL:(NSURL*)url alwaysCheckable:(BOOL*)pCheckable hasHandler:(BOOL*)pHasHandler
{
	BOOL _checkable = NO;
	BOOL _hasHandler = NO;
	void* result = %orig(url, &_checkable, &_hasHandler);

	if (_checkable || _hasHandler) {
		NSNumber *tag = objc_getAssociatedObject(url, kBlockSchemeTagKey);
		if (tag && tag.boolValue) {
			_hasHandler = NO;
			_checkable = NO;
		}
	}

	if (pCheckable) *pCheckable = _checkable;
	if (pHasHandler) *pHasHandler = _hasHandler;
	return result;
}

- (BOOL)canOpenURL:(NSURL*)url publicSchemes:(BOOL)ispublic privateSchemes:(BOOL)isprivate XPCConnection:(NSXPCConnection*)connection error:(NSError**)perror
{
	if (connection) {
		pid_t pid = connection.processIdentifier;
		if (jbclient_blacklist_check_pid(pid) && isJailbreakURLScheme(url.scheme)) {
			objc_setAssociatedObject(url, kBlockSchemeTagKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
		}
	}
	return %orig;
}

%end //%hook _LSCanOpenURLManager


@interface _LSDOpenClient : NSObject
- (NSXPCConnection *)XPCConnection;
@end

%hook _LSDOpenClient

// 16.2+
-(void)openURL:(NSURL*)url fileHandle:(id)fileHandle options:(id)options completionHandler:(void(^)(BOOL,NSError*))completionHandler
{
	NSXPCConnection *conn = [self XPCConnection];
	if (conn) {
		pid_t pid = [conn processIdentifier];
		if (jbclient_blacklist_check_pid(pid) && isJailbreakURLScheme(url.scheme)) {
			if (completionHandler) completionHandler(NO, nil);
			return;
		}
	}
	%orig;
}

// 15.0~16.0
- (void)openURL:(NSURL*)url options:(id)options completionHandler:(void(^)(BOOL,NSError*))completionHandler
{
	NSXPCConnection *conn = [self XPCConnection];
	if (conn) {
		pid_t pid = [conn processIdentifier];
		if (jbclient_blacklist_check_pid(pid) && isJailbreakURLScheme(url.scheme)) {
			if (completionHandler) completionHandler(NO, nil);
			return;
		}
	}
	%orig;
}

%end //%hook _LSDOpenClient

void lsdInit(void)
{
	MSImageRef coreServicesImage = MSGetImageByName("/System/Library/Frameworks/CoreServices.framework/CoreServices");

	// One %init for everything (Logos forbids re-initializing the same group):
	// the two C-function hooks from CoreServices, plus the two private classes.
	%init(_LSGetInboxURLForBundleIdentifier = MSFindSymbol(coreServicesImage, "__LSGetInboxURLForBundleIdentifier"),
		  _LSServer_RebuildApplicationDatabases = MSFindSymbol(coreServicesImage, "__LSServer_RebuildApplicationDatabases"),
		  _LSCanOpenURLManager = objc_getClass("_LSCanOpenURLManager"),
		  _LSDOpenClient = objc_getClass("_LSDOpenClient"));
}
