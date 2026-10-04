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
			@"chromatic.app", @"Saily.app",
		]];
	});
	return appName.length > 0 && [set containsObject:appName];
}

// A bundle path belongs to a jailbreak app when it lives under /var/jb
// (standard rootless symlink) or under the resolved preboot procursus root.
static BOOL isJailbreakBundlePath(const char *path)
{
	if (!path) return NO;
	if (strncmp(path, "/var/jb/", 8) == 0) return YES;
	if (strstr(path, "/procursus/")) return YES;
	return NO;
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

// ===========================================================================
// UTType hiding + extension/plugin hiding (ported from roothidehooks/lsd.x).
// Hides jailbreak apps' document types and extensions from "hidden"
// (blacklisted) apps so LSApplicationWorkspace / UIDocument* / extension
// queries don't reveal jailbreak apps.
// ===========================================================================

%hook _LSURLOverride
-(id)initWithOriginalURL:(NSURL*)url
{
	NSNumber *tag = objc_getAssociatedObject(url, kBlockSchemeTagKey);
	if (tag && tag.boolValue) {
		return nil;
	}
	return %orig;
}
%end

%group UTTypeHooks

@interface UTTypeRecord : NSObject
+ (id)typeRecordWithIdentifier:(id)identifier;
- (unsigned int)tableID;
@end

@interface _UTDeclaredTypeRecord : NSObject
- (id)_initWithContext:(void*)ctx tableID:(unsigned int)tableID unitID:(unsigned int)unitID;
- (BOOL)isDeclared;
- (BOOL)isCoreType;
- (BOOL)isInPublicDomain;
- (id)identifier;
- (id)declaringBundleRecord;
- (unsigned int)unitID;
- (unsigned int)_rawFlags;
@end

@interface LSBundleRecord : NSObject
- (NSURL*)URL;
@end

@interface _LSDReadClient : NSObject
- (NSXPCConnection*)XPCConnection;
@end

static __thread BOOL g_utrHide = NO;
static __thread int g_utrBusy = 0;

static BOOL utrFilterActive(void) { return g_utrHide && !g_utrBusy; }

static pid_t utrClientPid(_LSDReadClient* client)
{
	NSXPCConnection* conn = [client XPCConnection];
	return conn ? conn.processIdentifier : -1;
}

static BOOL utrHideClientBlacklisted(_LSDReadClient* client)
{
	pid_t pid = utrClientPid(client);
	return (pid > 0 && jbclient_blacklist_check_pid(pid));
}

static unsigned int utrTypeTableID(void)
{
	static unsigned int tid = 0;
	static dispatch_once_t once;
	dispatch_once(&once, ^{
		g_utrBusy++;
		tid = (unsigned int)[[NSClassFromString(@"UTTypeRecord") typeRecordWithIdentifier:@"public.data"] tableID];
		g_utrBusy--;
	});
	return tid;
}

static BOOL utrRecordIsFromJailbreakApp(_UTDeclaredTypeRecord* rec)
{
	if (![rec isDeclared]) return NO;
	if ([rec isCoreType]) return NO;
	if ([rec isInPublicDomain]) return NO;
	LSBundleRecord* bundleRec = [rec declaringBundleRecord];
	NSURL* url = [bundleRec URL];
	if (![url isKindOfClass:[NSURL class]] || !url.isFileURL) return NO;
	if (!isJailbreakBundlePath(url.path.fileSystemRepresentation)) return NO;
	return YES;
}

static BOOL utrUnitIsJailbreak(void* db, intptr_t unitID)
{
	BOOL result = NO;
	g_utrBusy++;
	unsigned int tid = utrTypeTableID();
	if (tid) {
		void* ctx = db;
		_UTDeclaredTypeRecord* rec = [[NSClassFromString(@"_UTDeclaredTypeRecord") alloc]
					_initWithContext:(void*)&ctx tableID:tid unitID:(unsigned int)unitID];
		result = utrRecordIsFromJailbreakApp(rec);
	}
	g_utrBusy--;
	return result;
}

typedef intptr_t (^UTREnumBlock)(intptr_t a2, intptr_t unitID, const void* unitBytes, void* a5);
%hookf(void, _UTEnumerateTypesForTag, void* db, void* tagClass, void* tag, id block)
{
	if (!utrFilterActive() || !block) { %orig; return; }
	UTREnumBlock orig = (UTREnumBlock)block;
	UTREnumBlock wrapper = ^intptr_t(intptr_t a2, intptr_t unitID, const void* unitBytes, void* a5) {
		if (utrUnitIsJailbreak(db, unitID)) return 0;
		return orig(a2, unitID, unitBytes, a5);
	};
	%orig(db, tagClass, tag, wrapper);
}

%hookf(void, _UTEnumerateTypesForIdentifier, void* db, long identStrId, id block)
{
	if (!utrFilterActive() || !block) { %orig; return; }
	UTREnumBlock orig = (UTREnumBlock)block;
	UTREnumBlock wrapper = ^intptr_t(intptr_t a2, intptr_t unitID, const void* unitBytes, void* a5) {
		if (utrUnitIsJailbreak(db, unitID)) return 0;
		return orig(a2, unitID, unitBytes, a5);
	};
	%orig(db, identStrId, wrapper);
}

typedef void (^UTRConformBlock)(intptr_t unitID, const void* unitBytes, intptr_t kind, unsigned char* outStop);
%hookf(void, _UTTypeSearchConformingTypesWithBlock, void* db, long unitID, long flags, long arg4, id block)
{
	if (!utrFilterActive() || !block) { %orig; return; }
	UTRConformBlock orig = (UTRConformBlock)block;
	UTRConformBlock wrapper = ^void(intptr_t uid, const void* unitBytes, intptr_t kind, unsigned char* outStop) {
		if (utrUnitIsJailbreak(db, uid)) return;
		orig(uid, unitBytes, kind, outStop);
	};
	%orig(db, unitID, flags, arg4, wrapper);
}

%hookf(void, _UTTypeSearchConformsToTypesWithBlock, void* db, long unitID, long flags, long arg4, id block)
{
	if (!utrFilterActive() || !block) { %orig; return; }
	UTRConformBlock orig = (UTRConformBlock)block;
	UTRConformBlock wrapper = ^void(intptr_t uid, const void* unitBytes, intptr_t kind, unsigned char* outStop) {
		if (utrUnitIsJailbreak(db, uid)) return;
		orig(uid, unitBytes, kind, outStop);
	};
	%orig(db, unitID, flags, arg4, wrapper);
}

%hookf(void, _LSSchemaCacheRead, void* a1, id block)
{
	if (utrFilterActive()) return;
	%orig(a1, block);
}

%hookf(void, _LSSchemaCacheWrite, void* a1, id block)
{
	if (utrFilterActive()) return;
	%orig(a1, block);
}

%hook _LSDReadClient
- (void)getTypeRecordWithTag:(id)tag ofClass:(id)_class conformingToIdentifier:(id)identifier completionHandler:(void(^)(id))handler
{
	if (!utrHideClientBlacklisted(self)) { %orig; return; }
	g_utrHide = YES; %orig; g_utrHide = NO;
}
- (void)getTypeRecordsWithTag:(id)tag ofClass:(id)_class conformingToIdentifier:(id)identifier completionHandler:(void(^)(id))handler
{
	if (!utrHideClientBlacklisted(self)) { %orig; return; }
	g_utrHide = YES; %orig; g_utrHide = NO;
}
- (void)getTypeRecordWithIdentifier:(id)identifier allowUndeclared:(BOOL)allowUndeclared completionHandler:(void(^)(id))handler
{
	if (!utrHideClientBlacklisted(self)) { %orig; return; }
	g_utrHide = YES; %orig; g_utrHide = NO;
}
- (void)getTypeRecordsWithIdentifiers:(id)identifiers completionHandler:(void(^)(id))handler
{
	if (!utrHideClientBlacklisted(self)) { %orig; return; }
	g_utrHide = YES; %orig; g_utrHide = NO;
}
- (void)getTypeRecordForImportedTypeWithIdentifier:(id)identifier conformingToIdentifier:(id)conforming completionHandler:(void(^)(id))handler
{
	if (!utrHideClientBlacklisted(self)) { %orig; return; }
	g_utrHide = YES; %orig; g_utrHide = NO;
}
- (void)getRelatedTypesOfTypeWithIdentifier:(id)identifier maximumDegreeOfSeparation:(NSInteger)degree completionHandler:(void(^)(id, id))handler
{
	if (!utrHideClientBlacklisted(self)) { %orig; return; }
	g_utrHide = YES; %orig; g_utrHide = NO;
}
- (void)getWhetherTypeIdentifier:(id)identifier conformsToTypeIdentifier:(id)other completionHandler:(void(^)(id))handler
{
	if (!utrHideClientBlacklisted(self)) { %orig; return; }
	g_utrHide = YES; %orig; g_utrHide = NO;
}
- (void)getResourceValuesForKeys:(id)keys URL:(id)url preferredLocalizations:(id)locs completionHandler:(void(^)(id, id, id))handler
{
	if (!utrHideClientBlacklisted(self)) { %orig; return; }
	g_utrHide = YES; %orig; g_utrHide = NO;
}
- (void)getBoundIconInfoForDocumentProxy:(id)documentProxy completionHandler:(void(^)(id, id))handler
{
	if (!utrHideClientBlacklisted(self)) { %orig; return; }
	g_utrHide = YES; %orig; g_utrHide = NO;
}
%end

%end // %group UTTypeHooks

%hook _LSQueryContext

@interface LSPlugInQueryWithUnits : NSObject
-(id)initWithPlugInUnits:(id)units forDatabaseWithUUID:(id)dbUUID;
@end

@interface _LSQueryContext : NSObject
-(NSMutableDictionary*)_resolveQueries:(NSMutableSet*)queries XPCConnection:(NSXPCConnection*)connection error:(NSError**)perror;
@end

-(NSMutableDictionary*)_resolveQueries:(NSMutableSet*)queries XPCConnection:(NSXPCConnection*)connection error:(NSError**)perror
{
	NSMutableDictionary* result = %orig;
	if(!result || !connection) return result;

	pid_t pid = connection.processIdentifier;
	if(!jbclient_blacklist_check_pid(pid)) return result;

	for(id key in result)
	{
		if([key isKindOfClass:NSClassFromString(@"LSPlugInQueryWithUnits")]
			|| [key isKindOfClass:NSClassFromString(@"LSPlugInQueryWithIdentifier")]
			|| [key isKindOfClass:NSClassFromString(@"LSPlugInQueryWithQueryDictionary")])
		{
			NSMutableArray* plugins = result[key];
			NSMutableIndexSet* removed = [[NSMutableIndexSet alloc] init];
			for (int i=0; i<[plugins count]; i++)
			{
				id plugin = plugins[i];
				id appbundle = [plugin performSelector:@selector(containingBundle)];
				if(!appbundle) continue;
				NSURL* bundleURL = [appbundle performSelector:@selector(bundleURL)];
				if(isJailbreakBundlePath(bundleURL.path.fileSystemRepresentation)) {
					[removed addIndex:i];
				}
			}
			[plugins removeObjectsAtIndexes:removed];

			if([key isKindOfClass:NSClassFromString(@"LSPlugInQueryWithUnits")])
			{
				NSMutableArray* units = [[key valueForKey:@"_pluginUnits"] mutableCopy];
				[units removeObjectsAtIndexes:removed];
				[key setValue:[units copy] forKey:@"_pluginUnits"];
			}
		}
		else if([key isKindOfClass:NSClassFromString(@"LSPlugInQueryAllUnits")])
		{
			NSMutableArray* unitsArray = result[key];
			for (int i=0; i<[unitsArray count]; i++)
			{
				id unitsResult = unitsArray[i];
				NSUUID* _dbUUID = [unitsResult valueForKey:@"_dbUUID"];
				NSArray* _pluginUnits = [unitsResult valueForKey:@"_pluginUnits"];
				id unitQuery = [[NSClassFromString(@"LSPlugInQueryWithUnits") alloc] initWithPlugInUnits:_pluginUnits forDatabaseWithUUID:_dbUUID];
				NSMutableDictionary* queriesResult = [self _resolveQueries:[NSSet setWithObject:unitQuery].mutableCopy XPCConnection:connection error:perror];
				if(queriesResult)
				{
					for(id queryKey in queriesResult)
					{
						NSArray* new_pluginUnits = [queryKey valueForKey:@"_pluginUnits"];
						[unitsResult setValue:new_pluginUnits forKey:@"_pluginUnits"];
					}
				}
			}
		}
	}

	return result;
}
%end

void lsdInit(void)
{
	MSImageRef coreServicesImage = MSGetImageByName("/System/Library/Frameworks/CoreServices.framework/CoreServices");

	// Default group: URL scheme hiding + _LSURLOverride + plugin/extension hiding.
	%init(_LSGetInboxURLForBundleIdentifier = MSFindSymbol(coreServicesImage, "__LSGetInboxURLForBundleIdentifier"),
		  _LSServer_RebuildApplicationDatabases = MSFindSymbol(coreServicesImage, "__LSServer_RebuildApplicationDatabases"),
		  _LSCanOpenURLManager = objc_getClass("_LSCanOpenURLManager"),
		  _LSDOpenClient = objc_getClass("_LSDOpenClient"),
		  _LSURLOverride = objc_getClass("_LSURLOverride"),
		  _LSQueryContext = objc_getClass("_LSQueryContext"));

	// UTType hiding group (CoreServices C functions). Best-effort: only install
	// if every symbol resolves.
	void* _LSSchemaCacheRead = MSFindSymbol(coreServicesImage, "__LSSchemaCacheRead");
	void* _LSSchemaCacheWrite = MSFindSymbol(coreServicesImage, "__LSSchemaCacheWrite");
	void* _UTEnumerateTypesForTag = MSFindSymbol(coreServicesImage, "__UTEnumerateTypesForTag");
	void* _UTEnumerateTypesForIdentifier = MSFindSymbol(coreServicesImage, "__UTEnumerateTypesForIdentifier");
	void* _UTTypeSearchConformingTypesWithBlock = MSFindSymbol(coreServicesImage, "__UTTypeSearchConformingTypesWithBlock");
	void* _UTTypeSearchConformsToTypesWithBlock = MSFindSymbol(coreServicesImage, "__UTTypeSearchConformsToTypesWithBlock");
	if(_LSSchemaCacheRead && _LSSchemaCacheWrite && _UTEnumerateTypesForTag && _UTEnumerateTypesForIdentifier && _UTTypeSearchConformingTypesWithBlock && _UTTypeSearchConformsToTypesWithBlock)
	{
		%init(UTTypeHooks,
			  _LSSchemaCacheRead=_LSSchemaCacheRead,
			  _LSSchemaCacheWrite=_LSSchemaCacheWrite,
			  _UTEnumerateTypesForTag=_UTEnumerateTypesForTag,
			  _UTEnumerateTypesForIdentifier=_UTEnumerateTypesForIdentifier,
			  _UTTypeSearchConformingTypesWithBlock=_UTTypeSearchConformingTypesWithBlock,
			  _UTTypeSearchConformsToTypesWithBlock=_UTTypeSearchConformsToTypesWithBlock);
	}
}
