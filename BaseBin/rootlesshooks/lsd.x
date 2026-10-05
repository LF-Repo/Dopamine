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
		const char *uicachePath = JBROOT_PATH_CSTRING("/usr/bin/uicache");
		if (!access(uicachePath, F_OK)) {
			exec_cmd(uicachePath, "-a", NULL);
		}
	});

	return r;
}

// ---------------------------------------------------------------------------
// RootHide-style URL scheme hiding
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

%end

@interface _LSDOpenClient : NSObject
- (NSXPCConnection *)XPCConnection;
@end

%hook _LSDOpenClient

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

%end

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

// ===========================================================================
// UTType hiding + extension/plugin hiding
// ===========================================================================

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

static pid_t utrClientPid(id client)
{
	NSXPCConnection* conn = [client XPCConnection];
	return conn ? conn.processIdentifier : -1;
}

static BOOL utrHideClientBlacklisted(id client)
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

// ---------------------------------------------------------------------------
// C function hooks (via MSHookFunction)
// ---------------------------------------------------------------------------

typedef intptr_t (^UTREnumBlock)(intptr_t a2, intptr_t unitID, const void* unitBytes, void* a5);
typedef void (^UTRConformBlock)(intptr_t unitID, const void* unitBytes, intptr_t kind, unsigned char* outStop);

static void (*orig__UTEnumerateTypesForTag)(void* db, void* tagClass, void* tag, id block);
static void (*orig__UTEnumerateTypesForIdentifier)(void* db, long identStrId, id block);
static void (*orig__UTTypeSearchConformingTypesWithBlock)(void* db, long unitID, long flags, long arg4, id block);
static void (*orig__UTTypeSearchConformsToTypesWithBlock)(void* db, long unitID, long flags, long arg4, id block);
static void (*orig__LSSchemaCacheRead)(void* a1, id block);
static void (*orig__LSSchemaCacheWrite)(void* a1, id block);

static void hook__UTEnumerateTypesForTag(void* db, void* tagClass, void* tag, id block)
{
	if (!utrFilterActive() || !block) { orig__UTEnumerateTypesForTag(db, tagClass, tag, block); return; }
	UTREnumBlock origBlock = (UTREnumBlock)block;
	UTREnumBlock wrapper = ^intptr_t(intptr_t a2, intptr_t unitID, const void* unitBytes, void* a5) {
		if (utrUnitIsJailbreak(db, unitID)) return 0;
		return origBlock(a2, unitID, unitBytes, a5);
	};
	orig__UTEnumerateTypesForTag(db, tagClass, tag, wrapper);
}

static void hook__UTEnumerateTypesForIdentifier(void* db, long identStrId, id block)
{
	if (!utrFilterActive() || !block) { orig__UTEnumerateTypesForIdentifier(db, identStrId, block); return; }
	UTREnumBlock origBlock = (UTREnumBlock)block;
	UTREnumBlock wrapper = ^intptr_t(intptr_t a2, intptr_t unitID, const void* unitBytes, void* a5) {
		if (utrUnitIsJailbreak(db, unitID)) return 0;
		return origBlock(a2, unitID, unitBytes, a5);
	};
	orig__UTEnumerateTypesForIdentifier(db, identStrId, wrapper);
}

static void hook__UTTypeSearchConformingTypesWithBlock(void* db, long unitID, long flags, long arg4, id block)
{
	if (!utrFilterActive() || !block) { orig__UTTypeSearchConformingTypesWithBlock(db, unitID, flags, arg4, block); return; }
	UTRConformBlock origBlock = (UTRConformBlock)block;
	UTRConformBlock wrapper = ^void(intptr_t uid, const void* unitBytes, intptr_t kind, unsigned char* outStop) {
		if (utrUnitIsJailbreak(db, uid)) return;
		origBlock(uid, unitBytes, kind, outStop);
	};
	orig__UTTypeSearchConformingTypesWithBlock(db, unitID, flags, arg4, wrapper);
}

static void hook__UTTypeSearchConformsToTypesWithBlock(void* db, long unitID, long flags, long arg4, id block)
{
	if (!utrFilterActive() || !block) { orig__UTTypeSearchConformsToTypesWithBlock(db, unitID, flags, arg4, block); return; }
	UTRConformBlock origBlock = (UTRConformBlock)block;
	UTRConformBlock wrapper = ^void(intptr_t uid, const void* unitBytes, intptr_t kind, unsigned char* outStop) {
		if (utrUnitIsJailbreak(db, uid)) return;
		origBlock(uid, unitBytes, kind, outStop);
	};
	orig__UTTypeSearchConformsToTypesWithBlock(db, unitID, flags, arg4, wrapper);
}

static void hook__LSSchemaCacheRead(void* a1, id block)
{
	if (utrFilterActive()) return;
	orig__LSSchemaCacheRead(a1, block);
}

static void hook__LSSchemaCacheWrite(void* a1, id block)
{
	if (utrFilterActive()) return;
	orig__LSSchemaCacheWrite(a1, block);
}

// ---------------------------------------------------------------------------
// _LSDReadClient hooks (via MSHookMessageEx — 不经过 Logos 展开)
// ---------------------------------------------------------------------------

static void (*orig_lsd_getTypeRecordWithTag)(id self, SEL _cmd, id tag, id klass, id identifier, void(^handler)(id));
static void (*orig_lsd_getTypeRecordsWithTag)(id self, SEL _cmd, id tag, id klass, id identifier, void(^handler)(id));
static void (*orig_lsd_getTypeRecordWithIdentifier)(id self, SEL _cmd, id identifier, BOOL allowUndeclared, void(^handler)(id));
static void (*orig_lsd_getTypeRecordsWithIdentifiers)(id self, SEL _cmd, id identifiers, void(^handler)(id));
static void (*orig_lsd_getTypeRecordForImportedTypeWithIdentifier)(id self, SEL _cmd, id identifier, id conforming, void(^handler)(id));
static void (*orig_lsd_getRelatedTypesOfTypeWithIdentifier)(id self, SEL _cmd, id identifier, NSInteger degree, void(^handler)(id, id));
static void (*orig_lsd_getWhetherTypeIdentifier)(id self, SEL _cmd, id identifier, id other, void(^handler)(id));
static void (*orig_lsd_getResourceValuesForKeys)(id self, SEL _cmd, id keys, id url, id locs, void(^handler)(id, id, id));
static void (*orig_lsd_getBoundIconInfoForDocumentProxy)(id self, SEL _cmd, id documentProxy, void(^handler)(id, id));

static void hook_lsd_getTypeRecordWithTag(id self, SEL _cmd, id tag, id klass, id identifier, void(^handler)(id))
{
	if (!utrHideClientBlacklisted(self)) { orig_lsd_getTypeRecordWithTag(self, _cmd, tag, klass, identifier, handler); return; }
	g_utrHide = YES; orig_lsd_getTypeRecordWithTag(self, _cmd, tag, klass, identifier, handler); g_utrHide = NO;
}
static void hook_lsd_getTypeRecordsWithTag(id self, SEL _cmd, id tag, id klass, id identifier, void(^handler)(id))
{
	if (!utrHideClientBlacklisted(self)) { orig_lsd_getTypeRecordsWithTag(self, _cmd, tag, klass, identifier, handler); return; }
	g_utrHide = YES; orig_lsd_getTypeRecordsWithTag(self, _cmd, tag, klass, identifier, handler); g_utrHide = NO;
}
static void hook_lsd_getTypeRecordWithIdentifier(id self, SEL _cmd, id identifier, BOOL allowUndeclared, void(^handler)(id))
{
	if (!utrHideClientBlacklisted(self)) { orig_lsd_getTypeRecordWithIdentifier(self, _cmd, identifier, allowUndeclared, handler); return; }
	g_utrHide = YES; orig_lsd_getTypeRecordWithIdentifier(self, _cmd, identifier, allowUndeclared, handler); g_utrHide = NO;
}
static void hook_lsd_getTypeRecordsWithIdentifiers(id self, SEL _cmd, id identifiers, void(^handler)(id))
{
	if (!utrHideClientBlacklisted(self)) { orig_lsd_getTypeRecordsWithIdentifiers(self, _cmd, identifiers, handler); return; }
	g_utrHide = YES; orig_lsd_getTypeRecordsWithIdentifiers(self, _cmd, identifiers, handler); g_utrHide = NO;
}
static void hook_lsd_getTypeRecordForImportedTypeWithIdentifier(id self, SEL _cmd, id identifier, id conforming, void(^handler)(id))
{
	if (!utrHideClientBlacklisted(self)) { orig_lsd_getTypeRecordForImportedTypeWithIdentifier(self, _cmd, identifier, conforming, handler); return; }
	g_utrHide = YES; orig_lsd_getTypeRecordForImportedTypeWithIdentifier(self, _cmd, identifier, conforming, handler); g_utrHide = NO;
}
static void hook_lsd_getRelatedTypesOfTypeWithIdentifier(id self, SEL _cmd, id identifier, NSInteger degree, void(^handler)(id, id))
{
	if (!utrHideClientBlacklisted(self)) { orig_lsd_getRelatedTypesOfTypeWithIdentifier(self, _cmd, identifier, degree, handler); return; }
	g_utrHide = YES; orig_lsd_getRelatedTypesOfTypeWithIdentifier(self, _cmd, identifier, degree, handler); g_utrHide = NO;
}
static void hook_lsd_getWhetherTypeIdentifier(id self, SEL _cmd, id identifier, id other, void(^handler)(id))
{
	if (!utrHideClientBlacklisted(self)) { orig_lsd_getWhetherTypeIdentifier(self, _cmd, identifier, other, handler); return; }
	g_utrHide = YES; orig_lsd_getWhetherTypeIdentifier(self, _cmd, identifier, other, handler); g_utrHide = NO;
}
static void hook_lsd_getResourceValuesForKeys(id self, SEL _cmd, id keys, id url, id locs, void(^handler)(id, id, id))
{
	if (!utrHideClientBlacklisted(self)) { orig_lsd_getResourceValuesForKeys(self, _cmd, keys, url, locs, handler); return; }
	g_utrHide = YES; orig_lsd_getResourceValuesForKeys(self, _cmd, keys, url, locs, handler); g_utrHide = NO;
}
static void hook_lsd_getBoundIconInfoForDocumentProxy(id self, SEL _cmd, id documentProxy, void(^handler)(id, id))
{
	if (!utrHideClientBlacklisted(self)) { orig_lsd_getBoundIconInfoForDocumentProxy(self, _cmd, documentProxy, handler); return; }
	g_utrHide = YES; orig_lsd_getBoundIconInfoForDocumentProxy(self, _cmd, documentProxy, handler); g_utrHide = NO;
}

// ---------------------------------------------------------------------------
// _LSQueryContext (plugin/extension hiding) — 无 block 参数，Logos 可处理
// ---------------------------------------------------------------------------

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

	// ObjC hooks via Logos（不带 block 参数的类）
	%init(_LSGetInboxURLForBundleIdentifier = MSFindSymbol(coreServicesImage, "__LSGetInboxURLForBundleIdentifier"),
		  _LSServer_RebuildApplicationDatabases = MSFindSymbol(coreServicesImage, "__LSServer_RebuildApplicationDatabases"),
		  _LSCanOpenURLManager = objc_getClass("_LSCanOpenURLManager"),
		  _LSDOpenClient = objc_getClass("_LSDOpenClient"),
		  _LSURLOverride = objc_getClass("_LSURLOverride"),
		  _LSQueryContext = objc_getClass("_LSQueryContext"));

	// _LSDReadClient：手动 MSHookMessageEx 安装（避免 Logos 展开 block 参数出错）
	Class lsdReadClient = objc_getClass("_LSDReadClient");
	if (lsdReadClient) {
		MSHookMessageEx(lsdReadClient, @selector(getTypeRecordWithTag:ofClass:conformingToIdentifier:completionHandler:),
			(IMP)hook_lsd_getTypeRecordWithTag, (IMP*)&orig_lsd_getTypeRecordWithTag);
		MSHookMessageEx(lsdReadClient, @selector(getTypeRecordsWithTag:ofClass:conformingToIdentifier:completionHandler:),
			(IMP)hook_lsd_getTypeRecordsWithTag, (IMP*)&orig_lsd_getTypeRecordsWithTag);
		MSHookMessageEx(lsdReadClient, @selector(getTypeRecordWithIdentifier:allowUndeclared:completionHandler:),
			(IMP)hook_lsd_getTypeRecordWithIdentifier, (IMP*)&orig_lsd_getTypeRecordWithIdentifier);
		MSHookMessageEx(lsdReadClient, @selector(getTypeRecordsWithIdentifiers:completionHandler:),
			(IMP)hook_lsd_getTypeRecordsWithIdentifiers, (IMP*)&orig_lsd_getTypeRecordsWithIdentifiers);
		MSHookMessageEx(lsdReadClient, @selector(getTypeRecordForImportedTypeWithIdentifier:conformingToIdentifier:completionHandler:),
			(IMP)hook_lsd_getTypeRecordForImportedTypeWithIdentifier, (IMP*)&orig_lsd_getTypeRecordForImportedTypeWithIdentifier);
		MSHookMessageEx(lsdReadClient, @selector(getRelatedTypesOfTypeWithIdentifier:maximumDegreeOfSeparation:completionHandler:),
			(IMP)hook_lsd_getRelatedTypesOfTypeWithIdentifier, (IMP*)&orig_lsd_getRelatedTypesOfTypeWithIdentifier);
		MSHookMessageEx(lsdReadClient, @selector(getWhetherTypeIdentifier:conformsToTypeIdentifier:completionHandler:),
			(IMP)hook_lsd_getWhetherTypeIdentifier, (IMP*)&orig_lsd_getWhetherTypeIdentifier);
		MSHookMessageEx(lsdReadClient, @selector(getResourceValuesForKeys:URL:preferredLocalizations:completionHandler:),
			(IMP)hook_lsd_getResourceValuesForKeys, (IMP*)&orig_lsd_getResourceValuesForKeys);
		MSHookMessageEx(lsdReadClient, @selector(getBoundIconInfoForDocumentProxy:completionHandler:),
			(IMP)hook_lsd_getBoundIconInfoForDocumentProxy, (IMP*)&orig_lsd_getBoundIconInfoForDocumentProxy);
	}

	// C 函数 hooks
	void* _LSSchemaCacheRead = MSFindSymbol(coreServicesImage, "__LSSchemaCacheRead");
	void* _LSSchemaCacheWrite = MSFindSymbol(coreServicesImage, "__LSSchemaCacheWrite");
	void* _UTEnumerateTypesForTag = MSFindSymbol(coreServicesImage, "__UTEnumerateTypesForTag");
	void* _UTEnumerateTypesForIdentifier = MSFindSymbol(coreServicesImage, "__UTEnumerateTypesForIdentifier");
	void* _UTTypeSearchConformingTypesWithBlock = MSFindSymbol(coreServicesImage, "__UTTypeSearchConformingTypesWithBlock");
	void* _UTTypeSearchConformsToTypesWithBlock = MSFindSymbol(coreServicesImage, "__UTTypeSearchConformsToTypesWithBlock");

	if (_LSSchemaCacheRead)  MSHookFunction(_LSSchemaCacheRead,  (void*)hook__LSSchemaCacheRead,  (void**)&orig__LSSchemaCacheRead);
	if (_LSSchemaCacheWrite) MSHookFunction(_LSSchemaCacheWrite, (void*)hook__LSSchemaCacheWrite, (void**)&orig__LSSchemaCacheWrite);
	if (_UTEnumerateTypesForTag) MSHookFunction(_UTEnumerateTypesForTag, (void*)hook__UTEnumerateTypesForTag, (void**)&orig__UTEnumerateTypesForTag);
	if (_UTEnumerateTypesForIdentifier) MSHookFunction(_UTEnumerateTypesForIdentifier, (void*)hook__UTEnumerateTypesForIdentifier, (void**)&orig__UTEnumerateTypesForIdentifier);
	if (_UTTypeSearchConformingTypesWithBlock) MSHookFunction(_UTTypeSearchConformingTypesWithBlock, (void*)hook__UTTypeSearchConformingTypesWithBlock, (void**)&orig__UTTypeSearchConformingTypesWithBlock);
	if (_UTTypeSearchConformsToTypesWithBlock) MSHookFunction(_UTTypeSearchConformsToTypesWithBlock, (void*)hook__UTTypeSearchConformsToTypesWithBlock, (void**)&orig__UTTypeSearchConformsToTypesWithBlock);
}