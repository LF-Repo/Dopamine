#import "hide_global.h"
#import <Foundation/Foundation.h>
#import <libjailbreak/libjailbreak.h>
#import <libjailbreak/util.h>
#import <sys/stat.h>

// ---------------------------------------------------------------------------
// URL scheme hiding (ported from DOEnvironmentManager.m)
// ---------------------------------------------------------------------------

static NSString *findAppPathForBundleName(NSString *appName)
{
	NSFileManager *fm = [NSFileManager defaultManager];
	NSArray<NSString *> *roots = @[@"/var/containers/Bundle/Application", @"/Applications"];
	for (NSString *root in roots) {
		NSArray *uuids = [fm contentsOfDirectoryAtPath:root error:nil];
		for (NSString *uuid in uuids) {
			NSString *uuidPath = [root stringByAppendingPathComponent:uuid];
			NSArray *contents = [fm contentsOfDirectoryAtPath:uuidPath error:nil];
			for (NSString *item in contents) {
				if ([item isEqualToString:appName]) {
					NSString *fullPath = [uuidPath stringByAppendingPathComponent:item];
					BOOL isDir = NO;
					if ([fm fileExistsAtPath:fullPath isDirectory:&isDir] && isDir) {
						return fullPath;
					}
				}
			}
		}
	}
	return nil;
}

static BOOL hideURLScheme(NSString *scheme, NSString *appPath)
{
	NSString *infoPlistPath = [appPath stringByAppendingPathComponent:@"Info.plist"];
	NSFileManager *fm = [NSFileManager defaultManager];
	if (![fm fileExistsAtPath:infoPlistPath]) return NO;

	NSData *data = [NSData dataWithContentsOfFile:infoPlistPath];
	if (!data) return NO;

	id parsed = [NSPropertyListSerialization propertyListWithData:data
	                                                      options:NSPropertyListMutableContainersAndLeaves
	                                                       format:NULL
	                                                        error:nil];
	if (![parsed isKindOfClass:[NSMutableDictionary class]]) return NO;

	NSMutableDictionary *plist = (NSMutableDictionary *)parsed;
	BOOL modified = NO;

	NSArray *urlTypes = plist[@"CFBundleURLTypes"];
	if ([urlTypes isKindOfClass:[NSArray class]]) {
		NSMutableArray *newUrlTypes = [NSMutableArray array];
		for (NSDictionary *urlType in urlTypes) {
			NSArray *schemes = urlType[@"CFBundleURLSchemes"];
			if ([schemes isKindOfClass:[NSArray class]] && [schemes containsObject:scheme]) {
				NSMutableDictionary *newUrlType = [urlType mutableCopy];
				NSMutableArray *newSchemes = [schemes mutableCopy];
				[newSchemes removeObject:scheme];
				if (newSchemes.count > 0) {
					newUrlType[@"CFBundleURLSchemes"] = newSchemes;
					[newUrlTypes addObject:newUrlType];
				}
				modified = YES;
			} else {
				[newUrlTypes addObject:urlType];
			}
		}
		if (modified) plist[@"CFBundleURLTypes"] = newUrlTypes;
	}

	NSArray *queriesSchemes = plist[@"LSApplicationQueriesSchemes"];
	if ([queriesSchemes isKindOfClass:[NSArray class]] && [queriesSchemes containsObject:scheme]) {
		NSMutableArray *newQueries = [queriesSchemes mutableCopy];
		[newQueries removeObject:scheme];
		plist[@"LSApplicationQueriesSchemes"] = newQueries;
		modified = YES;
	}

	if (!modified) return NO;

	NSString *backupPath = [infoPlistPath stringByAppendingString:@".hideurl_backup"];
	if (![fm fileExistsAtPath:backupPath]) {
		if (![fm copyItemAtPath:infoPlistPath toPath:backupPath error:nil]) return NO;
	}

	NSData *outData = [NSPropertyListSerialization dataWithPropertyList:plist
	                                                             format:NSPropertyListXMLFormat_v1_0
	                                                            options:0
	                                                              error:nil];
	if (!outData) return NO;
	return [outData writeToFile:infoPlistPath options:NSDataWritingAtomic error:nil];
}

static void restoreURLSchemeForAppAtPath(NSString *appPath)
{
	NSString *infoPlistPath = [appPath stringByAppendingPathComponent:@"Info.plist"];
	NSString *backupPath = [infoPlistPath stringByAppendingString:@".hideurl_backup"];
	NSFileManager *fm = [NSFileManager defaultManager];
	if (![fm fileExistsAtPath:backupPath]) return;

	[fm removeItemAtPath:infoPlistPath error:nil];
	[fm copyItemAtPath:backupPath toPath:infoPlistPath error:nil];
	[fm removeItemAtPath:backupPath error:nil];
}

static void refreshURLSchemeApps(NSArray<NSString *> *appPaths)
{
	for (NSString *appPath in appPaths) {
		exec_cmd(JBROOT_PATH("/usr/bin/uicache"), "-p", appPath.fileSystemRepresentation, NULL);
	}
}

static void hideJailbreakURLSchemes(void)
{
	NSDictionary<NSString *, NSArray<NSString *> *> *targets = @{
		@"Reveil.app":    @[@"reveil", @"82flex"],
		@"PostBox.app":   @[@"postbox"],
		@"Santander.app": @[@"santander"],
		@"Cowabunga.app": @[@"cowabunga"],
		@"misaka.app":    @[@"misaka"],
	};

	NSMutableArray<NSString *> *touchedApps = [NSMutableArray array];
	for (NSString *appName in targets) {
		NSString *appPath = findAppPathForBundleName(appName);
		if (!appPath) continue;
		BOOL anyModified = NO;
		for (NSString *scheme in targets[appName]) {
			if (hideURLScheme(scheme, appPath)) anyModified = YES;
		}
		if (anyModified) [touchedApps addObject:appPath];
	}
	if (touchedApps.count > 0) refreshURLSchemeApps(touchedApps);
}

static void restoreJailbreakURLSchemes(void)
{
	NSArray<NSString *> *appNames = @[@"Reveil.app", @"PostBox.app", @"Santander.app", @"Cowabunga.app", @"Misaka.app"];
	NSMutableArray<NSString *> *touchedApps = [NSMutableArray array];
	for (NSString *appName in appNames) {
		NSString *appPath = findAppPathForBundleName(appName);
		if (!appPath) continue;
		NSString *backupPath = [[appPath stringByAppendingPathComponent:@"Info.plist"] stringByAppendingString:@".hideurl_backup"];
		if ([[NSFileManager defaultManager] fileExistsAtPath:backupPath]) {
			restoreURLSchemeForAppAtPath(appPath);
			[touchedApps addObject:appPath];
		}
	}
	if (touchedApps.count > 0) refreshURLSchemeApps(touchedApps);
}

// ---------------------------------------------------------------------------
// Jailbreak library audit / quarantine (ported from DOEnvironmentManager.m)
// ---------------------------------------------------------------------------

static NSString *hideQuarantineRoot(void)
{
	return @"/var/mobile/.DopamineHideQuarantine";
}

static NSString *hideMapPath(void)
{
	return [hideQuarantineRoot() stringByAppendingPathComponent:@"map.plist"];
}

static NSString *restoreInProgressPath(void)
{
	return [hideQuarantineRoot() stringByAppendingPathComponent:@".restore_in_progress"];
}

static void auditLog(NSString *msg)
{
	FILE *f = fopen("/var/mobile/audit_log.txt", "a");
	if (f) {
		fprintf(f, "%s\n", msg.UTF8String);
		fclose(f);
	}
}

// Write the quarantine map, appending in place.
//
// The map is the only record of where each quarantined file went, so it must
// survive losing a race with a concurrent writer and must never be replaced by a
// shorter copy. It used to be rewritten atomically from the array we had in
// memory, which is only safe if this process is the sole writer. Two hiders can
// overlap: a no-inject App spawned while a jailbreak App is launching triggers
// hide from both the spawn path and the resurrection path, and each rewrites the
// whole array. The slower writer then lands last and silently drops the other
// one's entries —their files are already moved, but nothing will ever move them
// back, which is exactly the "settings files gone after a restart" symptom.
//
// Reading the file fresh on every write and adding just the new entry makes the
// operation additive: an interleaved writer can still be overwritten for the
// *tail*, but never loses the head it already committed, and a lost tail is
// recoverable on the next pass because the source file is simply absent and the
// audit walk re-discovers it.
static NSMutableArray *readHideMap(void)
{
	NSArray *existing = [NSArray arrayWithContentsOfFile:hideMapPath()];
	return existing ? [existing mutableCopy] : [NSMutableArray array];
}

static void hideItemAtPath(NSString *src)
{
	NSFileManager *fm = [NSFileManager defaultManager];
	NSString *root = hideQuarantineRoot();
	[fm createDirectoryAtPath:root withIntermediateDirectories:YES attributes:nil error:nil];

	// Record the mapping BEFORE moving. The other order loses the file outright if
	// we die in between: the move would have succeeded but the map would not know
	// where the quarantined copy went, leaving an unnamed orphan under the
	// quarantine root that nothing can ever restore.
	//
	// Re-read the map rather than reusing a copy held in memory: another hider
	// may have added entries since, and overwriting the file with our stale copy
	// would strand every file that hider moved. See readHideMap() above.
	NSString *dst = [root stringByAppendingPathComponent:[NSUUID UUID].UUIDString];
	NSMutableArray *map = readHideMap();
	[map addObject:@{ @"src": src, @"dst": dst }];
	if (![map writeToFile:hideMapPath() atomically:YES]) {
		auditLog([NSString stringWithFormat:@"hide ABORTED (map write failed): %@", src]);
		return; // do not move: an unmapped move is unrecoverable
	}

	if (![fm moveItemAtPath:src toPath:dst error:nil]) {
		// Roll this entry back —and only this one —so restore doesn't try to
		// move a file that is still sitting in its original place. Read the map
		// fresh again: another hider may have appended since our write, and
		// rewriting from our in-memory copy would drop those entries.
		NSMutableArray *fresh = readHideMap();
		[fresh removeObject:@{ @"src": src, @"dst": dst }];
		[fresh writeToFile:hideMapPath() atomically:YES];
		auditLog([NSString stringWithFormat:@"hide FAILED: %@", src]);
		return;
	}

	auditLog([NSString stringWithFormat:@"hide ok: %@", src]);
}

// Modification date of a path, or 0 when it cannot be read.
static NSTimeInterval hideItemModified(NSString *path)
{
	NSError *error = nil;
	NSDate *date = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:&error].fileModificationDate;
	return date ? [date timeIntervalSince1970] : 0;
}

// Put a quarantined copy somewhere we can still recover it from, instead of
// letting it become an orphan under the quarantine root with no map entry.
static void preserveConflict(NSString *dst)
{
	if (![[NSFileManager defaultManager] fileExistsAtPath:dst]) return;

	NSString *conflictDir = [hideQuarantineRoot() stringByAppendingPathComponent:@"conflicts"];
	NSFileManager *fm = [NSFileManager defaultManager];
	[fm createDirectoryAtPath:conflictDir withIntermediateDirectories:YES attributes:nil error:nil];

	NSString *name = [dst lastPathComponent];
	NSString *kept = [conflictDir stringByAppendingPathComponent:name];
	// dst is a bare UUID, but never assume it: if something already landed there,
	// add a suffix instead of overwriting another conflict copy.
	for (int n = 1; [fm fileExistsAtPath:kept]; n++) {
		kept = [conflictDir stringByAppendingPathComponent:
		        [NSString stringWithFormat:@"%@.%d", name, n]];
	}
	if ([fm moveItemAtPath:dst toPath:kept error:nil]) {
		auditLog([NSString stringWithFormat:@"restore CONFLICT kept live copy, quarantined copy saved: %@", kept]);
	}
	else {
		auditLog([NSString stringWithFormat:@"restore CONFLICT FAILED to preserve quarantined copy: %@", dst]);
	}
}

static void restoreHiddenItems(void)
{
	NSFileManager *fm = [NSFileManager defaultManager];
	NSArray *map = [NSArray arrayWithContentsOfFile:hideMapPath()];
	if (!map || map.count == 0) return;

	// Mark that a restore is in progress before touching anything. If the
	// process dies mid-restore (reboot, logout, crash), the marker survives
	// and the next startup pass knows the quarantine was not fully drained,
	// so it must not report "restore complete" just because some entries
	// happen to be back already.
	[[NSData data] writeToFile:restoreInProgressPath() atomically:NO];

	for (NSDictionary *entry in [map reverseObjectEnumerator]) {
		NSString *src = entry[@"src"];
		NSString *dst = entry[@"dst"];
		if (!src || !dst) continue;

		if ([fm fileExistsAtPath:dst]) {
			if (![fm fileExistsAtPath:src]) {
				[fm createDirectoryAtPath:[src stringByDeletingLastPathComponent]
			      withIntermediateDirectories:YES
			                       attributes:nil
			                            error:nil];
				if ([fm moveItemAtPath:dst toPath:src error:nil]) {
					auditLog([NSString stringWithFormat:@"restore ok: %@", src]);
				}
				else {
					// Leave dst in place AND keep the map entry, so a later restore
					// pass can still find it. Dropping the map here would strand it.
					auditLog([NSString stringWithFormat:@"restore FAILED (kept in quarantine): %@", src]);
					return;
				}
				continue;
			}

			// Both exist. NoInject hides and restores repeatedly, so between two
			// passes cfprefsd (or the app itself) can recreate the file at its
			// original path. Silently preferring the live file lost whatever the
			// quarantine held, which is what made tweak settings go missing.
			// A rename preserves mtime, so comparing the two tells us which copy
			// actually has the newer settings.
			NSTimeInterval srcTime = hideItemModified(src);
			NSTimeInterval dstTime = hideItemModified(dst);

			if (dstTime > srcTime) {
				// The quarantined copy is newer: it holds writes the live file
				// never received. Preserve the live copy before replacing it so
				// nothing is destroyed either way.
				preserveConflict(src);
				[fm removeItemAtPath:src error:nil];
				if ([fm moveItemAtPath:dst toPath:src error:nil]) {
					auditLog([NSString stringWithFormat:@"restore ok (quarantined was newer): %@", src]);
				}
				else {
					auditLog([NSString stringWithFormat:@"restore FAILED (quarantined was newer): %@", src]);
					return;
				}
			}
			else {
				// The live copy is newer or equally new: keep it, but do not throw
				// the quarantined copy away unreferenced.
				preserveConflict(dst);
				auditLog([NSString stringWithFormat:@"restore ok (live copy was newer): %@", src]);
			}
			continue;
		}

		// Nothing at either end (already restored on a previous pass): idempotent.
	}

	// All entries processed: the map can be dropped and the in-progress marker
	// cleared. If we die before reaching here, the marker survives and tells
	// the next pass that this restore never finished.
	[fm removeItemAtPath:hideMapPath() error:nil];
	[fm removeItemAtPath:restoreInProgressPath() error:nil];
}

static BOOL doAuditName(NSString *name, NSArray<NSString *> *exact, NSArray<NSString *> *regex)
{
	if ([exact containsObject:name]) return YES;
	for (NSString *pattern in regex) {
		NSRegularExpression *expression = [NSRegularExpression regularExpressionWithPattern:pattern options:0 error:nil];
		if ([expression firstMatchInString:name options:0 range:NSMakeRange(0, name.length)]) return YES;
	}
	return NO;
}

static void runJailbreakLibraryAudit(void)
{
	NSFileManager *fm = [NSFileManager defaultManager];

	NSDictionary<NSString *, NSDictionary *> *rules = @{
		@"/var/mobile/Library": @{
			@"whitelist": @[@"Accessibility", @"CoreBrightness", @"Keyboard", @"Preferences", @"Voicemail", @"Accounts", @"CoreDuet", @"KeyboardServices", @"PrivacyAccounting", @"WatchConnectivity", @"AddressBook", @"CoreFollowUp", @"LASD", @"Recents", @"Weather", @"AggregateDictionary", @"CountryModeling", @"Reminders", @"WebClips", @"CrashReporter", @"Logs", @"ReplayKit", @"WebKit", @"Application Support", @"MediaRemote", @"Safari", @"Caches", @"SplashBoard", @"MobileInstallation", @"SoftwareUpdate", @"BulletinBoard", @"MobileContainerManager", @"TCC", @"Settings", @"Cookies", @"Passes", @"UserNotifications", @"ApplicationSync", @"DataDeliveryServices", @"MediaStream", @"SafeHarbor", @"Wallet", @"Maps", @"Phone"],
			@"blacklist": @[@"Sileo", @"Filza", @"Flex3", @"SBSettings", @"iCleaner", @"AppTools", @"RootHide", @"NiceiOS", @"Cydia"]
		},
		@"/var/mobile/Library/Preferences": @{
			@"default": @"blacklist",
			@"whitelistRegex": @[@"^com\\.apple\\.", @"^systemgroup\\.com\\.apple\\."],
			@"whitelist": @[@".GlobalPreferences.plist", @".GlobalPreferences_m.plist", @"bluetoothaudiod.plist", @"NetworkInterfaces.plist", @"OSThermalStatus.plist", @"preferences.plist", @"osanalyticshelper.plist", @"UserEventAgent.plist", @"wifid.plist", @"dprivacyd.plist", @"silhouette.plist", @"nfcd.plist", @"ptpcamerad.plist", @"mobile_storage_proxy.plist", @".DopamineAppHideRules.plist", @".DopamineInjectionRules.plist"],
			@"blacklist": @[@"com.roothide.manager.plist", @"com.opa334.Dopamine.roothide.plist", @"com.opa334.Dopamine.plist", @"com.tigisoftware.Filza.plist", @"com.xina.jailbreak.plist", @"org.coolstar.SileoStore.plist", @"ru.domo.cocoatop64.plist", @"ws.hbang.Terminal.plist", @"xyz.willy.Zebra.plist", @"com.apple.terminal.plist"]
		},
		@"/var/mobile/Library/Application Support": @{
			@"blacklist": @[@"xyz.willy.Zebra"]
		},
		@"/var/mobile/Library/Application Support/Containers": @{
			@"default": @"blacklist",
			@"blacklist": @[@"xyz.willy.Zebra", @"com.tigisoftware.Filza", @"org.coolstar.SileoStore", @"com.apple.Terminal"]
		},
		@"/var/mobile/Library/UserConfigurationProfiles/PublicInfo": @{
			@"blacklist": @[@"Flex3Patches.plist"]
		},
		@"/var/mobile/Library/SplashBoard/Snapshots": @{
			@"default": @"blacklist",
			@"whitelistRegex": @[@"^com\\.apple\\."],
			@"blacklist": @[@"com.roothide.manager", @"com.opa334.Dopamine.roothide", @"com.opa334.Dopamine", @"com.tigisoftware.Filza", @"org.coolstar.SileoStore", @"ru.domo.cocoatop64", @"ws.hbang.Terminal", @"xyz.willy.Zebra", @"com.apple.Terminal"]
		},
		@"/var/mobile/Library/Caches": @{
			@"default": @"blacklist",
			@"whitelistRegex": @[@"^com\\.apple\\.", @"^TelephonyUI-\\d+$", @"^FamilyMarquee.*Mode-.*\\.png$"],
			@"whitelist": @[@"CloudKit", @"GameKit", @"GeoServices", @"FamilyCircle", @"PassKit", @"VoiceServices", @"VoiceTrigger", @"Backup", @"ssu"],
			@"blacklist": @[@"com.opa334.Dopamine", @"com.tigisoftware.Filza", @"org.coolstar.SileoStore", @"ws.hbang.Terminal", @"xyz.willy.Zebra", @"Cephei", @"com.apple.Terminal", @"GDFileManagerCache.sqlite", @"GDFileManagerCache.sqlite-shm", @"GDFileManagerCache.sqlite-wal", @"ImageTables", @"SentryCrash", @"io.sentry", @"com.hackemist.SDImageCache"]
		},
		@"/var/mobile/Library/Saved Application State": @{
			@"default": @"blacklist",
			@"whitelistRegex": @[@"^com\\.apple\\."],
			@"blacklist": @[@"com.opa334.Dopamine.savedState", @"com.tigisoftware.Filza.savedState", @"org.coolstar.SileoStore.savedState", @"ws.hbang.Terminal.savedState", @"xyz.willy.Zebra.savedState", @"ru.domo.cocoatop64.savedState", @"com.apple.Terminal.savedState"]
		},
		@"/var/mobile/Library/WebKit": @{
			@"whitelist": @[@"Databases", @"LocalStorage"],
			@"whitelistRegex": @[@"^com\\.apple\\."],
			@"blacklist": @[@"xyz.willy.Zebra"]
		},
		@"/var/mobile/Library/Cookies": @{
			@"default": @"blacklist",
			@"whitelistRegex": @[@"^com\\.apple\\."],
			@"whitelist": @[@"Cookies.binarycookies"],
			@"blacklist": @[@"com.johncoates.Flex.binarycookies"]
		},
		@"/var/mobile/Library/HTTPStorages": @{
			@"default": @"blacklist",
			@"whitelistRegex": @[@"^com\\.apple\\."],
			@"blacklist": @[@"com.opa334.Dopamine", @"com.tigisoftware.Filza", @"org.coolstar.SileoStore", @"ws.hbang.Terminal", @"xyz.willy.Zebra"]
		},
		@"/var/mobile/Documents": @{
			@"blacklist": @[@"DumpDecrypter", @"Dumplpa", @"wiki.qaq.chromatic", @"TheosProject", @"DebBackup", @"Settings_Customizer", @"Background_Files", @"ProGestureConfigs", @"Saved_Fonts", @"Included_Audio", @"Saved_Operations", @"Saved_Locks", @"Anilaunch", @"AD-deb", @"Debra", @".Xinaf1re", @"PerfectDynamiclsland", @"Cowabunga_Audio", @".DynamicCowBackups", @".PlampyUIPro"]
		},
		@"/var/mobile": @{
			@"blacklist": @[@".DO-NOT-DELETE-Cowabunga", @".Derootifier", @"Helix", @".ssh", @".cache"]
		}
	};

	NSArray<NSString *> *paths = [rules.allKeys sortedArrayUsingSelector:@selector(compare:)];
	for (NSString *path in paths) {
		if (![fm fileExistsAtPath:path]) continue;
		NSDictionary *rule = rules[path];
		NSString *defaultAction = rule[@"default"];
		NSArray *whitelist = rule[@"whitelist"] ?: @[];
		NSArray *blacklist = rule[@"blacklist"] ?: @[];
		NSArray *whitelistRegex = rule[@"whitelistRegex"] ?: @[];
		NSArray<NSString *> *children = [fm contentsOfDirectoryAtPath:path error:nil];

		for (NSString *name in children) {
			BOOL white = doAuditName(name, whitelist, whitelistRegex);
			BOOL black = [blacklist containsObject:name];
			NSString *result = nil;
			if (black) result = @"BLACKLIST";
			else if (white) result = @"WHITELIST";
			else if (defaultAction) result = [defaultAction isEqualToString:@"blacklist"] ? @"DEFAULT-BLACKLIST" : @"DEFAULT-WHITELIST";
			else result = @"UNMATCHED";

			BOOL shouldHide = [result isEqualToString:@"BLACKLIST"] || [result isEqualToString:@"DEFAULT-BLACKLIST"];
			if (shouldHide) hideItemAtPath([path stringByAppendingPathComponent:name]);
		}
	}

	for (NSString *name in @[@".misaka"]) {
		NSString *fullPath = [@"/var/mobile/Documents" stringByAppendingPathComponent:name];
		if ([fm fileExistsAtPath:fullPath]) hideItemAtPath(fullPath);
	}
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

int hide_global_urlschemes_hide(void)
{
	@autoreleasepool { hideJailbreakURLSchemes(); }
	return 0;
}

int hide_global_urlschemes_show(void)
{
	@autoreleasepool { restoreJailbreakURLSchemes(); }
	return 0;
}

int hide_global_audit_hide(void)
{
	@autoreleasepool {
		auditLog(@"=== audit hide START ===");
		runJailbreakLibraryAudit();
		auditLog(@"=== audit hide END ===");
	}
	return 0;
}

int hide_global_audit_restore(void)
{
	@autoreleasepool {
		auditLog(@"=== audit restore START ===");
		restoreHiddenItems();
		auditLog(@"=== audit restore END ===");
	}
	return 0;
}

// Put back anything left over from a hide that never got to restore.
//
// A hide is a destructive operation: the files are moved to a quarantine root
// that nothing else knows about. Normally every path back is taken (the app
// exits, the watchdog notices, a no-inject app is killed), but a device reboot,
// a user logout or a launchd restart in the middle of a window leaves the
// quarantine populated with no map-driven caller left to drain it. The files
// then stay at their quarantine paths indefinitely and every tweak that reads
// them looks broken.
//
// This runs once at startup, before anything else needs those files, so the
// window is closed for good instead of depending on the previous session to have
// ended cleanly.
int hide_global_audit_recover(void)
{
	@autoreleasepool {
		NSFileManager *fm = [NSFileManager defaultManager];
		NSString *map = hideMapPath();
		if (![fm fileExistsAtPath:map]) return 0;

		NSArray *entries = [NSArray arrayWithContentsOfFile:map];
		if (!entries.count) {
			auditLog(@"=== audit recover: empty map, clearing ===");
			[fm removeItemAtPath:map error:nil];
			return 0;
		}

		auditLog([NSString stringWithFormat:@"=== audit recover: %lu leftover entr(ies) from a previous session ===",
		          (unsigned long)entries.count]);
		restoreHiddenItems();
		auditLog(@"=== audit recover END ===");
	}
	return 0;
}
