#import <Foundation/Foundation.h>
#import <substrate.h>
#import <objc/objc.h>
#import <objc/runtime.h>
#import <libjailbreak/jbclient_xpc.h>
#import <libroot.h>

@interface XBSnapshotContainerIdentity : NSObject
@property (nonatomic, readonly, copy) NSString *bundleIdentifier;
@property (nonatomic, readonly, copy) NSString *snapshotContainerPath;
@end

@interface XBApplicationSnapshot : NSObject
- (XBSnapshotContainerIdentity *)containerIdentity;
- (NSString *)_configureDefaultPathWithinGroupForFormat:(long long)format;
@end

@interface XBApplicationSnapshotManifestImpl : NSObject
+ (long long)_outputFormatForSnapshot:(id)snapshot;
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

%hook XBApplicationSnapshotManifestImpl

- (BOOL)_imageAccessQueue_saveData:(NSData *)data forSnapshot:(XBApplicationSnapshot *)snapshot
{
    if (!data.length || !snapshot) {
        return %orig;
    }

    XBSnapshotContainerIdentity *ident = snapshot.containerIdentity;
    if ([ident.bundleIdentifier hasPrefix:@"com.apple."] || ![ident.snapshotContainerPath hasPrefix:JBROOT_PATH_NSSTRING(@"/var/mobile/Library/SplashBoard/Snapshots/")]) {
        return %orig;
    }

    NSString *path = [snapshot _configureDefaultPathWithinGroupForFormat:[[self class] _outputFormatForSnapshot:snapshot]];
    if (!path) {
        return NO;
    }
    
    [[NSFileManager defaultManager] createDirectoryAtPath:path.stringByDeletingLastPathComponent
                              withIntermediateDirectories:YES attributes:nil error:nil];
    return [data writeToFile:path options:0 error:nil];
}

%end


// ---- Hide Manager: keep hidden apps out of SpringBoard queries ----
// When a hidden app asks SpringBoard to open or describe another app, the
// jailbreak must not reveal that bundle. FBSystemService records the requesting
// (hidden) pid against the bundle id, and FBSApplicationLibrary then refuses to
// describe a jailbreak-path bundle to that same requester.
//
// A bundle belongs to the jailbreak when it lives under /var/jb or the resolved
// preboot procursus root.
static bool isJailbreakBundlePath(const char *path)
{
	if (!path) return false;
	if (strncmp(path, "/var/jb/", 8) == 0) return true;
	if (strstr(path, "/procursus/")) return true;
	return false;
}

static const void *kDenyQueryTagKey = &kDenyQueryTagKey;

%hook FBSApplicationLibrary
- (id)applicationInfoForBundleIdentifier:(NSString *)bundleIdentifier
{
	id result = %orig;
	NSNumber *tag = objc_getAssociatedObject(bundleIdentifier, kDenyQueryTagKey);
	if (tag && tag.boolValue) {
		NSURL *executableURL = [result performSelector:@selector(executableURL)];
		if (result && executableURL && isJailbreakBundlePath(executableURL.path.fileSystemRepresentation)) {
			return nil;
		}
	}
	return result;
}
%end

%hook FBSystemService
- (void *)openApplication:(NSString *)bundleIdentifier withOptions:(id)options originator:(id)originator requestID:(void *)requestID completion:(void *)completion
{
	id currentContext = [NSClassFromString(@"BSServiceConnection") performSelector:@selector(currentContext)];
	id remoteProcess = [currentContext performSelector:@selector(remoteProcess)];
	NSNumber *_pid = [remoteProcess valueForKey:@"_pid"];
	pid_t pid = _pid.intValue;

	if (jbclient_blacklist_check_pid(pid)) {
		objc_setAssociatedObject(bundleIdentifier, kDenyQueryTagKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
	}

	return %orig;
}
%end

void springboardInit(void)
{
    %init();
}
