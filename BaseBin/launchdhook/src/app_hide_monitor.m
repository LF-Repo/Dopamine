#import <Foundation/Foundation.h>
#include <libproc.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <spawn.h>

#import <libjailbreak/jbroot.h>
#import <libjailbreak/info.h>
#import <libjailbreak/util.h>
#import "jbserver/jbserver_local.h"


extern int proc_listallpids(void *buffer, int buffersize);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffersize);
extern void systemwide_domain_set_enabled(bool enabled);
extern char **environ;

#define APP_HIDE_RULES_PATH    "/var/mobile/Library/Preferences/.DopamineAppHideRules.plist"
#define APP_HIDE_LOG_PATH      "/var/mobile/Documents/DopamineAppHide.log"
#define APP_HIDE_LOG_MAX_SIZE  (512 * 1024)
#define HIDE_QUARANTINE        "/var/mobile/.DopamineHideQuarantine"
#define HIDE_MAP_PATH          HIDE_QUARANTINE "/map.plist"
#define MONITOR_HIDE_MARKER    "/var/mobile/.DopamineMonitorDidHide"

#pragma mark - 日志

static void hide_log(NSString *format, ...)
{
    va_list args;
    va_start(args, format);
    NSString *msg = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);

    NSLog(@"[AppHideMonitor] %@", msg);

    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    char timebuf[16];
    strftime(timebuf, sizeof(timebuf), "%H:%M:%S", &tm);

    FILE *fp = fopen(APP_HIDE_LOG_PATH, "a");
    if (!fp) return;
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    if (size > APP_HIDE_LOG_MAX_SIZE) {
        fclose(fp);
        fp = fopen(APP_HIDE_LOG_PATH, "w");
        if (!fp) return;
    }
    fprintf(fp, "[%s] %s\n", timebuf, msg.UTF8String);
    fclose(fp);
}

#pragma mark - 进程扫描

static NSArray<NSString *> *target_bundle_ids(void)
{
    NSDictionary *rules = [NSDictionary dictionaryWithContentsOfFile:@APP_HIDE_RULES_PATH];
    NSMutableArray *result = [NSMutableArray array];
    for (NSString *bid in rules) {
        if ([rules[bid][@"HideEnvironment"] boolValue]) [result addObject:bid];
    }
    return result;
}

static NSString *bundle_id_for_pid(pid_t pid)
{
    char pathbuf[4096];
    if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) <= 0) return nil;

    NSString *path = [NSString stringWithUTF8String:pathbuf];
    NSRange appRange = [path rangeOfString:@".app/"];
    if (appRange.location == NSNotFound) return nil;

    NSString *appPath = [path substringToIndex:appRange.location + 4];
    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
        [appPath stringByAppendingPathComponent:@"Info.plist"]];
    return info[@"CFBundleIdentifier"];
}

static NSArray<NSString *> *running_bundle_ids(void)
{
    int count = proc_listallpids(NULL, 0);
    if (count <= 0) return @[];

    pid_t *pids = malloc(sizeof(pid_t) * (count + 16));
    int actual = proc_listallpids(pids, sizeof(pid_t) * (count + 16));
    NSMutableArray *result = [NSMutableArray array];

    for (int i = 0; i < actual; i++) {
        NSString *bid = bundle_id_for_pid(pids[i]);
        if (bid && ![result containsObject:bid]) [result addObject:bid];
    }
    free(pids);
    return result;
}

static BOOL any_target_running(void)
{
    NSArray *targets = target_bundle_ids();
    if (targets.count == 0) return NO;
    NSArray *running = running_bundle_ids();
    for (NSString *bid in running) {
        if ([targets containsObject:bid]) return YES;
    }
    return NO;
}

#pragma mark - 隔离区工具

static NSString *jbroot_str(void)
{
    // 优先从 gSystemInfo 拿（launchdhook initializer 里已设置）
    if (gSystemInfo.jailbreakInfo.rootPath) {
        NSString *path = [NSString stringWithUTF8String:gSystemInfo.jailbreakInfo.rootPath];
        if (path.length > 0 && !access(path.fileSystemRepresentation, F_OK)) {
            return path;
        }
    }
    // 回退到 jbclient
    const char *p = jbclient_get_jbroot();
    if (p && access(p, F_OK) == 0) {
        return [NSString stringWithUTF8String:p];
    }
    return nil;
}

static NSString *map_path(void)
{
    return @HIDE_MAP_PATH;
}

static NSMutableArray *load_map(void)
{
    NSArray *arr = [NSArray arrayWithContentsOfFile:map_path()];
    return arr ? [arr mutableCopy] : [NSMutableArray array];
}

static void save_map(NSArray *map)
{
    [map writeToFile:map_path() atomically:YES];
}

static void hide_item(NSString *src)
{
    NSFileManager *fm = [NSFileManager defaultManager];
    [[NSFileManager defaultManager] createDirectoryAtPath:@HIDE_QUARANTINE
                             withIntermediateDirectories:YES attributes:nil error:nil];

    if (![fm fileExistsAtPath:src]) return;

    NSString *dst = [@HIDE_QUARANTINE stringByAppendingPathComponent:[NSUUID UUID].UUIDString];
    NSError *err = nil;
    if (![fm moveItemAtPath:src toPath:dst error:&err]) {
        hide_log(@"hide failed: %@ (%@)", src, err.localizedDescription);
        return;
    }
    NSMutableArray *map = load_map();
    [map addObject:@{@"src": src, @"dst": dst}];
    save_map(map);
}

static void restore_items(void)
{
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *map = load_map();
    for (NSDictionary *entry in [map reverseObjectEnumerator]) {
        NSString *src = entry[@"src"];
        NSString *dst = entry[@"dst"];
        if (!src || !dst) continue;
        if ([fm fileExistsAtPath:src]) continue;
        [fm createDirectoryAtPath:[src stringByDeletingLastPathComponent]
      withIntermediateDirectories:YES attributes:nil error:nil];
        [fm moveItemAtPath:dst toPath:src error:nil];
    }
    [fm removeItemAtPath:map_path() error:nil];
}

#pragma mark - jbctl / exec_cmd

static int exec_cmd_wrapper(const char *path, const char *arg1, const char *arg2, const char *arg3)
{
    pid_t pid;
    const char *argv[] = {path, arg1, arg2, arg3, NULL};
    int idx = 1;
    while (argv[idx]) idx++;
    // 去掉 NULL 之后的参数
    return posix_spawn(&pid, path, NULL, NULL, (char *const *)argv, environ);
}

static void run_jbctl_internal(const char *cmd1, const char *cmd2)
{
    mach_port_t port = jbserver_local_start();
    jbctl_earlyboot(port, "internal", cmd1, cmd2, NULL);
    jbserver_local_stop();
}

#pragma mark - URL Scheme 隐藏

static BOOL hide_url_scheme(NSString *scheme, NSString *appPath)
{
    NSString *infoPath = [appPath stringByAppendingPathComponent:@"Info.plist"];
    NSFileManager *fm = [NSFileManager defaultManager];

    NSData *data = [NSData dataWithContentsOfFile:infoPath];
    if (!data) return NO;

    NSMutableDictionary *plist = [NSPropertyListSerialization
        propertyListWithData:data options:NSPropertyListMutableContainersAndLeaves
        format:NULL error:nil];
    if (!plist) return NO;

    BOOL modified = NO;

    NSArray *urlTypes = plist[@"CFBundleURLTypes"];
    if ([urlTypes isKindOfClass:[NSArray class]]) {
        NSMutableArray *newTypes = [NSMutableArray array];
        for (NSDictionary *t in urlTypes) {
            NSArray *schemes = t[@"CFBundleURLSchemes"];
            if ([schemes containsObject:scheme]) {
                NSMutableDictionary *nt = [t mutableCopy];
                NSMutableArray *ns = [schemes mutableCopy];
                [ns removeObject:scheme];
                if (ns.count) {
                    nt[@"CFBundleURLSchemes"] = ns;
                    [newTypes addObject:nt];
                }
                modified = YES;
            } else {
                [newTypes addObject:t];
            }
        }
        if (modified) plist[@"CFBundleURLTypes"] = newTypes;
    }

    if (!modified) return NO;

    NSString *backupPath = [infoPath stringByAppendingString:@".hideurl_backup"];
    if (![fm fileExistsAtPath:backupPath]) {
        [fm copyItemAtPath:infoPath toPath:backupPath error:nil];
    }

    NSData *out = [NSPropertyListSerialization dataWithPropertyList:plist
        format:NSPropertyListXMLFormat_v1_0 options:0 error:nil];
    [out writeToFile:infoPath atomically:YES];

    hide_log(@"hide URL scheme '%@' in %@", scheme, appPath);
    return YES;
}

static NSString *find_app_path(NSString *appName)
{
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *roots = @[@"/var/containers/Bundle/Application", @"/Applications"];

    for (NSString *root in roots) {
        for (NSString *uuid in [fm contentsOfDirectoryAtPath:root error:nil]) {
            NSString *uuidPath = [root stringByAppendingPathComponent:uuid];
            for (NSString *item in [fm contentsOfDirectoryAtPath:uuidPath error:nil]) {
                if ([item isEqualToString:appName]) {
                    NSString *full = [uuidPath stringByAppendingPathComponent:item];
                    BOOL isDir = NO;
                    if ([fm fileExistsAtPath:full isDirectory:&isDir] && isDir) return full;
                }
            }
        }
    }
    return nil;
}

static void hide_all_url_schemes(void)
{
    NSDictionary *targets = @{
        @"Reveil.app":    @[@"reveil", @"82flex"],
        @"PostBox.app":   @[@"postbox"],
        @"Santander.app": @[@"santander"],
        @"Cowabunga.app": @[@"cowabunga"],
        @"misaka.app":    @[@"misaka"],
    };

    for (NSString *appName in targets) {
        NSString *appPath = find_app_path(appName);
        if (!appPath) continue;
        for (NSString *scheme in targets[appName]) {
            hide_url_scheme(scheme, appPath);
        }
    }
}

static void restore_all_url_schemes(void)
{
    NSArray *apps = @[@"Reveil.app", @"PostBox.app", @"Santander.app",
                      @"Cowabunga.app", @"misaka.app"];
    for (NSString *appName in apps) {
        NSString *appPath = find_app_path(appName);
        if (!appPath) continue;
        NSString *infoPath = [appPath stringByAppendingPathComponent:@"Info.plist"];
        NSString *backup = [infoPath stringByAppendingString:@".hideurl_backup"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:backup]) {
            [[NSFileManager defaultManager] removeItemAtPath:infoPath error:nil];
            [[NSFileManager defaultManager] copyItemAtPath:backup toPath:infoPath error:nil];
            [[NSFileManager defaultManager] removeItemAtPath:backup error:nil];
        }
    }
}

#pragma mark - Library Audit

static BOOL audit_name_matches(NSString *name, NSArray *exact, NSArray *regex)
{
    if ([exact containsObject:name]) return YES;
    for (NSString *pattern in regex) {
        NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:pattern options:0 error:nil];
        if ([re firstMatchInString:name options:0 range:NSMakeRange(0, name.length)]) return YES;
    }
    return NO;
}

static void run_library_audit(void)
{
    NSDictionary *rules = @{
        @"/var/mobile/Library": @{
            @"whitelist": @[@"Accessibility", @"CoreBrightness", @"Keyboard", @"Preferences", @"Voicemail", @"Accounts", @"CoreDuet", @"KeyboardServices", @"PrivacyAccounting", @"WatchConnectivity", @"AddressBook", @"CoreFollowUp", @"LASD", @"Recents", @"Weather", @"AggregateDictionary", @"CountryModeling", @"Reminders", @"WebClips", @"CrashReporter", @"Logs", @"ReplayKit", @"WebKit", @"Application Support", @"MediaRemote", @"Safari", @"Caches", @"SplashBoard", @"MobileInstallation", @"SoftwareUpdate", @"BulletinBoard", @"MobileContainerManager", @"TCC", @"Settings", @"Cookies", @"Passes", @"UserNotifications", @"ApplicationSync", @"DataDeliveryServices", @"MediaStream", @"SafeHarbor", @"Wallet", @"Maps", @"Phone"],
            @"blacklist": @[@"Sileo", @"Filza", @"Flex3", @"SBSettings", @"iCleaner"]
        },
        @"/var/mobile/Library/Preferences": @{
            @"default": @"blacklist",
            @"whitelistRegex": @[@"^com\\.apple\\.", @"^systemgroup\\.com\\.apple\\."],
            @"whitelist": @[@".GlobalPreferences.plist", @".GlobalPreferences_m.plist", @"bluetoothaudiod.plist", @"NetworkInterfaces.plist", @"OSThermalStatus.plist", @"preferences.plist", @"osanalyticshelper.plist", @"UserEventAgent.plist", @"wifid.plist", @"dprivacyd.plist", @"silhouette.plist", @"nfcd.plist", @"ptpcamerad.plist", @"mobile_storage_proxy.plist"],
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
            @"blacklist": @[@"DumpDecrypter", @"Dumplpa"]
        },
        @"/var/mobile": @{
            @"blacklist": @[@".DO-NOT-DELETE-Cowabunga", @".Derootifier", @"Helix", @".ssh", @".cache"]
        }
    };

    NSFileManager *fm = [NSFileManager defaultManager];

    for (NSString *path in rules) {
        if (![fm fileExistsAtPath:path]) continue;
        NSDictionary *rule = rules[path];
        NSString *defaultAction = rule[@"default"];
        NSArray *whitelist = rule[@"whitelist"] ?: @[];
        NSArray *blacklist = rule[@"blacklist"] ?: @[];
        NSArray *whitelistRegex = rule[@"whitelistRegex"] ?: @[];

        for (NSString *name in [fm contentsOfDirectoryAtPath:path error:nil]) {
            BOOL white = audit_name_matches(name, whitelist, whitelistRegex);
            BOOL black = [blacklist containsObject:name];
            NSString *result;
            if (black) result = @"BLACKLIST";
            else if (white) result = @"WHITELIST";
            else if (defaultAction) result = [defaultAction isEqualToString:@"blacklist"] ? @"DEFAULT-BLACKLIST" : @"DEFAULT-WHITELIST";
            else result = @"UNMATCHED";

            if ([result isEqualToString:@"BLACKLIST"] || [result isEqualToString:@"DEFAULT-BLACKLIST"]) {
                hide_item([path stringByAppendingPathComponent:name]);
            }
        }
    }

    // Documents/.misaka
    NSString *misaka = @"/var/mobile/Documents/.misaka";
    if ([fm fileExistsAtPath:misaka]) hide_item(misaka);
}

#pragma mark - Hide / Unhide

static void perform_hide(void)
{
    hide_log(@"perform_hide begin");

    NSString *jbroot = jbroot_str();
    if (!jbroot) {
        hide_log(@"jbroot missing, abort");
        return;
    }

    // 1. crash reporter 禁用标记
    FILE *fp = fopen("/var/mobile/.DopamineCrashReporterDisabled", "w");
    if (fp) fclose(fp);

    // 2. 移走 forkfix
    NSString *forkfix = [jbroot stringByAppendingPathComponent:@"basebin/forkfix.dylib"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:forkfix]) {
        [[NSFileManager defaultManager] createDirectoryAtPath:@HIDE_QUARANTINE
                                 withIntermediateDirectories:YES attributes:nil error:nil];
        NSString *dst = [@HIDE_QUARANTINE stringByAppendingPathComponent:@"forkfix.dylib"];
        [[NSFileManager defaultManager] removeItemAtPath:dst error:nil];
        [[NSFileManager defaultManager] moveItemAtPath:forkfix toPath:dst error:nil];
        hide_log(@"forkfix moved");
    }

    // 3. safe_mode 标记
    NSString *safeMode = [jbroot stringByAppendingPathComponent:@"basebin/.safe_mode"];
    fp = fopen(safeMode.fileSystemRepresentation, "w");
    if (fp) fclose(fp);

    // 4. 隐藏 URL Scheme
    hide_all_url_schemes();

    // 5. 删除 /var/jb 符号链接
    unlink("/var/jb");
    hide_log(@"/var/jb removed");

    // 6. Library Audit
    run_library_audit();
    hide_log(@"library audit done");

    // 7. 禁用 systemwide domain
    systemwide_domain_set_enabled(false);

    // 8. 异步刷新 LaunchServices（App 图标）
    NSString *uicache = [jbroot stringByAppendingPathComponent:@"usr/bin/uicache"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:uicache]) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
            posix_spawn(NULL, uicache.fileSystemRepresentation, NULL, NULL,
                        (char *const[]){(char *)uicache.fileSystemRepresentation, "-a", NULL},
                        environ);
            hide_log(@"uicache -a issued");
        });
    }

    // 9. 写 monitor 隐藏标记（用于判断是不是 monitor 隐藏的）
    FILE *mf = fopen(MONITOR_HIDE_MARKER, "w");
    if (mf) fclose(mf);

    hide_log(@"perform_hide complete");
}

static void perform_unhide(void)
{
    hide_log(@"perform_unhide begin");

    NSString *jbroot = jbroot_str();
    if (!jbroot) {
        hide_log(@"jbroot missing, abort");
        return;
    }

    systemwide_domain_set_enabled(true);

    // 恢复 /var/jb 符号链接
    if (symlink(jbroot.fileSystemRepresentation, "/var/jb") == 0) {
        hide_log(@"/var/jb restored");
    }

    // 恢复被移走的文件
    restore_items();
    hide_log(@"library restored");

    // 恢复 URL Scheme
    restore_all_url_schemes();

    // 恢复 forkfix
    NSString *forkfixDst = [@HIDE_QUARANTINE stringByAppendingPathComponent:@"forkfix.dylib"];
    NSString *forkfix = [jbroot stringByAppendingPathComponent:@"basebin/forkfix.dylib"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:forkfixDst]) {
        [[NSFileManager defaultManager] moveItemAtPath:forkfixDst toPath:forkfix error:nil];
    }

    // 删除 safe_mode 标记
    NSString *safeMode = [jbroot stringByAppendingPathComponent:@"basebin/.safe_mode"];
    unlink(safeMode.fileSystemRepresentation);

// 删除 crash reporter 禁用标记
    unlink("/var/mobile/.DopamineCrashReporterDisabled");

    // 异步刷新 LaunchServices
    NSString *uicache = [jbroot stringByAppendingPathComponent:@"usr/bin/uicache"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:uicache]) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
            posix_spawn(NULL, uicache.fileSystemRepresentation, NULL, NULL,
                        (char *const[]){(char *)uicache.fileSystemRepresentation, "-a", NULL},
                        environ);
            hide_log(@"uicache -a issued (unhide)");
        });
    }

    // 删除 monitor 隐藏标记
    unlink(MONITOR_HIDE_MARKER);

    hide_log(@"perform_unhide complete");
}

#pragma mark - 监控线程

static bool gActionInProgress = false;

static time_t gLastTargetSeen = 0;
static const int UNHIDE_GRACE_SECONDS = 60;

static void *monitor_thread(void *arg)
{
    hide_log(@"monitor thread running");

    while (1) {
        @autoreleasepool {
            BOOL shouldHide = any_target_running();
            time_t now = time(NULL);

            if (shouldHide) {
                gLastTargetSeen = now;
            }

            BOOL actuallyHidden = (access("/var/jb", F_OK) != 0);

            // 只有超过 60 秒没检测到目标 App，才允许恢复
            BOOL graceElapsed = (gLastTargetSeen == 0) || ((now - gLastTargetSeen) > UNHIDE_GRACE_SECONDS);

            if (shouldHide && !actuallyHidden && !gActionInProgress) {
                gActionInProgress = true;
                hide_log(@"triggering HIDE");
                perform_hide();
                gActionInProgress = false;
            }
            else if (graceElapsed && !shouldHide && actuallyHidden
                     && access(MONITOR_HIDE_MARKER, F_OK) == 0
                     && !gActionInProgress) {
                gActionInProgress = true;
                hide_log(@"triggering UNHIDE");
                perform_unhide();
                gActionInProgress = false;
            }
        }
        sleep(2);
    }
    return NULL;
}

void start_app_hide_monitor(void)
{
    hide_log(@"==== monitor starting ====");
    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    int r = pthread_create(&thread, &attr, monitor_thread, NULL);
    pthread_attr_destroy(&attr);
    hide_log(r != 0 ? @"pthread_create failed" : @"pthread_create ok");
}

bool app_hide_is_target(const char *executablePath)
{
    if (!executablePath) return false;
    @autoreleasepool {
        NSString *path = [NSString stringWithUTF8String:executablePath];
        NSRange range = [path rangeOfString:@".app/"];
        if (range.location == NSNotFound) return false;

        NSString *appPath = [path substringToIndex:range.location + 4];
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
            [appPath stringByAppendingPathComponent:@"Info.plist"]];
        NSString *bid = info[@"CFBundleIdentifier"];
        if (!bid) return false;

        NSArray *targets = target_bundle_ids();
        return [targets containsObject:bid];
    }
}

static pthread_mutex_t gHideLock = PTHREAD_MUTEX_INITIALIZER;

void app_hide_perform_hide_sync(void)
{
    @autoreleasepool {
        pthread_mutex_lock(&gHideLock);
        if (access("/var/jb", F_OK) == 0) {
            hide_log(@"sync hide from spawn_hook");
            perform_hide();
        } else {
            hide_log(@"already hidden, skip sync hide");
        }
        pthread_mutex_unlock(&gHideLock);
    }
}