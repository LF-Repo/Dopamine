#import <Foundation/Foundation.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <spawn.h>

#import <libjailbreak/info.h>
#import <libjailbreak/jbclient_xpc.h>

extern char **environ;

#define APP_HIDE_LOG_PATH     "/var/mobile/Documents/DopamineAppHide.log"
#define APP_HIDE_LOG_MAX_SIZE (512 * 1024)

#pragma mark - 日志

static void hide_log(NSString *format, ...)
{
    va_list args;
    va_start(args, format);
    NSString *msg = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);

    NSLog(@"[AppHide] %@", msg);

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

#pragma mark - URL Scheme Hiding

static NSDictionary *jb_url_targets(void)
{
    return @{
        @"Sileo.app":     @[@"sileo"],
        @"Saily.app":     @[@"apt-repo"],
        @"chromatic.app": @[@"apt-repo"],
        @"Filza.app":     @[
            @"filza",
            @"db-lmvo0l08204d0a0",
            @"boxsdk-810yk37nbrpwaee5907xc4iz8c1ay3my",
            @"com.googleusercontent.apps.802910049260-0hf6uv6nsj21itl94v66tphcqnfl172r",
        ],
        @"iCleaner.app":  @[@"icleaner"],
    };
}

static NSDictionary *third_party_url_targets(void)
{
    // 普通 App：路径在 /var/containers/Bundle/Application/ 或 /Applications/
    return @{
        @"PostBox.app":    @[@"postbox"],
        @"Santander.app":  @[@"santander"],
        @"Reveil.app":     @[@"reveil", @"82flex"],
        @"Cowabunga.app":  @[@"cowabunga"],
        @"misaka.app":     @[@"misaka"],
    };
}

static NSString *find_jb_app_path(NSString *appName)
{
    NSString *jbroot = jbroot_str();
    if (!jbroot) return nil;
    NSString *full = [[jbroot stringByAppendingPathComponent:@"Applications"]
                      stringByAppendingPathComponent:appName];
    BOOL isDir = NO;
    if ([[NSFileManager defaultManager] fileExistsAtPath:full isDirectory:&isDir] && isDir) {
        return full;
    }
    return nil;
}

static NSString *find_sys_app_path(NSString *appName)
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

static BOOL hide_url_scheme_in_plist(NSString *infoPath, NSString *scheme)
{
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
            if ([schemes isKindOfClass:[NSArray class]] && [schemes containsObject:scheme]) {
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

    NSArray *queries = plist[@"LSApplicationQueriesSchemes"];
    if ([queries isKindOfClass:[NSArray class]] && [queries containsObject:scheme]) {
        NSMutableArray *nq = [queries mutableCopy];
        [nq removeObject:scheme];
        plist[@"LSApplicationQueriesSchemes"] = nq;
        modified = YES;
    }

    if (!modified) return NO;

    NSString *backup = [infoPath stringByAppendingString:@".hideurl_backup"];
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:backup]) {
        [fm copyItemAtPath:infoPath toPath:backup error:nil];
    }

    NSData *out = [NSPropertyListSerialization dataWithPropertyList:plist
        format:NSPropertyListXMLFormat_v1_0 options:0 error:nil];
    return [out writeToFile:infoPath atomically:YES];
}

static void refresh_launch_services(NSArray<NSString *> *appPaths)
{
    if (appPaths.count == 0) return;

    NSString *jbroot = jbroot_str();
    if (!jbroot) return;
    NSString *uicache = [jbroot stringByAppendingPathComponent:@"usr/bin/uicache"];
    if (![[NSFileManager defaultManager] fileExistsAtPath:uicache]) return;

    for (NSString *appPath in appPaths) {
        const char *uicachePath = uicache.fileSystemRepresentation;
        const char *appPathC = appPath.fileSystemRepresentation;

        pid_t pid;
        posix_spawn(&pid, uicachePath, NULL, NULL,
                    (char *const[]){(char *)uicachePath, "-u", (char *)appPathC, NULL},
                    environ);
        waitpid(pid, NULL, 0);

        posix_spawn(&pid, uicachePath, NULL, NULL,
                    (char *const[]){(char *)uicachePath, "-p", (char *)appPathC, NULL},
                    environ);
        waitpid(pid, NULL, 0);
    }
}

static void do_hide_url_schemes(NSDictionary *targets, BOOL useJb)
{
    NSMutableArray<NSString *> *modified = [NSMutableArray array];

    for (NSString *appName in targets) {
        NSString *appPath = useJb ? find_jb_app_path(appName)
                                   : find_sys_app_path(appName);
        if (!appPath) continue;

        NSString *infoPath = [appPath stringByAppendingPathComponent:@"Info.plist"];
        BOOL any = NO;
        for (NSString *scheme in targets[appName]) {
            if (hide_url_scheme_in_plist(infoPath, scheme)) any = YES;
        }
        if (any) [modified addObject:appPath];
    }

    if (modified.count == 0) return;
    refresh_launch_services(modified);
    hide_log(@"hid URL schemes in %lu apps", (unsigned long)modified.count);
}

void apply_url_scheme_hiding_from_prefs(void)
{
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:
        @"/var/mobile/Library/Preferences/com.opa334.Dopamine.plist"];
    if (!prefs) return;

    if ([prefs[@"hideJailbreakURLSchemes"] boolValue]) {
        hide_log(@"pref: hide jailbreak URL schemes");
        do_hide_url_schemes(jb_url_targets(), YES);
    }
    if ([prefs[@"hideOtherURLSchemes"] boolValue]) {
        hide_log(@"pref: hide third-party URL schemes");
        do_hide_url_schemes(third_party_url_targets(), NO);
    }
}
