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

#import <libjailbreak/jbroot.h>
#import "jbserver/jbserver_local.h"

extern int proc_listallpids(void *buffer, int buffersize);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffersize);
extern void systemwide_domain_set_enabled(bool enabled);
extern int jbctl_earlyboot(mach_port_t serverPort, const char *arg0, ...);

#define APP_HIDE_RULES_PATH    "/var/mobile/Library/Preferences/.DopamineAppHideRules.plist"
#define APP_HIDE_LOG_PATH      "/var/mobile/Documents/DopamineAppHide.log"
#define APP_HIDE_LOG_MAX_SIZE  (512 * 1024)
#define HIDE_QUARANTINE        "/var/mobile/.DopamineAppHideQuarantine"

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
        NSDictionary *rule = rules[bid];
        if ([rule[@"HideEnvironment"] boolValue]) {
            [result addObject:bid];
        }
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
    NSString *infoPath = [appPath stringByAppendingPathComponent:@"Info.plist"];
    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:infoPath];
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
        if (bid && ![result containsObject:bid]) {
            [result addObject:bid];
        }
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
        if ([targets containsObject:bid]) {
            hide_log(@"target detected: %@", bid);
            return YES;
        }
    }
    return NO;
}

#pragma mark - 隔离区

static void quarantine_move(const char *path)
{
    if (access(path, F_OK) != 0) return;

    mkdir(HIDE_QUARANTINE, 0755);

    const char *name = strrchr(path, '/');
    if (!name) return;
    name++;

    char dst[512];
    snprintf(dst, sizeof(dst), HIDE_QUARANTINE "/%s", name);

    if (rename(path, dst) == 0) {
        hide_log(@"quarantined: %s", path);
    } else {
        hide_log(@"quarantine failed: %s (errno=%d)", path, errno);
    }
}

static void quarantine_restore(const char *path)
{
    const char *name = strrchr(path, '/');
    if (!name) return;
    name++;

    char src[512];
    snprintf(src, sizeof(src), HIDE_QUARANTINE "/%s", name);

    if (access(src, F_OK) != 0) return;

    if (rename(src, path) == 0) {
        hide_log(@"restored: %s", path);
    } else {
        hide_log(@"restore failed: %s (errno=%d)", path, errno);
    }
}

#pragma mark - jbctl 调用

static void run_jbctl_internal(const char *cmd1, const char *cmd2)
{
    mach_port_t port = jbserver_local_start();
    jbctl_earlyboot(port, "internal", cmd1, cmd2, NULL);
    jbserver_local_stop();
}

#pragma mark - 隐藏/恢复

static const char *kPlistsToHide[] = {
    "/var/mobile/Library/Preferences/com.opa334.Dopamine.plist",
    "/var/mobile/Library/Preferences/com.opa334.Dopamine.roothide.plist",
    "/var/mobile/Library/Preferences/com.tigisoftware.Filza.plist",
    "/var/mobile/Library/Preferences/com.xina.jailbreak.plist",
    "/var/mobile/Library/Preferences/org.coolstar.SileoStore.plist",
    "/var/mobile/Library/Preferences/ws.hbang.Terminal.plist",
    "/var/mobile/Library/Preferences/xyz.willy.Zebra.plist",
    NULL
};

static void perform_hide(void)
{
    hide_log(@"perform_hide begin");

    run_jbctl_internal("fakelib", "unmount");
    hide_log(@"fakelib unmounted");

    run_jbctl_internal("protection", "deactivate");
    hide_log(@"protection deactivated");

    for (int i = 0; kPlistsToHide[i]; i++) {
        quarantine_move(kPlistsToHide[i]);
    }

    if (unlink("/var/jb") == 0) hide_log(@"/var/jb removed");

    systemwide_domain_set_enabled(false);
    hide_log(@"systemwide domain disabled");

    hide_log(@"perform_hide complete");
}

static void perform_unhide(void)
{
    hide_log(@"perform_unhide begin");

    systemwide_domain_set_enabled(true);
    hide_log(@"systemwide domain enabled");

    const char *jbroot = JBROOT_PATH("/");
    if (jbroot && access(jbroot, F_OK) == 0) {
        if (symlink(jbroot, "/var/jb") == 0) hide_log(@"/var/jb restored");
    }

    for (int i = 0; kPlistsToHide[i]; i++) {
        quarantine_restore(kPlistsToHide[i]);
    }

    run_jbctl_internal("protection", "activate");
    hide_log(@"protection activated");

    run_jbctl_internal("fakelib", "mount");
    hide_log(@"fakelib mounted");

    hide_log(@"perform_unhide complete");
}

#pragma mark - 监控线程

static bool gIsHidden = false;
static bool gActionInProgress = false;

static void *monitor_thread(void *arg)
{
    hide_log(@"monitor thread running");

    gIsHidden = (access("/var/jb", F_OK) != 0);
    hide_log(@"initial state: isHidden=%d", gIsHidden);

    while (1) {
        @autoreleasepool {
            BOOL shouldHide = any_target_running();

            if (shouldHide && !gIsHidden && !gActionInProgress) {
                gActionInProgress = true;
                hide_log(@"triggering HIDE");
                perform_hide();
                gActionInProgress = false;
            }
            else if (!shouldHide && gIsHidden && !gActionInProgress) {
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

    if (r != 0) {
        hide_log(@"pthread_create failed: %d", r);
    } else {
        hide_log(@"pthread_create ok");
    }
}