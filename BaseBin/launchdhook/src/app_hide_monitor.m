#import <Foundation/Foundation.h>
#include <libproc.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#define APP_HIDE_RULES_PATH "/var/mobile/Library/Preferences/.DopamineAppHideRules.plist"
#define APP_HIDE_LOG_PATH   "/var/mobile/Documents/DopamineAppHide.log"
#define APP_HIDE_LOG_MAX_SIZE (512 * 1024)

static void hide_log(NSString *format, ...)
{
    va_list args;
    va_start(args, format);
    NSString *msg = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);

    NSLog(@"[AppHideMonitor] %@", msg);

    NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
    fmt.dateFormat = @"HH:mm:ss.SSS";
    NSString *line = [NSString stringWithFormat:@"[%@] %@\n", [fmt stringFromDate:[NSDate date]], msg];

    FILE *fp = fopen(APP_HIDE_LOG_PATH, "a");
    if (!fp) return;

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    if (size > APP_HIDE_LOG_MAX_SIZE) {
        fclose(fp);
        fp = fopen(APP_HIDE_LOG_PATH, "w");
        if (!fp) return;
    }

    fputs(line.UTF8String, fp);
    fclose(fp);
}

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

static void tick(void)
{
    @autoreleasepool {
        BOOL shouldHide = any_target_running();
        hide_log(@"shouldHide=%d", shouldHide);
    }
}

void start_app_hide_monitor(void)
{
    hide_log(@"==== monitor starting ====");

    dispatch_queue_t queue = dispatch_queue_create("com.dopamine.apphide.monitor", DISPATCH_QUEUE_SERIAL);
    dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);
    dispatch_source_set_timer(timer,
                              dispatch_time(DISPATCH_TIME_NOW, 1ull * NSEC_PER_SEC),
                              1ull * NSEC_PER_SEC,
                              100ull * NSEC_PER_MSEC);
    dispatch_source_set_event_handler(timer, ^{
        tick();
    });
    dispatch_resume(timer);
}