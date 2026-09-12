#include <objc/runtime.h>
#include <objc/message.h>
#include <mach-o/dyld.h>
#include <os/log.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>

#define HIDDEN_SCHEMES_FILE "/var/mobile/Library/Caches/.DopamineHiddenSchemes"
#define DEBUG_LOG_FILE      "/var/mobile/Library/Caches/.urlscheme_debug.log"

static void dbg_log(const char *fmt, ...)
{
    int fd = open(DEBUG_LOG_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return;
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) {
        write(fd, buf, n);
        write(fd, "\n", 1);
    }
    close(fd);
}

static bool scheme_is_hidden(const char *scheme)
{
    if (!scheme || !scheme[0]) return false;

    FILE *fp = fopen(HIDDEN_SCHEMES_FILE, "r");
    if (!fp) {
        dbg_log("[URLSchemeBlock] file not readable: %s", HIDDEN_SCHEMES_FILE);
        return false;
    }

    char line[256];
    bool found = false;
    size_t slen = strlen(scheme);
    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r' ||
                           line[len - 1] == ' '  || line[len - 1] == '\t')) {
            line[--len] = '\0';
        }
        if (len == 0) continue;
        if (len == slen && strcasecmp(line, scheme) == 0) {
            found = true;
            break;
        }
    }
    fclose(fp);
    return found;
}

static const char *url_scheme_cstr(id url)
{
    if (!url) return NULL;
    id scheme = ((id (*)(id, SEL))objc_msgSend)(url, sel_registerName("scheme"));
    if (!scheme) return NULL;
    return ((const char *(*)(id, SEL))objc_msgSend)(scheme, sel_registerName("UTF8String"));
}

static const char *nsstring_cstr(id str)
{
    if (!str) return NULL;
    return ((const char *(*)(id, SEL))objc_msgSend)(str, sel_registerName("UTF8String"));
}

static BOOL (*orig_canOpenURL)(id, SEL, id);
static BOOL hooked_canOpenURL(id self, SEL _cmd, id url)
{
    const char *scheme = url_scheme_cstr(url);
    dbg_log("[URLSchemeBlock] canOpenURL called: %s", scheme ?: "(null)");
    if (scheme_is_hidden(scheme)) {
        dbg_log("[URLSchemeBlock] BLOCKED canOpenURL: %s", scheme);
        return NO;
    }
    return orig_canOpenURL(self, _cmd, url);
}

static void (*orig_openURL_opts)(id, SEL, id, id, void (^)(BOOL));
static void hooked_openURL_opts(id self, SEL _cmd, id url, id opts, void (^completion)(BOOL))
{
    const char *scheme = url_scheme_cstr(url);
    dbg_log("[URLSchemeBlock] openURL:options: called: %s", scheme ?: "(null)");
    if (scheme_is_hidden(scheme)) {
        dbg_log("[URLSchemeBlock] BLOCKED openURL:options: %s", scheme);
        if (completion) completion(NO);
        return;
    }
    orig_openURL_opts(self, _cmd, url, opts, completion);
}

static BOOL (*orig_openURL)(id, SEL, id);
static BOOL hooked_openURL(id self, SEL _cmd, id url)
{
    const char *scheme = url_scheme_cstr(url);
    dbg_log("[URLSchemeBlock] openURL: called: %s", scheme ?: "(null)");
    if (scheme_is_hidden(scheme)) {
        dbg_log("[URLSchemeBlock] BLOCKED openURL: %s", scheme);
        return NO;
    }
    return orig_openURL(self, _cmd, url);
}

static id (*orig_appsForScheme)(id, SEL, id);
static id hooked_appsForScheme(id self, SEL _cmd, id scheme)
{
    const char *s = nsstring_cstr(scheme);
    dbg_log("[URLSchemeBlock] LSAppWorkspace applicationsAvailableForHandlingURLScheme: %s", s ?: "(null)");
    if (scheme_is_hidden(s)) {
        dbg_log("[URLSchemeBlock] BLOCKED LSAppWorkspace for scheme: %s", s);
        return nil;
    }
    return orig_appsForScheme(self, _cmd, scheme);
}

static id (*orig_appsForURL)(id, SEL, id);
static id hooked_appsForURL(id self, SEL _cmd, id url)
{
    const char *scheme = url_scheme_cstr(url);
    dbg_log("[URLSchemeBlock] LSAppWorkspace applicationsAvailableForOpeningURL: %s", scheme ?: "(null)");
    if (scheme_is_hidden(scheme)) {
        dbg_log("[URLSchemeBlock] BLOCKED LSAppWorkspace URL: %s", scheme);
        return nil;
    }
    return orig_appsForURL(self, _cmd, url);
}

static BOOL (*orig_appIsInstalled)(id, SEL, id);
static BOOL hooked_appIsInstalled(id self, SEL _cmd, id bundleId)
{
    const char *bid = nsstring_cstr(bundleId);
    dbg_log("[URLSchemeBlock] LSAppWorkspace applicationIsInstalled: %s", bid ?: "(null)");
    return orig_appIsInstalled(self, _cmd, bundleId);
}

static bool gHooksInstalled = false;

static void try_install_hooks(void)
{
    if (gHooksInstalled) return;

    Class uiApp = objc_getClass("UIApplication");
    if (!uiApp) {
        dbg_log("[URLSchemeBlock] UIApplication not loaded yet");
        return;
    }

    dbg_log("[URLSchemeBlock] installing hooks, UIApplication=%p", uiApp);

    Method m1 = class_getInstanceMethod(uiApp, sel_registerName("canOpenURL:"));
    if (m1) {
        orig_canOpenURL = (void *)method_getImplementation(m1);
        method_setImplementation(m1, (IMP)hooked_canOpenURL);
        dbg_log("[URLSchemeBlock] hooked UIApplication canOpenURL:");
    } else {
        dbg_log("[URLSchemeBlock] FAILED to find canOpenURL:");
    }

    Method m2 = class_getInstanceMethod(uiApp, sel_registerName("openURL:options:completionHandler:"));
    if (m2) {
        orig_openURL_opts = (void *)method_getImplementation(m2);
        method_setImplementation(m2, (IMP)hooked_openURL_opts);
        dbg_log("[URLSchemeBlock] hooked UIApplication openURL:options:completionHandler:");
    }

    Method m3 = class_getInstanceMethod(uiApp, sel_registerName("openURL:"));
    if (m3) {
        orig_openURL = (void *)method_getImplementation(m3);
        method_setImplementation(m3, (IMP)hooked_openURL);
        dbg_log("[URLSchemeBlock] hooked UIApplication openURL:");
    }

    Class lsw = objc_getClass("LSApplicationWorkspace");
    if (lsw) {
        Method m4 = class_getInstanceMethod(lsw, sel_registerName("applicationsAvailableForHandlingURLScheme:"));
        if (m4) {
            orig_appsForScheme = (void *)method_getImplementation(m4);
            method_setImplementation(m4, (IMP)hooked_appsForScheme);
            dbg_log("[URLSchemeBlock] hooked LSAppWorkspace applicationsAvailableForHandlingURLScheme:");
        }

        Method m5 = class_getInstanceMethod(lsw, sel_registerName("applicationsAvailableForOpeningURL:"));
        if (m5) {
            orig_appsForURL = (void *)method_getImplementation(m5);
            method_setImplementation(m5, (IMP)hooked_appsForURL);
            dbg_log("[URLSchemeBlock] hooked LSAppWorkspace applicationsAvailableForOpeningURL:");
        }

        Method m6 = class_getInstanceMethod(lsw, sel_registerName("applicationIsInstalled:"));
        if (m6) {
            orig_appIsInstalled = (void *)method_getImplementation(m6);
            method_setImplementation(m6, (IMP)hooked_appIsInstalled);
            dbg_log("[URLSchemeBlock] hooked LSAppWorkspace applicationIsInstalled:");
        }
    } else {
        dbg_log("[URLSchemeBlock] LSApplicationWorkspace not available");
    }

    gHooksInstalled = true;
    dbg_log("[URLSchemeBlock] hooks installed");
}

static void dyld_image_added(const struct mach_header *mh, intptr_t vmaddr_slide)
{
    if (objc_getClass("UIApplication")) {
        try_install_hooks();
    }
}

void install_urlscheme_hook(void)
{
    dbg_log("[URLSchemeBlock] install_urlscheme_hook called, pid=%d", getpid());

    if (objc_getClass("UIApplication")) {
        try_install_hooks();
    } else {
        _dyld_register_func_for_add_image(dyld_image_added);
        dbg_log("[URLSchemeBlock] registered dyld image callback");
    }
}