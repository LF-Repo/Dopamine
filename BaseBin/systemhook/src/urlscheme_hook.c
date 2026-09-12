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

#define HIDDEN_SCHEMES_FILE "/var/mobile/Library/Preferences/.DopamineHiddenSchemes"

static bool scheme_is_hidden(const char *scheme)
{
    if (!scheme || !scheme[0]) return false;

    FILE *fp = fopen(HIDDEN_SCHEMES_FILE, "r");
    if (!fp) return false;

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
    if (scheme_is_hidden(scheme)) {
        os_log(OS_LOG_DEFAULT, "[URLSchemeBlock] canOpenURL blocked: %{public}s", scheme);
        return NO;
    }
    return orig_canOpenURL(self, _cmd, url);
}

static void (*orig_openURL_opts)(id, SEL, id, id, void (^)(BOOL));
static void hooked_openURL_opts(id self, SEL _cmd, id url, id opts, void (^completion)(BOOL))
{
    const char *scheme = url_scheme_cstr(url);
    if (scheme_is_hidden(scheme)) {
        os_log(OS_LOG_DEFAULT, "[URLSchemeBlock] openURL:options: blocked: %{public}s", scheme);
        if (completion) completion(NO);
        return;
    }
    orig_openURL_opts(self, _cmd, url, opts, completion);
}

static BOOL (*orig_openURL)(id, SEL, id);
static BOOL hooked_openURL(id self, SEL _cmd, id url)
{
    const char *scheme = url_scheme_cstr(url);
    if (scheme_is_hidden(scheme)) {
        os_log(OS_LOG_DEFAULT, "[URLSchemeBlock] openURL: blocked: %{public}s", scheme);
        return NO;
    }
    return orig_openURL(self, _cmd, url);
}

static id (*orig_appsForScheme)(id, SEL, id);
static id hooked_appsForScheme(id self, SEL _cmd, id scheme)
{
    const char *s = nsstring_cstr(scheme);
    if (scheme_is_hidden(s)) {
        os_log(OS_LOG_DEFAULT, "[URLSchemeBlock] LSApplicationWorkspace blocked: %{public}s", s);
        return nil;
    }
    return orig_appsForScheme(self, _cmd, scheme);
}

static id (*orig_appsForURL)(id, SEL, id);
static id hooked_appsForURL(id self, SEL _cmd, id url)
{
    const char *scheme = url_scheme_cstr(url);
    if (scheme_is_hidden(scheme)) {
        os_log(OS_LOG_DEFAULT, "[URLSchemeBlock] LSApplicationWorkspace URL blocked: %{public}s", scheme);
        return nil;
    }
    return orig_appsForURL(self, _cmd, url);
}

static bool gHooksInstalled = false;

static void try_install_hooks(void)
{
    if (gHooksInstalled) return;

    Class uiApp = objc_getClass("UIApplication");
    if (!uiApp) return;

    Method m1 = class_getInstanceMethod(uiApp, sel_registerName("canOpenURL:"));
    if (m1) {
        orig_canOpenURL = (void *)method_getImplementation(m1);
        method_setImplementation(m1, (IMP)hooked_canOpenURL);
        os_log(OS_LOG_DEFAULT, "[URLSchemeBlock] hooked UIApplication canOpenURL:");
    }

    Method m2 = class_getInstanceMethod(uiApp, sel_registerName("openURL:options:completionHandler:"));
    if (m2) {
        orig_openURL_opts = (void *)method_getImplementation(m2);
        method_setImplementation(m2, (IMP)hooked_openURL_opts);
        os_log(OS_LOG_DEFAULT, "[URLSchemeBlock] hooked UIApplication openURL:options:completionHandler:");
    }

    Method m3 = class_getInstanceMethod(uiApp, sel_registerName("openURL:"));
    if (m3) {
        orig_openURL = (void *)method_getImplementation(m3);
        method_setImplementation(m3, (IMP)hooked_openURL);
        os_log(OS_LOG_DEFAULT, "[URLSchemeBlock] hooked UIApplication openURL:");
    }

    Class lsw = objc_getClass("LSApplicationWorkspace");
    if (lsw) {
        Method m4 = class_getInstanceMethod(lsw, sel_registerName("applicationsAvailableForHandlingURLScheme:"));
        if (m4) {
            orig_appsForScheme = (void *)method_getImplementation(m4);
            method_setImplementation(m4, (IMP)hooked_appsForScheme);
            os_log(OS_LOG_DEFAULT, "[URLSchemeBlock] hooked LSApplicationWorkspace applicationsAvailableForHandlingURLScheme:");
        }

        Method m5 = class_getInstanceMethod(lsw, sel_registerName("applicationsAvailableForOpeningURL:"));
        if (m5) {
            orig_appsForURL = (void *)method_getImplementation(m5);
            method_setImplementation(m5, (IMP)hooked_appsForURL);
            os_log(OS_LOG_DEFAULT, "[URLSchemeBlock] hooked LSApplicationWorkspace applicationsAvailableForOpeningURL:");
        }
    }

    gHooksInstalled = true;
}

static void dyld_image_added(const struct mach_header *mh, intptr_t vmaddr_slide)
{
    if (objc_getClass("UIApplication")) {
        try_install_hooks();
    }
}

void install_urlscheme_hook(void)
{
    if (objc_getClass("UIApplication")) {
        try_install_hooks();
    } else {
        _dyld_register_func_for_add_image(dyld_image_added);
    }
}