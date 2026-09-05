#include "var_filter.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <regex.h>

#define MAX_HIDDEN_PIDS 256

static pid_t hidden_pids[MAX_HIDDEN_PIDS];
static int hidden_pid_count = 0;
static pthread_mutex_t hidden_pids_mutex = PTHREAD_MUTEX_INITIALIZER;

extern char *JB_RandomRootPath;

void set_jailbreak_hidden_for_pid(pid_t pid, bool hidden) {
    pthread_mutex_lock(&hidden_pids_mutex);
    if (hidden) {
        for (int i = 0; i < hidden_pid_count; i++) {
            if (hidden_pids[i] == pid) {
                pthread_mutex_unlock(&hidden_pids_mutex);
                return;
            }
        }
        if (hidden_pid_count < MAX_HIDDEN_PIDS) {
            hidden_pids[hidden_pid_count++] = pid;
        }
    } else {
        for (int i = 0; i < hidden_pid_count; i++) {
            if (hidden_pids[i] == pid) {
                hidden_pids[i] = hidden_pids[--hidden_pid_count];
                break;
            }
        }
    }
    pthread_mutex_unlock(&hidden_pids_mutex);
}

bool is_jailbreak_hidden_for_pid(pid_t pid) {
    pthread_mutex_lock(&hidden_pids_mutex);
    for (int i = 0; i < hidden_pid_count; i++) {
        if (hidden_pids[i] == pid) {
            pthread_mutex_unlock(&hidden_pids_mutex);
            return true;
        }
    }
    pthread_mutex_unlock(&hidden_pids_mutex);
    return false;
}

bool is_jailbreak_hidden_for_current_process(void) {
    return is_jailbreak_hidden_for_pid(getpid());
}

static bool match_rule(const char *name, FilterRule *rule) {
    if (!name || !rule || !rule->pattern) return false;
    switch (rule->type) {
        case MATCH_EXACT:
            return strcmp(name, rule->pattern) == 0;
        case MATCH_PREFIX:
            return strncmp(name, rule->pattern, strlen(rule->pattern)) == 0;
        case MATCH_SUFFIX:
            return strlen(name) >= strlen(rule->pattern) && 
                   strcmp(name + strlen(name) - strlen(rule->pattern), rule->pattern) == 0;
        case MATCH_CONTAINS:
            return strstr(name, rule->pattern) != NULL;
        case MATCH_REGEX: {
            regex_t regex;
            if (regcomp(&regex, rule->pattern, REG_EXTENDED | REG_NOSUB) != 0) return false;
            int ret = regexec(&regex, name, 0, NULL, 0);
            regfree(&regex);
            return ret == 0;
        }
    }
    return false;
}

static FilterRule var_whitelist[] = {
    {MATCH_EXACT, ".DocumentRevisions-V100"},
    {MATCH_EXACT, ".fseventsd"},
    {MATCH_EXACT, "Keychains"},
    {MATCH_EXACT, "MobileDevice"},
    {MATCH_EXACT, "buddy"},
    {MATCH_EXACT, "datamigrator"},
    {MATCH_EXACT, "folders"},
    {MATCH_EXACT, "keybags"},
    {MATCH_EXACT, "networkd"},
    {MATCH_EXACT, "root"},
    {MATCH_EXACT, "tmp"},
    {MATCH_EXACT, "Managed Preferences"},
    {MATCH_EXACT, "MobileSoftwareUpdate"},
    {MATCH_EXACT, "containers"},
    {MATCH_EXACT, "db"},
    {MATCH_EXACT, "hardware"},
    {MATCH_EXACT, "mobile"},
    {MATCH_EXACT, "preferences"},
    {MATCH_EXACT, "run"},
    {MATCH_EXACT, "vm"},
    {MATCH_EXACT, "MobileAsset"},
    {MATCH_EXACT, "audit"},
    {MATCH_EXACT, "empty"},
    {MATCH_EXACT, "installd"},
    {MATCH_EXACT, "log"},
    {MATCH_EXACT, "logs"},
    {MATCH_EXACT, "msgs"},
    {MATCH_EXACT, "protected"},
    {MATCH_EXACT, "select"},
    {MATCH_EXACT, "wireless"},
    {MATCH_EXACT, "dirs_cleaner"},
    {MATCH_EXACT, "dextcores"},
    {MATCH_EXACT, "staged_system_apps"},
    {MATCH_EXACT, "internal"},
    {MATCH_EXACT, "iomfb_bics_daemon"},
};

static FilterRule var_blacklist[] = {
    {MATCH_EXACT, "jb"},
    {MATCH_EXACT, "stash"},
    {MATCH_EXACT, "alternatives"},
    {MATCH_EXACT, "ap"},
    {MATCH_EXACT, "apt"},
    {MATCH_EXACT, "bin"},
    {MATCH_EXACT, "bzip2"},
    {MATCH_EXACT, "cache"},
    {MATCH_EXACT, "dpkg"},
    {MATCH_EXACT, "etc"},
    {MATCH_EXACT, "gzip"},
    {MATCH_EXACT, "local"},
    {MATCH_EXACT, "lib"},
    {MATCH_EXACT, "Lib"},
    {MATCH_EXACT, "libexec"},
    {MATCH_EXACT, "Library"},
    {MATCH_EXACT, "LIY"},
    {MATCH_EXACT, "Liy"},
    {MATCH_EXACT, "newuser"},
    {MATCH_EXACT, "profile"},
    {MATCH_EXACT, "sbin"},
    {MATCH_EXACT, "sh"},
    {MATCH_EXACT, "share"},
    {MATCH_EXACT, "ssh"},
    {MATCH_EXACT, "sudo_logsrvd.conf"},
    {MATCH_EXACT, "suid_profile"},
    {MATCH_EXACT, "sy"},
    {MATCH_EXACT, "usr"},
    {MATCH_EXACT, "zlogin"},
    {MATCH_EXACT, "zlogout"},
    {MATCH_EXACT, "zprofile"},
    {MATCH_EXACT, "zshenv"},
    {MATCH_EXACT, "zshrc"},
    {MATCH_EXACT, "master.passwd"},
    {MATCH_EXACT, ".keep_symlinks"},
    {MATCH_EXACT, "QPEhelper"},
    {MATCH_EXACT, "testrebuild"},
};

static FilterRule varlog_whitelist[] = {
    {MATCH_REGEX, "^com\\.apple\\."},
    {MATCH_EXACT, "asl"},
    {MATCH_EXACT, "mDNSResponder"},
    {MATCH_EXACT, "ppp"},
};

static FilterRule mobile_prefs_whitelist[] = {
    {MATCH_REGEX, "^com\\.apple\\."},
    {MATCH_REGEX, "^systemgroup\\.com\\.apple\\."},
    {MATCH_EXACT, ".GlobalPreferences.plist"},
    {MATCH_EXACT, ".GlobalPreferences_m.plist"},
    {MATCH_EXACT, "bluetoothaudiod.plist"},
    {MATCH_EXACT, "NetworkInterfaces.plist"},
    {MATCH_EXACT, "OSThermalStatus.plist"},
    {MATCH_EXACT, "preferences.plist"},
    {MATCH_EXACT, "osanalyticshelper.plist"},
    {MATCH_EXACT, "UserEventAgent.plist"},
    {MATCH_EXACT, "wifid.plist"},
    {MATCH_EXACT, "dprivacyd.plist"},
    {MATCH_EXACT, "silhouette.plist"},
    {MATCH_EXACT, "nfcd.plist"},
    {MATCH_EXACT, "kNPProgressTrackerDomain.plist"},
    {MATCH_EXACT, "siriknowledged.plist"},
    {MATCH_EXACT, "UITextInputContextIdentifiers.plist"},
    {MATCH_EXACT, "mobile_storage_proxy.plist"},
    {MATCH_EXACT, "splashboardd.plist"},
    {MATCH_EXACT, "mobile_installation_proxy.plist"},
    {MATCH_EXACT, "languageassetd.plist"},
    {MATCH_EXACT, "ptpcamerad.plist"},
    {MATCH_EXACT, "com.google.gmp.measurement.monitor.plist"},
    {MATCH_EXACT, "com.google.gmp.measurement.plist"},
};

static FilterRule mobile_prefs_blacklist[] = {
    {MATCH_EXACT, "com.roothide.manager.plist"},
    {MATCH_EXACT, "com.opa334.Dopamine.roothide.plist"},
    {MATCH_EXACT, "com.opa334.Dopamine.plist"},
    {MATCH_EXACT, "com.tigisoftware.Filza.plist"},
    {MATCH_EXACT, "com.xina.jailbreak.plist"},
    {MATCH_EXACT, "org.coolstar.SileoStore.plist"},
    {MATCH_EXACT, "ru.domo.cocoatop64.plist"},
    {MATCH_EXACT, "ws.hbang.Terminal.plist"},
    {MATCH_EXACT, "xyz.willy.Zebra.plist"},
    {MATCH_EXACT, "com.apple.lockscreencache-new.plist"},
    {MATCH_EXACT, "com.apple.homescreencache-new.plist"},
    {MATCH_EXACT, "com.apple.terminal.plist"},
};

static FilterRule mobile_caches_whitelist[] = {
    {MATCH_REGEX, "^com\\.apple\\."},
    {MATCH_REGEX, "^TelephonyUI-\\d+$"},
    {MATCH_REGEX, "^FamilyMarquee.*Mode-.*\\.png$"},
    {MATCH_EXACT, ".com.apple.persistentconnection.settings.lock.lock"},
    {MATCH_EXACT, "Checkpoint.plist"},
    {MATCH_EXACT, "CloudKit"},
    {MATCH_EXACT, "GameKit"},
    {MATCH_EXACT, "GeoServices"},
    {MATCH_EXACT, "FamilyCircle"},
    {MATCH_EXACT, "DateFormats.plist"},
    {MATCH_EXACT, "INSTALLATION"},
    {MATCH_EXACT, "MappedImageCache"},
    {MATCH_EXACT, "PassKit"},
    {MATCH_EXACT, "RemoteConfiguration.plist"},
    {MATCH_EXACT, "VoiceServices"},
    {MATCH_EXACT, "VoiceTrigger"},
    {MATCH_EXACT, "mediaanalysisd-service"},
    {MATCH_EXACT, "rtcreportingd"},
    {MATCH_EXACT, "sharedCaches"},
    {MATCH_EXACT, "Backup"},
    {MATCH_EXACT, "ssu"},
};

static FilterRule mobile_caches_blacklist[] = {
    {MATCH_EXACT, "ImageTables"},
    {MATCH_EXACT, "SentryCrash"},
    {MATCH_EXACT, "io.sentry"},
    {MATCH_EXACT, "com.hackemist.SDImageCache"},
    {MATCH_EXACT, "com.opa334.Dopamine"},
    {MATCH_EXACT, "com.tigisoftware.Filza"},
    {MATCH_EXACT, "org.coolstar.SileoStore"},
    {MATCH_EXACT, "ws.hbang.Terminal"},
    {MATCH_EXACT, "xyz.willy.Zebra"},
    {MATCH_EXACT, "Cephei"},
    {MATCH_EXACT, "com.apple.Terminal"},
    {MATCH_EXACT, "GDFileManagerCache.sqlite"},
    {MATCH_EXACT, "GDFileManagerCache.sqlite-shm"},
    {MATCH_EXACT, "GDFileManagerCache.sqlite-wal"},
};

static FilterRule mobile_http_blacklist[] = {
    {MATCH_EXACT, "com.opa334.Dopamine"},
    {MATCH_EXACT, "com.tigisoftware.Filza"},
    {MATCH_EXACT, "org.coolstar.SileoStore"},
    {MATCH_EXACT, "ws.hbang.Terminal"},
    {MATCH_EXACT, "xyz.willy.Zebra"},
};

static FilterRule mobile_savedstate_blacklist[] = {
    {MATCH_EXACT, "com.opa334.Dopamine.savedState"},
    {MATCH_EXACT, "com.tigisoftware.Filza.savedState"},
    {MATCH_EXACT, "org.coolstar.SileoStore.savedState"},
    {MATCH_EXACT, "ws.hbang.Terminal.savedState"},
    {MATCH_EXACT, "xyz.willy.Zebra.savedState"},
    {MATCH_EXACT, "ru.domo.cocoatop64.savedState"},
    {MATCH_EXACT, "com.apple.Terminal.savedState"},
};

static FilterRule mobile_splash_blacklist[] = {
    {MATCH_EXACT, "com.roothide.manager"},
    {MATCH_EXACT, "com.opa334.Dopamine.roothide"},
    {MATCH_EXACT, "com.opa334.Dopamine"},
    {MATCH_EXACT, "com.tigisoftware.Filza"},
    {MATCH_EXACT, "com.xina.jailbreak"},
    {MATCH_EXACT, "org.coolstar.SileoStore"},
    {MATCH_EXACT, "ru.domo.cocoatop64"},
    {MATCH_EXACT, "ws.hbang.Terminal"},
    {MATCH_EXACT, "xyz.willy.Zebra"},
    {MATCH_EXACT, "com.apple.Terminal"},
};

static FilterRule mobile_cookies_blacklist[] = {
    {MATCH_EXACT, "com.johncoates.Flex.binarycookies"},
};

static FilterRule mobile_media_blacklist[] = {
    {MATCH_CONTAINS, "Auto"},
    {MATCH_CONTAINS, "Touch"},
    {MATCH_CONTAINS, "Theme"},
    {MATCH_CONTAINS, "Script"},
    {MATCH_EXACT, "Cydia"},
    {MATCH_EXACT, "CatScript"},
    {MATCH_EXACT, "TrollRecorder"},
    {MATCH_EXACT, ".evasi0n7_installed"},
    {MATCH_EXACT, ".loli"},
    {MATCH_EXACT, "blackb0x.log"},
    {MATCH_EXACT, "Divise"},
    {MATCH_EXACT, ".bootstrapped_electraRemover"},
    {MATCH_EXACT, "install"},
    {MATCH_EXACT, "log.txt"},
    {MATCH_EXACT, "p0laris"},
    {MATCH_EXACT, ".Trash"},
    {MATCH_EXACT, "spirit"},
    {MATCH_EXACT, "TouchSprite"},
    {MATCH_EXACT, ".bootstrapped_Th0r_remover"},
    {MATCH_EXACT, "AppRank"},
    {MATCH_EXACT, "KDTScript"},
    {MATCH_EXACT, "NeonStaticClockIcon.png"},
};

static FilterRule mobile_docs_blacklist[] = {
};

static FilterRule varroot_blacklist[] = {
    {MATCH_EXACT, ".bash_history"},
    {MATCH_EXACT, ".config"},
    {MATCH_EXACT, ".local"},
};

static FilterRule varroot_caches_blacklist[] = {
    {MATCH_EXACT, "shshd"},
};

static FilterRule varroot_http_blacklist[] = {
    {MATCH_EXACT, "shshd"},
    {MATCH_EXACT, "FilzaHelper"},
};

static FilterRule varroot_prefs_blacklist[] = {
    {MATCH_EXACT, "com.xina.jailbreak.plist"},
    {MATCH_EXACT, "com.xina.blacklist.plist"},
    {MATCH_EXACT, "ws.hbang.Terminal.plist"},
};

static FilterRule vartmp_whitelist[] = {
    {MATCH_REGEX, "^\\w{8}-\\w{4}-\\w{4}-\\w{4}-\\w{12}$"},
    {MATCH_REGEX, "^com\\.apple\\."},
    {MATCH_REGEX, "^SSOBackup-"},
    {MATCH_REGEX, "^SOSBackup-.*-tomb"},
    {MATCH_REGEX, "^CFNetworkDownload_"},
    {MATCH_REGEX, "^NSIRD_installd_"},
    {MATCH_REGEX, "^NSIRD_nsurlsessiond_"},
    {MATCH_REGEX, "^NSIRD_contextstored_"},
    {MATCH_REGEX, "^modelDataBlob_"},
    {MATCH_EXACT, ".LINKS"},
    {MATCH_EXACT, "MediaCache"},
    {MATCH_EXACT, "analytics"},
    {MATCH_EXACT, "aud"},
    {MATCH_EXACT, "ct.shutdown"},
    {MATCH_EXACT, "fseventsd-uuid"},
    {MATCH_EXACT, "hdds6.dat"},
    {MATCH_EXACT, "nfcd.firstlaunch"},
    {MATCH_EXACT, "powerlog"},
    {MATCH_EXACT, "recommendations"},
    {MATCH_EXACT, "journeys"},
    {MATCH_EXACT, "ClonedAXAsset"},
    {MATCH_EXACT, "internal"},
    {MATCH_EXACT, "modelDataBlob.mlmodelc"},
    {MATCH_EXACT, "SoftwareUpdateCore"},
    {MATCH_EXACT, "CalNotificationsAvailable"},
    {MATCH_EXACT, "biokit_hw_issue_notification"},
};

static DirRule all_rules[] = {
    {"/var", false, var_whitelist, sizeof(var_whitelist)/sizeof(var_whitelist[0]), var_blacklist, sizeof(var_blacklist)/sizeof(var_blacklist[0])},
    {"/var/log", true, varlog_whitelist, sizeof(varlog_whitelist)/sizeof(varlog_whitelist[0]), NULL, 0},
    {"/var/mobile/Library/Preferences", true, mobile_prefs_whitelist, sizeof(mobile_prefs_whitelist)/sizeof(mobile_prefs_whitelist[0]), mobile_prefs_blacklist, sizeof(mobile_prefs_blacklist)/sizeof(mobile_prefs_blacklist[0])},
    {"/var/mobile/Library/Caches", true, mobile_caches_whitelist, sizeof(mobile_caches_whitelist)/sizeof(mobile_caches_whitelist[0]), mobile_caches_blacklist, sizeof(mobile_caches_blacklist)/sizeof(mobile_caches_blacklist[0])},
    {"/var/mobile/Library/HTTPStorages", true, NULL, 0, mobile_http_blacklist, sizeof(mobile_http_blacklist)/sizeof(mobile_http_blacklist[0])},
    {"/var/mobile/Library/Saved Application State", true, NULL, 0, mobile_savedstate_blacklist, sizeof(mobile_savedstate_blacklist)/sizeof(mobile_savedstate_blacklist[0])},
    {"/var/mobile/Library/SplashBoard/Snapshots", true, NULL, 0, mobile_splash_blacklist, sizeof(mobile_splash_blacklist)/sizeof(mobile_splash_blacklist[0])},
    {"/var/mobile/Library/Cookies", true, NULL, 0, mobile_cookies_blacklist, sizeof(mobile_cookies_blacklist)/sizeof(mobile_cookies_blacklist[0])},
    {"/var/mobile/Media", true, NULL, 0, mobile_media_blacklist, sizeof(mobile_media_blacklist)/sizeof(mobile_media_blacklist[0])},
    {"/var/mobile/Documents", false, NULL, 0, mobile_docs_blacklist, sizeof(mobile_docs_blacklist)/sizeof(mobile_docs_blacklist[0])},
    {"/var/root", false, NULL, 0, varroot_blacklist, sizeof(varroot_blacklist)/sizeof(varroot_blacklist[0])},
    {"/var/root/Library/Caches", true, NULL, 0, varroot_caches_blacklist, sizeof(varroot_caches_blacklist)/sizeof(varroot_caches_blacklist[0])},
    {"/var/root/Library/HTTPStorages", true, NULL, 0, varroot_http_blacklist, sizeof(varroot_http_blacklist)/sizeof(varroot_http_blacklist[0])},
    {"/var/root/Library/Preferences", true, NULL, 0, varroot_prefs_blacklist, sizeof(varroot_prefs_blacklist)/sizeof(varroot_prefs_blacklist[0])},
    {"/var/tmp", false, vartmp_whitelist, sizeof(vartmp_whitelist)/sizeof(vartmp_whitelist[0]), NULL, 0},
};

static int all_rules_count = sizeof(all_rules) / sizeof(all_rules[0]);

bool should_hide_file(const char *dir_path, const char *name) {
    if (!is_jailbreak_hidden_for_current_process()) {
        return false;
    }
    for (int i = 0; i < all_rules_count; i++) {
        if (strcmp(dir_path, all_rules[i].path) == 0) {
            DirRule *rule = &all_rules[i];
            for (int b = 0; b < rule->blacklist_count; b++) {
                if (match_rule(name, &rule->blacklist[b])) {
                    return true;
                }
            }
            if (!rule->default_deny) {
                bool in_whitelist = false;
                for (int w = 0; w < rule->whitelist_count; w++) {
                    if (match_rule(name, &rule->whitelist[w])) {
                        in_whitelist = true;
                        break;
                    }
                }
                if (!in_whitelist) return true;
            }
            return false;
        }
    }
    return false;
}

bool is_jailbreak_path(const char *path) {
    if (!path) return false;
    if (strstr(path, "/var/jb") == path) return true;
    if (JB_RandomRootPath && strstr(path, JB_RandomRootPath) == path) return true;
    const char *jailbreak_paths[] = {
        "/var/apt", "/var/dpkg", "/var/bin", "/var/usr",
        "/var/ssh", "/var/lib", "/var/etc", "/var/sbin",
        "/var/sh", "/var/share", "/var/local",
        "/var/master.passwd", "/var/zlogin", "/var/zshrc",
        "/usr/lib/TweakLoader.dylib",
        "/usr/lib/systemhook.dylib",
        NULL
    };
    for (int i = 0; jailbreak_paths[i] != NULL; i++) {
        if (strstr(path, jailbreak_paths[i]) != NULL) return true;
    }
    const char *jailbreak_bundles[] = {
        "com.opa334.Dopamine",
        "com.tigisoftware.Filza",
        "org.coolstar.SileoStore",
        "ws.hbang.Terminal",
        "xyz.willy.Zebra",
        "com.xina.jailbreak",
        "com.roothide.manager",
        "ru.domo.cocoatop64",
        NULL
    };
    for (int i = 0; jailbreak_bundles[i] != NULL; i++) {
        if (strstr(path, jailbreak_bundles[i]) != NULL) return true;
    }
    return false;
}

FilteredDIR *filtered_opendir(const char *name) {
    DIR *real = opendir(name);
    if (!real) return NULL;
    FilteredDIR *fdir = malloc(sizeof(FilteredDIR));
    if (!fdir) {
        closedir(real);
        return NULL;
    }
    fdir->real_dir = real;
    strncpy(fdir->dir_path, name, sizeof(fdir->dir_path) - 1);
    fdir->dir_path[sizeof(fdir->dir_path) - 1] = '\0';
    fdir->buffer = NULL;
    fdir->owner_pid = getpid();
    return fdir;
}

struct dirent *filtered_readdir(FilteredDIR *dirp) {
    if (!dirp || !dirp->real_dir) return NULL;
    if (dirp->owner_pid != getpid()) {
        dirp->owner_pid = getpid();
    }
    struct dirent *entry;
    while ((entry = readdir(dirp->real_dir)) != NULL) {
        if (!should_hide_file(dirp->dir_path, entry->d_name)) {
            return entry;
        }
    }
    return NULL;
}

int filtered_closedir(FilteredDIR *dirp) {
    if (!dirp) return -1;
    int ret = closedir(dirp->real_dir);
    free(dirp);
    return ret;
}

void init_var_filter(void) {
}

void cleanup_var_filter(void) {
    pthread_mutex_lock(&hidden_pids_mutex);
    hidden_pid_count = 0;
    pthread_mutex_unlock(&hidden_pids_mutex);
}