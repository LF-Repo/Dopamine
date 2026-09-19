#include "hide_jb.h"
#include "common.h"
#include "litehook.h"

#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

static bool gHideJb = false;

bool hide_jb_is_active(void) { return gHideJb; }


static const char *kHidePrefixes[] = {
    "/var/jb",
    "/var/mobile/.DO-NOT-DELETE-Cowabunga",
    "/var/mobile/.Derootifier",
    "/var/mobile/Helix",
    "/var/mobile/.ssh",
    "/var/mobile/.cache",
    "/var/mobile/.DopamineHideQuarantine",
    "/var/mobile/.DopamineCrashReporterDisabled",
    NULL
};


static const char *kHideBasenamePrefixes[] = {
    "com.opa334.Dopamine",
    "com.tigisoftware.Filza",
    "org.coolstar.SileoStore",
    "ws.hbang.Terminal",
    "xyz.willy.Zebra",
    "ru.domo.cocoatop64",
    "com.roothide.manager",
    "com.xina.jailbreak",
    "com.apple.Terminal",
    "com.apple.terminal",
    "com.hackemist.SDImageCache",
    "com.johncoates.Flex",
    NULL
};


static const char *kHideFilenames[] = {
    "Sileo",
    "Filza",
    "Flex3",
    "SBSettings",
    "iCleaner",
    "Cephei",
    "GDFileManagerCache.sqlite",
    "GDFileManagerCache.sqlite-shm",
    "GDFileManagerCache.sqlite-wal",
    "ImageTables",
    "SentryCrash",
    "io.sentry",
    "Flex3Patches.plist",
    "DumpDecrypter",
    "Dumplpa",
    ".misaka",
    NULL
};

static bool matches_hide_prefix(const char *path)
{
    for (int i = 0; kHidePrefixes[i]; i++) {
        size_t plen = strlen(kHidePrefixes[i]);
        if (strncmp(path, kHidePrefixes[i], plen) == 0) {
            char next = path[plen];
            if (next == '\0' || next == '/') return true;
        }
    }
    return false;
}

static bool matches_hide_basename(const char *path)
{
    const char *basename = strrchr(path, '/');
    if (!basename) return false;
    basename++;


    for (int i = 0; kHideBasenamePrefixes[i]; i++) {
        if (strncmp(basename, kHideBasenamePrefixes[i], strlen(kHideBasenamePrefixes[i])) == 0) {
            return true;
        }
    }


    for (int i = 0; kHideFilenames[i]; i++) {
        if (strcmp(basename, kHideFilenames[i]) == 0) return true;
    }

    return false;
}

static bool should_hide_path(const char *path)
{
    if (!path || !gHideJb) return false;
    if (path[0] != '/') return false;
    if (strncmp(path, "/var/", 5) != 0) return false;

    if (matches_hide_prefix(path)) return true;
    if (matches_hide_basename(path)) return true;

    return false;
}



static int open_hook(const char *path, int oflag, ...)
{
    if (should_hide_path(path)) { errno = ENOENT; return -1; }
    mode_t mode = 0;
    if (oflag & O_CREAT) {
        va_list ap; va_start(ap, oflag);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    return syscall(SYS_open, path, oflag, mode);
}

static int openat_hook(int fd, const char *path, int oflag, ...)
{
    if (should_hide_path(path)) { errno = ENOENT; return -1; }
    mode_t mode = 0;
    if (oflag & O_CREAT) {
        va_list ap; va_start(ap, oflag);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    return syscall(SYS_openat, fd, path, oflag, mode);
}

static int stat_hook(const char *path, struct stat *buf)
{
    if (should_hide_path(path)) { errno = ENOENT; return -1; }
    return syscall(SYS_stat, path, buf);
}

static int lstat_hook(const char *path, struct stat *buf)
{
    if (should_hide_path(path)) { errno = ENOENT; return -1; }
    return syscall(SYS_lstat, path, buf);
}

static int fstatat_hook(int fd, const char *path, struct stat *buf, int flag)
{
    if (should_hide_path(path)) { errno = ENOENT; return -1; }
    return syscall(SYS_fstatat, fd, path, buf, flag);
}

static int access_hook(const char *path, int amode)
{
    if (should_hide_path(path)) { errno = ENOENT; return -1; }
    return syscall(SYS_access, path, amode);
}

static int statfs_hook(const char *path, struct statfs *buf)
{
    if (should_hide_path(path)) { errno = ENOENT; return -1; }
    return syscall(SYS_statfs, path, buf);
}

static ssize_t readlink_hook(const char *path, char *buf, size_t bufsize)
{
    if (should_hide_path(path)) { errno = ENOENT; return -1; }
    return syscall(SYS_readlink, path, buf, bufsize);
}

static ssize_t readlinkat_hook(int fd, const char *path, char *buf, size_t bufsize)
{
    if (should_hide_path(path)) { errno = ENOENT; return -1; }
    return syscall(SYS_readlinkat, fd, path, buf, bufsize);
}

static DIR *opendir_hook(const char *path)
{
    if (should_hide_path(path)) { errno = ENOENT; return NULL; }
    int fd = syscall(SYS_open, path, O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0) return NULL;
    DIR *d = fdopendir(fd);
    if (!d) syscall(SYS_close, fd);
    return d;
}

#include <dlfcn.h>

void hide_jb_enable(void)
{
    if (gHideJb) return;
    gHideJb = true;

    litehook_hook_function(open,   open_hook);
    litehook_hook_function(openat, openat_hook);

    void *real_access = dlsym(RTLD_DEFAULT, "access");
    if (real_access) litehook_hook_function(real_access, access_hook);


    // void *real_stat     = dlsym(RTLD_DEFAULT, "stat");
    // void *real_lstat    = dlsym(RTLD_DEFAULT, "lstat");
    // void *real_fstatat  = dlsym(RTLD_DEFAULT, "fstatat");
    // void *real_statfs   = dlsym(RTLD_DEFAULT, "statfs");
    // void *real_readlink = dlsym(RTLD_DEFAULT, "readlink");
    // if (real_stat)     litehook_hook_function(real_stat,     stat_hook);
    // if (real_lstat)    litehook_hook_function(real_lstat,    lstat_hook);
    // if (real_fstatat)  litehook_hook_function(real_fstatat,  fstatat_hook);
    // if (real_statfs)   litehook_hook_function(real_statfs,   statfs_hook);
    // if (real_readlink) litehook_hook_function(real_readlink, readlink_hook);
}