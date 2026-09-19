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

#define JB_PREFIX      "/var/jb"
#define JB_PREFIX_LEN  7

static bool gHideJb = false;

bool hide_jb_is_active(void) { return gHideJb; }

static bool should_hide_path(const char *path)
{
    if (!path || !gHideJb) return false;
    if (strncmp(path, JB_PREFIX, JB_PREFIX_LEN) != 0) return false;
    char next = path[JB_PREFIX_LEN];
    return (next == '\0' || next == '/');
}

/* ---------- open ---------- */
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

/* ---------- openat ---------- */
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

/* ---------- stat / lstat / fstatat ---------- */
static int stat_hook(const char *path, struct stat *buf)
{
    if (should_hide_path(path)) { errno = ENOENT; return -1; }
    return syscall(SYS_stat64, path, buf);
}

static int lstat_hook(const char *path, struct stat *buf)
{
    if (should_hide_path(path)) { errno = ENOENT; return -1; }
    return syscall(SYS_lstat64, path, buf);
}

static int fstatat_hook(int fd, const char *path, struct stat *buf, int flag)
{
    if (should_hide_path(path)) { errno = ENOENT; return -1; }
    return syscall(SYS_fstatat64, fd, path, buf, flag);
}

/* ---------- access ---------- */
static int access_hook(const char *path, int amode)
{
    if (should_hide_path(path)) { errno = ENOENT; return -1; }
    return syscall(SYS_access, path, amode);
}

/* ---------- statfs ---------- */
static int statfs_hook(const char *path, struct statfs *buf)
{
    if (should_hide_path(path)) { errno = ENOENT; return -1; }
    return syscall(SYS_statfs64, path, buf);
}

/* ---------- readlink ---------- */
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

/* ---------- opendir ----------
 * opendir 不是 syscall，所以用 open + fdopendir 模拟。
 * 其它情况下正确调用原语。 */
static DIR *opendir_hook(const char *path)
{
    if (should_hide_path(path)) { errno = ENOENT; return NULL; }
    int fd = syscall(SYS_open, path, O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0) return NULL;
    DIR *d = fdopendir(fd);
    if (!d) syscall(SYS_close, fd);
    return d;
}

void hide_jb_enable(void)
{
    if (gHideJb) return;
    gHideJb = true;

    litehook_hook_function(open,       open_hook);
    litehook_hook_function(openat,     openat_hook);
    litehook_hook_function(stat,       stat_hook);
    litehook_hook_function(lstat,      lstat_hook);
    litehook_hook_function(fstatat,    fstatat_hook);
    litehook_hook_function(access,     access_hook);
    litehook_hook_function(statfs,     statfs_hook);
    litehook_hook_function(readlink,   readlink_hook);
    litehook_hook_function(readlinkat, readlinkat_hook);
    litehook_hook_function(opendir,    opendir_hook);
}