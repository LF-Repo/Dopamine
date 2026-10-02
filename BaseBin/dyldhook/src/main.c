#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sandbox.h>
#include <libjailbreak/jbclient_mach.h>

#include "dyld.h"
#include "dyld_jbinfo.h"

bool gDyldHookLog = false;

__attribute__((section("__DATA,__jbinfo"))) static char jbinfoSection[0x4000];
#define jbInfo ((struct dyld_jbinfo *)&jbinfoSection[0])

bool gDyldhookInitDone = false;

bool jbinfo_is_checked_in(void)
{
	return jbInfo->state == DYLD_STATE_CHECKED_IN;
}

char *jbinfo_get_jbroot(void)
{
	return jbInfo->jbRootPath;
}

bool jbinfo_should_force_cs_adhoc(void)
{
	return jbInfo->forceCSAdhoc;
}

void consume_tokenized_sandbox_extensions(char *sandboxExtensions)
{
	if (sandboxExtensions[0] == '\0') return;

	char *it = sandboxExtensions;
	char *last = sandboxExtensions;
	while (*(++it) != '\0') {
		if (*it == '|') {
			*it = '\0';
			sandbox_extension_consume(last);
			last = &it[1];
			*it = '|';
		}
	}
	sandbox_extension_consume(last);
}

void dyldhook_perform_checkin(void)
{
	struct jbserver_mach_msg_checkin_reply *replyPtr; // Only for sizeof macro

	char *jbRootPathPtr = &jbInfo->data[0];
	char *bootUUIDPtr = &jbInfo->data[sizeof(replyPtr->jbRootPath)];
	char *sandboxExtensionsPtr = &jbInfo->data[sizeof(replyPtr->jbRootPath)+sizeof(replyPtr->bootUUID)];

	// Tell jbserver (in launchd) that this process exists
	// This will, amongst other things, disable page validation, which allows instruction hooks to be applied later
	if (jbclient_mach_process_checkin(jbRootPathPtr, bootUUIDPtr, sandboxExtensionsPtr, &jbInfo->fullyDebugged, &jbInfo->forceCSAdhoc) == 0) {
		if (gDyldHookLog) {
			_simple_dprintf(2, "Performed checkin [%s %s %s]\n", jbRootPathPtr, bootUUIDPtr, sandboxExtensionsPtr);
		}
		consume_tokenized_sandbox_extensions(sandboxExtensionsPtr);
		jbInfo->jbRootPath = jbRootPathPtr;
		jbInfo->bootUUID = bootUUIDPtr;
		jbInfo->sandboxExtensions = sandboxExtensionsPtr;
		jbInfo->state = DYLD_STATE_CHECKED_IN;
	}
	else {
		if (gDyldHookLog) {
			_simple_dprintf(2, "Checkin failed???\n");
		}
	}
}

int simple_atoi(char *p)
{
	int negate = p[0] == '-';
	if (negate) p++;

    int k = 0;
    while (*p) {
		if (*p >= '0' && *p <= '9') {
			k = k * 10 + (*p) - '0';
		}
		p++;
	}

	return (negate ? -1 : 1) * k;
}

mach_port_t mach_task_self_ = MACH_PORT_NULL;
void mach_init_4real(void)
{
	// Because mach_init has a "call once" mechanism, we can just call it ourselves without breaking anything in the later dyld flow
	// This allows us to have a proper pthread descriptor which fixes a whole bunch of stuff
	extern void mach_init(void);
	mach_init(); // This sets up mach_task_self_ in dyld but we can't get it since getting a global from dyld is not implemented in MachOMerger

	mach_task_self_ = task_self_trap();
	// Apparently task_self_trap increases the refcount of the task so we call deallocate again to decrease it
	mach_port_deallocate(mach_task_self_, mach_task_self_);
}

// ---- Stage 1 of the RootHide-style stealth injection ------------------------
//
// GOAL OF STAGE 1: prove, on a real device, that code running inside the merged
// dyld can make one of dyld's OWN __TEXT pages writable.
//
// Why that matters: a hook-based hide (systemhook.dylib) always leaves an extra
// image in the process, and an extra image can always be caught (its UUID never
// matches any real file at the claimed path). The only way out is to do the
// hiding from something that is ALREADY part of the process - the merged dyld -
// so that no extra image exists at all. Installing instruction hooks from dyld
// requires re-protecting a code page, which is exactly what this probes.
//
// It must run AFTER dyldhook_perform_checkin(): the check-in is what disables
// page validation and therefore allows re-protecting code pages.
//
// NOTE: this changes NO behaviour, it only logs. If vm_protect fails we find out
// here instead of halfway through stage 2.
//
// vm_protect is one of the trampolines MachOMerger created for us (see main.S);
// it is declared by hand with plain types so this file does not depend on which
// Mach headers happen to be pulled in. VM_PROT_* values: read 1, write 2,
// execute 4, copy 0x10 (copy => copy-on-write, so the dyld file on disk is not
// modified).
extern int vm_protect(mach_port_t target_task, unsigned long address, unsigned long size, int set_maximum, int new_protection);
// NOTE: variadic, to match the declaration pulled in by <sys/fcntl.h> (via
// <sandbox.h>) - declaring it as a fixed 3-arg function is a type conflict.
extern int open(const char *path, int flags, ...);
extern long write(int fd, const void *buf, unsigned long nbyte);

// Minimal logging helpers: this runs before libc exists, so there is no
// snprintf/printf here. We append to a file inside the jbroot instead, which the
// user can simply read with Filza.
static int gStage1Fd = -1;

static void stage1_puts(const char *s)
{
	if (gStage1Fd < 0) return;
	unsigned long n = 0;
	while (s[n]) n++;
	write(gStage1Fd, s, n);
}

static void stage1_put_int(long v)
{
	char tmp[24];
	int i = 0;
	int neg = 0;
	if (v < 0) { neg = 1; v = -v; }
	if (v == 0) tmp[i++] = '0';
	while (v > 0) { tmp[i++] = (char)('0' + (v % 10)); v /= 10; }
	if (neg) tmp[i++] = '-';
	char out[24];
	int j = 0;
	while (i > 0) out[j++] = tmp[--i];
	if (gStage1Fd >= 0) write(gStage1Fd, out, (unsigned long)j);
}

static void stage1_open_log(void)
{
	char *jbroot = jbinfo_get_jbroot();
	if (!jbroot) return;

	// "<jbroot>/basebin/hidejb_stage1.txt"
	char path[512];
	int i = 0;
	while (jbroot[i] && i < 440) { path[i] = jbroot[i]; i++; }
	const char *suffix = "/basebin/hidejb_stage1.txt";
	int k = 0;
	while (suffix[k] && i < 511) { path[i++] = suffix[k++]; }
	path[i] = '\0';

	// O_WRONLY|O_CREAT|O_TRUNC = 0x0001|0x0200|0x0400
	gStage1Fd = open(path, 0x0001 | 0x0200 | 0x0400, 0644);
}

static void dyldhook_probe_text_writable(void)
{
	const unsigned long pageSize = 0x4000;
	unsigned long probe = (unsigned long)(uintptr_t)&dyldhook_probe_text_writable;
	unsigned long pageStart = probe & ~(pageSize - 1);

	stage1_open_log();

	int kr = vm_protect(mach_task_self_, pageStart, pageSize, 0, 1 | 2 | 0x10);
	if (gDyldHookLog) {
		_simple_dprintf(2, "[hidejb stage1] vm_protect dyld __TEXT @0x%lx rw+copy -> %d\n", pageStart, kr);
	}

	stage1_puts("hidejb stage1 probe\npage=");
	stage1_put_int((long)pageStart);
	if (kr == 0) {
		stage1_puts("\nvm_protect RW+copy = OK\n");
		// Put it straight back: leaving a writable code page is itself a tell.
		int kr2 = vm_protect(mach_task_self_, pageStart, pageSize, 0, 1 | 4);
		if (gDyldHookLog) {
			_simple_dprintf(2, "[hidejb stage1] restore dyld __TEXT r-x -> %d\n", kr2);
		}
		stage1_puts("restore r-x = ");
		stage1_put_int((long)kr2);
		stage1_puts("\nRESULT: FEASIBLE\n");
	} else {
		stage1_puts("\nvm_protect RW+copy = FAILED kr=");
		stage1_put_int((long)kr);
		stage1_puts("\nRESULT: NOT-FEASIBLE\n");
	}
	if (gStage1Fd >= 0) { write(gStage1Fd, "", 0); }
}

void dyldhook_init(uintptr_t kernelParams)
{
	mach_init_4real();

	// If we are in launchd, bail out
	if (getpid() == 1) {
		return;
	}

	// Walk kernelParams to get envp
	uintptr_t argc = *(uintptr_t *)(kernelParams + sizeof(void *));
	char **argv = (char **)(kernelParams + sizeof(void *) + sizeof(argc));
	char **envp = (char **)(kernelParams + sizeof(void *) + sizeof(argc) + (sizeof(const char *) * argc) + sizeof(void *));

	if (_simple_getenv(envp, "DYLD_HOOK_PRINT") != NULL) {
		gDyldHookLog = true;
	}

	if (_simple_getenv(envp, "DYLD_HOOK_SETUID") != NULL) {
		int uid = 0, gid = 0, ruid = 0, rgid = 0, fd = -1;
		gid_t groups[NGROUPS_MAX] = { 0 };

		for (int i = 1; i < argc; i++) {
			if (gDyldHookLog) {
				_simple_dprintf(2, "Processing %s\n", argv[i]);
			}

			int r = argc - i - 1;
			if (!strcmp(argv[i], "--fd")) {
				if (r < 1) break;
				fd = simple_atoi(argv[++i]);
			}
			else if (!strcmp(argv[i], "--uid")) {
				if (r < 1) break;
				uid = simple_atoi(argv[++i]);
			}
			else if (!strcmp(argv[i], "--ruid")) {
				if (r < 1) break;
				ruid = simple_atoi(argv[++i]);
			}
			else if (!strcmp(argv[i], "--gid")) {
				if (r < 1) break;
				gid = simple_atoi(argv[++i]);
			}
			else if (!strcmp(argv[i], "--rgid")) {
				if (r < 1) break;
				rgid = simple_atoi(argv[++i]);
			}
			else if (!strcmp(argv[i], "--groups")) {
				if (r < NGROUPS_MAX) break;
				for (int k = 0; k < NGROUPS_MAX; k++) {
					groups[k] = simple_atoi(argv[++i]);
				}
			}
		}

		if (gDyldHookLog) {
			_simple_dprintf(2, "DYLD_HOOK_SETUID (fd=%d, uid=%d, ruid=%d, gid=%d, rgid=%d)\n", fd, uid, ruid, gid, rgid);
		}

		if (fd == -1) return;

		setgid(gid);
		setgid(gid);
		setregid(rgid, -1);
		int ngroups;
		for (ngroups = 0; ngroups < NGROUPS_MAX; ngroups++) {
			if (groups[ngroups] == -1) break;
		}
		setgroups(ngroups, groups);
		setuid(uid);
		setuid(uid);
		setreuid(ruid, -1);

		// if (gDyldHookLog) {
		// 	uid_t uid  = getuid();
		// 	uid_t euid = geteuid();
		// 	gid_t gid  = getgid();
		// 	gid_t egid = getegid();

		// 	_simple_dprintf(2, "PID  : %d\n", (int)getpid());
		// 	_simple_dprintf(2, "PPID : %d\n", (int)getppid());
		// 	_simple_dprintf(2, "uid  : real=%d  effective=%d\n", (int)uid,  (int)euid);
		// 	_simple_dprintf(2, "gid  : real=%d  effective=%d\n", (int)gid,  (int)egid);
		// }

		char r = 0x42;
		write(fd, &r, sizeof(r));

		__asm("b .");
	}

	// If DYLD_INSERT_LIBRARIES is not set or does not contain systemhook, bail out
	const char *insertLibrariesVar = _simple_getenv(envp, "DYLD_INSERT_LIBRARIES");
	if (!insertLibrariesVar) {
		if (gDyldHookLog) {
			_simple_dprintf(2, "Not checking in, DYLD_INSERT_LIBRARIES was not found\n");
		}
		return;		
	}
	if (!strstr(insertLibrariesVar, "/systemhook.dylib")) {
		if (gDyldHookLog) {
			_simple_dprintf(2, "Not checking in, no systemhook found in DYLD_INSERT_LIBRARIES (%s)\n", insertLibrariesVar);
		}
		return;
	}

	// If all is well, do check-in right here before dyld_start!
	dyldhook_perform_checkin();

	// Stage 1 probe: only for apps that launchdhook marked as hidden, and it only
	// logs. Nothing else about this process changes.
	if (_simple_getenv(envp, "DOPAMINE_APP_HIDE") != NULL) {
		dyldhook_probe_text_writable();
	}
}