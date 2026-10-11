#include "common.h"
#include <xpc/xpc.h>
#include <xpc_private.h>
#include <mach-o/dyld.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sandbox.h>
#include <paths.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include "envbuf.h"
#include "private.h"
#include <libjailbreak/jbclient_xpc.h>
#include <libjailbreak/jbserver_domains.h>
#include <libjailbreak/util.h>
#include <libjailbreak/jbroot.h>
#include <libjailbreak/hookd.h>
#include <libkern/OSCacheControl.h>

bool string_has_prefix(const char *str, const char* prefix)
{
	if (!str || !prefix) {
		return false;
	}

	size_t str_len = strlen(str);
	size_t prefix_len = strlen(prefix);

	if (str_len < prefix_len) {
		return false;
	}

	return !strncmp(str, prefix, prefix_len);
}

bool string_has_suffix(const char* str, const char* suffix)
{
	if (!str || !suffix) {
		return false;
	}

	size_t str_len = strlen(str);
	size_t suffix_len = strlen(suffix);

	if (str_len < suffix_len) {
		return false;
	}

	return !strcmp(str + str_len - suffix_len, suffix);
}

void string_enumerate_components(const char *string, const char *separator, void (^enumBlock)(const char *pathString, bool *stop))
{
	char *stringCopy = strdup(string);
	char *curString = strtok(stringCopy, separator);
	while (curString != NULL) {
		bool stop = false;
		enumBlock(curString, &stop);
		if (stop) break;
		curString = strtok(NULL, separator);
	}
	free(stringCopy);
}

int timespec_compare(struct timespec *t1, struct timespec *t2)
{
	if (t1->tv_sec == t2->tv_sec && t1->tv_nsec == t2->tv_nsec) return 0;

	if (t1->tv_sec == t2->tv_sec) {
		return t1->tv_nsec > t2->tv_nsec ? 1 : -1;
	}
	else {
		return t1->tv_sec > t2->tv_sec ? 1 : -1;
	}
}

xpc_object_t xpc_object_from_plist(const char *path)
{
	xpc_object_t xObj = NULL;
	int ldFd = open(path, O_RDONLY);
	if (ldFd >= 0) {
		struct stat s = {};
		if(fstat(ldFd, &s) != 0) {
			close(ldFd);
			return NULL;
		}
		size_t len = s.st_size;
		void *addr = mmap(NULL, len, PROT_READ, MAP_FILE | MAP_PRIVATE, ldFd, 0);
		if (addr != MAP_FAILED) {
			close(ldFd);

			xObj = xpc_create_from_plist(addr, len);
			munmap(addr, len);
		}
	}
	return xObj;
}

xpc_object_t jbuserconfig_get_value(const char *key)
{
	const char *configPath = JBROOT_PATH("/basebin/config.plist");
	if (!access(configPath, R_OK)) {
		static xpc_object_t configDict = NULL;
		static struct timespec lastConfigWrite = { .tv_sec=0, .tv_nsec = 0 };

		struct stat configStat;
		if (stat(configPath, &configStat) == 0) {
			if (timespec_compare(&configStat.st_mtimespec, &lastConfigWrite) > 0) {
				lastConfigWrite = configStat.st_mtimespec;
				if (configDict) xpc_release(configDict);
				configDict = xpc_object_from_plist(configPath);
			}
		}

		return xpc_dictionary_get_value(configDict, key);
	}

	return NULL;
}

static kSpawnConfig spawn_config_for_executable(const char* path, char *const argv[restrict])
{
	// Blacklist to ensure general system stability
	// I don't like this but for some processes it seems neccessary
	const char *processBlacklist[] = {
		"/System/Library/Frameworks/GSS.framework/Helpers/GSSCred",
		"/System/Library/PrivateFrameworks/DataAccess.framework/Support/dataaccessd",
		"/System/Library/PrivateFrameworks/IDSBlastDoorSupport.framework/XPCServices/IDSBlastDoorService.xpc/IDSBlastDoorService",
		"/System/Library/PrivateFrameworks/MessagesBlastDoorSupport.framework/XPCServices/MessagesBlastDoorService.xpc/MessagesBlastDoorService",
	};
	size_t blacklistCount = sizeof(processBlacklist) / sizeof(processBlacklist[0]);
	for (size_t i = 0; i < blacklistCount; i++)
	{
		if (!strcmp(processBlacklist[i], path)) return 0;
	}

	xpc_object_t userBlacklist = jbuserconfig_get_value("ProcessBlacklist");
	if (userBlacklist && xpc_get_type(userBlacklist) == XPC_TYPE_ARRAY) {
		size_t userBlacklistCount = xpc_array_get_count(userBlacklist);
		for (size_t i = 0; i < userBlacklistCount; i++) {
			if (!strcmp(xpc_array_get_string(userBlacklist, i), path)) return kSpawnConfigTrust;
		}
	}

	return (kSpawnConfigInject | kSpawnConfigTrust);
}

// Weak fallback so this translation unit can be linked into launchdhook (which
// does not compile hidejb.c). systemhook provides the strong definition in
// hidejb.c. When hidejb is active we must keep propagating DOPAMINE_APP_HIDE to
// children even though hidejb_init() unset it from our own environ (so the hide
// marker is not visible to the app as a "suspicious environment variable").
__attribute__((weak)) bool hidejb_is_hidden(void)
{
	return false;
}

// Derive the injected library path from the jailbreak root.
//
// Why this exists: HOOK_DYLIB_PATH is a constant, so any detector can hardcode
// "/usr/lib/systemhook.dylib" and simply look for that string in a process's
// environment. Varying the name per jailbreak removes that fixed feature.
//
// The name is derived from the jailbreak root rather than stored in a file: the
// jailbreak root already changes on every jailbreak (it lives under a per-boot
// preboot UUID), and every binary that needs this value can compute it from the
// same source, so there is no new state to keep in sync across launchdhook,
// systemhook and dyldhook. The trade-off is deliberate: the name stays constant
// for the lifetime of one jailbreak.
//
// The result stays inside /usr/lib and keeps a .dylib suffix on purpose. The
// fakelib mount publishes exactly that directory, and dyldhook needs the suffix
// to recognise the entry as our library (see dyldhook/src/main.c).
//
// Returns HOOK_DYLIB_PATH whenever anything is unexpected, so a failure here
// degrades to today's behaviour instead of breaking injection.
// Weak fallback so this translation unit also links into launchdhook, which
// compiles common.c but not systemhook's main.c and therefore has no
// get_jbroot(). systemhook provides the strong definition (systemhook/src/main.c).
// Without this, the link would fail with an undefined symbol.
__attribute__((weak)) char *get_jbroot(void)
{
	return NULL;
}

const char *hook_dylib_path(void)
{
	static char path[PATH_MAX];
	static dispatch_once_t onceToken;

	dispatch_once(&onceToken, ^{
		const char *jbroot = get_jbroot();
		if (!jbroot || !jbroot[0]) return; // keep the canonical path

		// FNV-1a over the jailbreak root: stable within one jailbreak, and
		// different across jailbreaks because the preboot UUID differs.
		uint64_t hash = 14695981039346656037ULL;
		for (const char *p = jbroot; *p; p++) {
			hash ^= (unsigned char)*p;
			hash *= 1099511628211ULL;
		}

		// Deliberately neutral: this must not resemble any real jailbreak library
		// name (no "ellekit", "hooker", "substrate", ...), both because a familiar
		// name would be a giveaway in itself and because the marker table in
		// hidejb_rules.c keys off such names.
		int n = snprintf(path, sizeof(path), "/usr/lib/lib_%016llx.dylib",
						 (unsigned long long)hash);
		if (n <= 0 || (size_t)n >= sizeof(path)) {
			path[0] = '\0'; // truncation or error: fall back below
			return;
		}

		// The variant name only helps if it actually resolves. fakelib publishes
		// /usr/lib and carries a symlink for the canonical name only, so publish a
		// matching symlink for the variant too.
		//
		// If we cannot create it we must NOT advertise the variant: dyld would
		// fail to load the library and the process would start with no jailbreak
		// hooks at all. Keeping the canonical path here is the safe degradation.
		//
		// Creating this link is idempotent: create() fails harmlessly with EEXIST
		// on every subsequent call.
		char linkTarget[PATH_MAX];
		n = snprintf(linkTarget, sizeof(linkTarget), "%s/basebin/%s",
					 jbroot, HOOK_DYLIB_NAME);
		if (n <= 0 || (size_t)n >= sizeof(linkTarget)) {
			path[0] = '\0';
			return;
		}

		if (symlink(linkTarget, path) != 0 && access(path, F_OK) != 0) {
			path[0] = '\0';
		}
	});

	return path[0] ? path : HOOK_DYLIB_PATH;
}

// 1. Ensure the binary about to be spawned and all of it's dependencies are trust cached
// 2. Insert "DYLD_INSERT_LIBRARIES=/usr/lib/systemhook.dylib" into all binaries spawned
// 3. Increase Jetsam limit to more sane value (Multipler defined as JETSAM_MULTIPLIER)
// 4. Fix spawning as root via persona entitlement on iOS 17.6+

static int spawn_exec_hook_common(bool isExec,
						   const char *path,
						   char *const argv[restrict],
						   char *const envp[restrict],
		struct _posix_spawn_args_desc *desc,
								 int (*trust_binary)(const char *path),
								double jetsamMultiplier,
								 int (^orig)(pid_t *pid, char *const envp[restrict]))
{
	if (!path) {
		return orig(NULL, envp);
	}

	bool personaFixNeedsResume = true;
	int personaFixUid = -1;
	int personaFixGid = -1;
	posix_spawnattr_t attr = NULL;
	if (desc) attr = desc->attrp;

	kSpawnConfig spawnConfig = spawn_config_for_executable(path, argv);

	if (spawnConfig & kSpawnConfigTrust) {
		// Upload binary to trustcache if needed
		trust_binary(path);
	}

	const char *existingLibraryInserts = envbuf_getenv((const char **)envp, "DYLD_INSERT_LIBRARIES");
	__block bool systemHookAlreadyInserted = false;
	if (existingLibraryInserts) {
		string_enumerate_components(existingLibraryInserts, ":", ^(const char *existingLibraryInsert, bool *stop) {
			if (!strcmp(existingLibraryInsert, hook_dylib_path())) {
				systemHookAlreadyInserted = true;
			}
		});
	}

	int JBEnvAlreadyInsertedCount = (int)systemHookAlreadyInserted;

	// Check if we can find at least one reason to not insert jailbreak related environment variables
	// In this case we also need to remove pre existing environment variables if they are already set
	bool shouldInsertJBEnv = true;
	bool hasSafeModeVariable = false;
	do {
		if (!(spawnConfig & kSpawnConfigInject)) {
			shouldInsertJBEnv = false;
			break;
		}

		// Check if we can find a _SafeMode or _MSSafeMode variable
		// In this case we do not want to inject anything
		const char *safeModeValue = envbuf_getenv((const char **)envp, "_SafeMode");
		const char *msSafeModeValue = envbuf_getenv((const char **)envp, "_MSSafeMode");
		if (safeModeValue) {
			if (!strcmp(safeModeValue, "1")) {
				shouldInsertJBEnv = false;
				hasSafeModeVariable = true;
				break;
			}
		}
		if (msSafeModeValue) {
			if (!strcmp(msSafeModeValue, "1")) {
				shouldInsertJBEnv = false;
				hasSafeModeVariable = true;
				break;
			}
		}

		int proctype = 0;
		if (posix_spawnattr_getprocesstype_np(&attr, &proctype) == 0) {
			if (proctype == POSIX_SPAWN_PROC_TYPE_DRIVER) {
				// Do not inject hook into DriverKit drivers
				shouldInsertJBEnv = false;
				break;
			}
		}

		// Keep checking the canonical path here: that is the file that exists on
		// disk. hook_dylib_path() is a symlink to it, so either check works, but
		// the canonical one keeps this independent of the variant derivation.
		if (access(HOOK_DYLIB_PATH, F_OK) != 0) {
			// If the hook dylib doesn't exist, don't try to inject it (would crash the process)
			shouldInsertJBEnv = false;
			break;
		}
	} while (0);

	uint8_t *attrStruct = (uint8_t *)attr;
	if (attrStruct) {
		// If systemhook is being injected and jetsam limits are set, increase them by a factor of jetsamMultiplier
		if (shouldInsertJBEnv) {
			if (jetsamMultiplier == 0 || isnan(jetsamMultiplier)) jetsamMultiplier = 3; // default value (3x)
			if (jetsamMultiplier > 1) {
				int memlimit_active = *(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_ACTIVE);
				if (memlimit_active != -1) {
					*(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_ACTIVE) = memlimit_active * jetsamMultiplier;
				}
				int memlimit_inactive = *(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_INACTIVE);
				if (memlimit_inactive != -1) {
					*(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_INACTIVE) = memlimit_inactive * jetsamMultiplier;
				}
			}
		}

		// On iOS 17.6 and up Apple neutered persona overwrites to block going from (non root) -> (root)
		// Since jailbreak infra relies on this, we need to reenable it via our patches
		// To do this we will spawn the process as suspended, modify the ucred to the desired uid/gid and resume it
		// POSIX_SPAWN_SETEXEC is not a concern since using it together with POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE is not supported anyways
		if (__builtin_available(iOS 17.6, *)) {
			bool hasExecFlag = false;
			short flags = 0;
			if (posix_spawnattr_getflags(&attr, &flags) == 0) {
				if (flags & POSIX_SPAWN_SETEXEC) {
					hasExecFlag = true;
				}
			}
			if (!hasExecFlag && !isExec && getuid() != 0) {
				struct _posix_spawn_persona_info *personaInfo = *(struct _posix_spawn_persona_info **)(attrStruct + POSIX_SPAWNATTR_OFF_PERSONA);
				if (personaInfo) {
					if (personaInfo->pspi_id == 99 && (personaInfo->pspi_flags & POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE)) {
						if (personaInfo->pspi_flags & POSIX_SPAWN_PERSONA_UID) {
							personaFixUid = personaInfo->pspi_uid;
						}
						if (personaInfo->pspi_flags & POSIX_SPAWN_PERSONA_GID) {
							personaFixGid = personaInfo->pspi_gid;
						}
					}
				}

				if (personaFixUid == 0 || personaFixGid == 0) {
					// Revert any request to become root back to mobile
					// Otherwise posix_spawn will straight up fail
					if (personaFixUid == 0) personaInfo->pspi_uid = 501;
					if (personaFixGid == 0) personaInfo->pspi_gid = 501;

					if (flags & POSIX_SPAWN_START_SUSPENDED) {
						personaFixNeedsResume = false;
					}
					else {
						posix_spawnattr_setflags(&attr, flags | POSIX_SPAWN_START_SUSPENDED);
					}
				}
			}
		}
	}

	int r = -1;

	pid_t childPid = -1;

	bool hideChild = hidejb_is_hidden();

	if (!hideChild && ((shouldInsertJBEnv && JBEnvAlreadyInsertedCount == 1) || (!shouldInsertJBEnv && JBEnvAlreadyInsertedCount == 0 && !hasSafeModeVariable))) {
		// we're already good, just call orig
		r = orig(&childPid, envp);
	}
	else {
		// the state we want to be in is not the state we are in right now

		char **envc = envbuf_mutcopy((const char **)envp);

		if (shouldInsertJBEnv) {
			if (!systemHookAlreadyInserted) {
				const char *hookPath = hook_dylib_path();
				size_t hookPathLen = strlen(hookPath);
				char newLibraryInsert[hookPathLen + (existingLibraryInserts ? (strlen(existingLibraryInserts) + 1) : 0) + 1];
				strcpy(newLibraryInsert, hookPath);
				if (existingLibraryInserts) {
					strcat(newLibraryInsert, ":");
					strcat(newLibraryInsert, existingLibraryInserts);
				}
				envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", newLibraryInsert);
			}
			// Keep dyld from merging the injected library into the shared cache image
			// list. RootHide sets this unconditionally on the injection path
			// (roothider.m); we do the same, but only when we really injected this
			// child — a child that merely inherited the variable already has it set,
			// and rewriting it would be pure noise on the spawn path.
			//
			// Beyond matching RootHide this is what makes the hide reliable: an image
			// that dyld caches gets its __DATA_CONST shared, so our vm_protect-based
			// hooks cannot patch it and the process keeps seeing the real jailbreak
			// state.
			if (envbuf_getenv((const char **)envc, "DYLD_INSERT_LIBRARIES")) {
				envbuf_setenv(&envc, "DYLD_IN_CACHE", "0");
			}
			if (hideChild) {
				// Re-add the hide marker that hidejb_init() unset from our own
				// environ, so child processes keep hiding.
				envbuf_setenv(&envc, "DOPAMINE_APP_HIDE", "1");
			}
		}
		else {
			if (systemHookAlreadyInserted && existingLibraryInserts) {
				if (!strcmp(existingLibraryInserts, hook_dylib_path())) {
					envbuf_unsetenv(&envc, "DYLD_INSERT_LIBRARIES");
				}
				else {
					char *newLibraryInsert = malloc(strlen(existingLibraryInserts)+1);
					newLibraryInsert[0] = '\0';

					__block bool first = true;
					string_enumerate_components(existingLibraryInserts, ":", ^(const char *existingLibraryInsert, bool *stop) {
						if (strcmp(existingLibraryInsert, hook_dylib_path()) != 0) {
							if (first) {
								strcpy(newLibraryInsert, existingLibraryInsert);
								first = false;
							}
							else {
								strcat(newLibraryInsert, ":");
								strcat(newLibraryInsert, existingLibraryInsert);
							}
						}
					});
					envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", newLibraryInsert);

					free(newLibraryInsert);
				}
			}
			envbuf_unsetenv(&envc, "_SafeMode");
			envbuf_unsetenv(&envc, "_MSSafeMode");
		}

		r = orig(&childPid, envc);

		envbuf_free(envc);
	}

	if (personaFixUid == 0 || personaFixGid == 0 && childPid != -1) {
		jbclient_persona_fix(childPid, personaFixUid, personaFixGid);
		if (personaFixNeedsResume) {
			kill(childPid, SIGCONT);
		}
	}

	return r;
}

int posix_spawn_hook_shared(pid_t *restrict pid, 
					   const char *restrict path,
			 struct _posix_spawn_args_desc *desc,
						  	    char *const argv[restrict],
					   			char *const envp[restrict],
					   				  void *orig,
					   				  int (*trust_binary)(const char *path),
					   				  int (*set_process_debugged)(uint64_t pid, bool fullyDebugged),
					   				 double jetsamMultiplier)
{
	int (*posix_spawn_orig)(pid_t *restrict, const char *restrict, struct _posix_spawn_args_desc *, char *const[restrict], char *const[restrict]) = orig;

	int r = spawn_exec_hook_common(false, path, argv, envp, desc, trust_binary, jetsamMultiplier, ^int(pid_t *pidOut, char *const envp_patched[restrict]) {
		int rr = posix_spawn_orig(pid ?: pidOut, path, desc, argv, envp_patched);
		if (rr == 0 && pid && pidOut) {
			*pidOut = *pid;
		}
		return rr;
	});

	if (r == 0 && pid && desc) {
		posix_spawnattr_t attr = desc->attrp;
		short flags = 0;
		if (posix_spawnattr_getflags(&attr, &flags) == 0) {
			if (flags & POSIX_SPAWN_START_SUSPENDED) {
				// If something spawns a process as suspended, ensure mapping invalid pages in it is possible
				// Normally it would only be possible after systemhook.dylib enables it
				// Fixes Frida issues
				set_process_debugged(*pid, false);
			}
		}
	}

	return r;
}

kern_return_t vm_allocate_nearby(vm_map_t target_task, vm_address_t from_area, vm_size_t from_area_size, vm_address_t *address, vm_size_t size, uint64_t limit)
{
	if (from_area != 0 && from_area_size > 0 && address) {
		// Make sure allocation is within limit for every single page in the area
		uint64_t realLimit = limit - (from_area_size / 2);

		for (uint64_t off = 0; off < realLimit; off += vm_page_size) {
			vm_address_t tmp = (from_area + from_area_size) + off;
			kern_return_t kr = vm_allocate(target_task, &tmp, size, VM_FLAGS_FIXED);
			if (kr == KERN_SUCCESS) {
				*address = tmp;
				return kr;
			}

			tmp = (from_area - size) - off;
			kr = vm_allocate(target_task, &tmp, size, VM_FLAGS_FIXED);
			if (kr == KERN_SUCCESS) {
				*address = tmp;
				return kr;
			}
		}
	}

	return KERN_NO_SPACE;
}

int execve_hook_shared(const char *path,
					   char *const argv[],
					   char *const envp[],
			 				 void *orig,
			 				 int (*trust_binary)(const char *path))
{
	int (*execve_orig)(const char *, char *const[], char *const[]) = orig;

	int r = spawn_exec_hook_common(true, path, argv, envp, NULL, trust_binary, 0, ^int(pid_t *pidOut, char *const envp_patched[restrict]){
		return execve_orig(path, argv, envp_patched);
	});

	return r;
}

__attribute__((noinline, naked)) volatile void *get_tpidrr0_el0(void)
{
	asm("MRS X0, TPIDRRO_EL0");
	asm("RET");
}

kern_return_t litehook_hook_memory_hookd(void *target, void *source, size_t sourceSize)
{
	kern_return_t kr = hookd_hook(mach_task_self_, (uint64_t)target, source, sourceSize);
	if (kr == KERN_SUCCESS) {
		sys_icache_invalidate(target, sourceSize);
	}
	return kr;
}

kern_return_t mach_vm_protect_fixed(mach_port_name_t task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection)
{
	kern_return_t rv;

	bool skipped = false;
	if (!skipped) {
		if ((new_protection & VM_PROT_EXECUTE) || (new_protection & VM_PROT_COPY)) {
			rv = hookd_vm_protect(task, address, size, set_maximum, new_protection);
		}
		else {
			rv = _kernelrpc_mach_vm_protect_trap(task, address, size, set_maximum, new_protection);
			if (rv == MACH_SEND_INVALID_DEST) {
				rv = _kernelrpc_mach_vm_protect(task, address, size, set_maximum, new_protection);
			}
		}
	}

	return rv;
}
