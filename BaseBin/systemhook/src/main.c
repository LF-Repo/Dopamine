#include "common/common.h"

#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/getsect.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <paths.h>
#include <util.h>
#include <ptrauth.h>
#include <libjailbreak/jbclient_xpc.h>
#include <libjailbreak/codesign.h>
#include <libjailbreak/jbroot.h>
#include <libjailbreak/hookd.h>
#include "../dyldhook/src/dyld_jbinfo.h"
#include "common/hookd_external.h"
#include <choma/CSBlob.h>
#include "litehook.h"
#include "sandbox.h"
#include "common/private.h"
#include "common/inline.h"
#include <stdarg.h>

bool gFullyDebugged = false;
static void *gLibSandboxHandle;
char *JB_BootUUID = NULL;
char *JB_RootPath = NULL;
char *get_jbroot(void) { return JB_RootPath; }

static char gExecutablePath[PATH_MAX];
static int load_executable_path(void)
{
	char executablePath[PATH_MAX];
	uint32_t bufsize = PATH_MAX;
	if (_NSGetExecutablePath(executablePath, &bufsize) == 0) {
		if (realpath(executablePath, gExecutablePath) != NULL) return 0;
	}
	return -1;
}

static char *JB_SandboxExtensions = NULL;

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

void *(*sandbox_apply_orig)(void *) = NULL;
void *sandbox_apply_hook(void *a1)
{
	void *r = sandbox_apply_orig(a1);
	consume_tokenized_sandbox_extensions(JB_SandboxExtensions);
	return r;
}

int dyld_hook_routine(void **dyld, int idx, void *hook, void **orig, uint16_t pacSalt)
{
	if (!dyld) return -1;

	uint64_t dyldPacDiversifier = ((uint64_t)dyld & ~(0xFFFFull << 48)) | (0x63FAull << 48);
	void **dyldFuncPtrs = ptrauth_auth_data(*dyld, ptrauth_key_process_independent_data, dyldPacDiversifier);
	if (!dyldFuncPtrs) return -1;

	if (vm_protect(mach_task_self_, (mach_vm_address_t)&dyldFuncPtrs[idx], sizeof(void *), false, VM_PROT_READ | VM_PROT_WRITE) == 0) {
		uint64_t location = (uint64_t)&dyldFuncPtrs[idx];
		uint64_t pacDiversifier = (location & ~(0xFFFFull << 48)) | ((uint64_t)pacSalt << 48);

		*orig = ptrauth_auth_and_resign(dyldFuncPtrs[idx], ptrauth_key_process_independent_code, pacDiversifier, ptrauth_key_function_pointer, 0);
		dyldFuncPtrs[idx] = ptrauth_auth_and_resign(hook, ptrauth_key_function_pointer, 0, ptrauth_key_process_independent_code, pacDiversifier);
		vm_protect(mach_task_self_, (mach_vm_address_t)&dyldFuncPtrs[idx], sizeof(void *), false, VM_PROT_READ);
		return 0;
	}

	return -1;
}

void *(*dyld_dlsym_orig)(void *dyld, void *handle, const char *name);
void *dyld_dlsym_hook(void *dyld, void *handle, const char *name)
{
	if (handle == gLibSandboxHandle && !strcmp(name, "sandbox_apply")) {
		return sandbox_apply_hook;
	}
	__attribute__((musttail)) return dyld_dlsym_orig(dyld, handle, name);
}

int ptrace_hook(int request, pid_t pid, caddr_t addr, int data)
{
	int r = ptrace_inline(request, pid, addr, data);

	if (r == 0 && (request == PT_ATTACHEXC || request == PT_ATTACH)) {
		jbclient_platform_set_process_debugged(pid, true);
		jbclient_platform_set_process_debugged(getpid(), true);
	}

	return r;
}

#ifndef __arm64e__

int necp_match_policy_hook(uint8_t *parameters, size_t parameters_size, void *returned_result)
{
	jbclient_cs_revalidate();
	return syscall(SYS_necp_match_policy, parameters, parameters_size, returned_result);
}

int necp_open_hook(int flags)
{
	jbclient_cs_revalidate();
	return syscall(SYS_necp_open, flags);
}

int necp_client_action_hook(int necp_fd, uint32_t action, uuid_t client_id, size_t client_id_len, uint8_t *buffer, size_t buffer_size)
{
	jbclient_cs_revalidate();
	return syscall(SYS_necp_client_action, necp_fd, action, client_id, client_id_len, buffer, buffer_size);
}

int necp_session_open_hook(int flags)
{
	jbclient_cs_revalidate();
	return syscall(SYS_necp_session_open, flags);
}

int necp_session_action_hook(int necp_fd, uint32_t action, uint8_t *in_buffer, size_t in_buffer_length, uint8_t *out_buffer, size_t out_buffer_length)
{
	jbclient_cs_revalidate();
	return syscall(SYS_necp_session_action, necp_fd, action, in_buffer, in_buffer_length, out_buffer, out_buffer_length);
}

int csops_hook(pid_t pid, unsigned int ops, void *useraddr, size_t usersize)
{
	int rv = syscall(SYS_csops, pid, ops, useraddr, usersize);
	if (rv != 0) return rv;
	if (ops == CS_OPS_STATUS) {
		if (useraddr && usersize == sizeof(uint32_t)) {
			uint32_t* csflag = (uint32_t *)useraddr;
			*csflag |= CS_VALID;
			*csflag &= ~CS_DEBUGGED;
			if (pid == getpid() && gFullyDebugged) {
				*csflag |= CS_DEBUGGED;
			}
		}
	}
	return rv;
}

int csops_audittoken_hook(pid_t pid, unsigned int ops, void *useraddr, size_t usersize, audit_token_t *token)
{
	int rv = syscall(SYS_csops_audittoken, pid, ops, useraddr, usersize, token);
	if (rv != 0) return rv;
	if (ops == CS_OPS_STATUS) {
		if (useraddr && usersize == sizeof(uint32_t)) {
			uint32_t* csflag = (uint32_t *)useraddr;
			*csflag |= CS_VALID;
			*csflag &= ~CS_DEBUGGED;
			if (pid == getpid() && gFullyDebugged) {
				*csflag |= CS_DEBUGGED;
			}
		}
	}
	return rv;
}

#endif

// ============ 增强隐藏逻辑（仅在开启"隐藏越狱"后生效） ============

static bool gHideJailbreakEnabled = false;

static bool hide_path_string(const char *path)
{
	if (!path) return false;
	if (!gHideJailbreakEnabled) return false;  // 未开启隐藏越狱，直接放行

	const char *rules[] = {
		// 越狱根目录和工具路径
		"/var/jb",
		"/var/binpack",
		"/var/stash",
		// Substrate / Tweak 注入相关
		"/Library/MobileSubstrate",
		"/Library/PreferenceBundles",
		"/usr/lib/TweakInject",
		"/usr/libexec/ellekit",
		"/usr/libexec/substitute",
		"/usr/libexec/libhooker",
		"/usr/libexec/roothide",
		// 越狱商店应用（系统不会访问这些路径）
		"/Applications/Dopamine.app",
		"/Applications/RootHide.app",
		"/Applications/Sileo.app",
		"/Applications/Zebra.app",
		"/Applications/Filza.app",
		"/Applications/Installer.app",
		// 越狱应用的偏好设置（仅特定 plist，不影响系统服务）
		"/var/mobile/Library/Preferences/com.opa334.Dopamine",
		"/var/mobile/Library/Preferences/com.roothide.manager",
		"/var/mobile/Library/Preferences/org.coolstar.SileoStore",
		"/var/mobile/Library/Preferences/com.tigisoftware.Filza",
		"/var/mobile/Library/Preferences/xyz.willy.Zebra",
		"/var/mobile/Library/Application Support/xyz.willy.Zebra",
		"/var/mobile/Library/Application Support/com.tigisoftware.Filza",
		// Bundle ID 和关键词子串匹配（用于动态生成的路径）
		"com.opa334.Dopamine",
		"com.roothide.manager",
		"org.coolstar.SileoStore",
		"com.tigisoftware.Filza",
		"xyz.willy.Zebra",
		"ws.hbang.Terminal",
		"ru.domo.cocoatop64",
		"com.xina.jailbreak",
		"jailbreak",
		"substrate",
		"cydia",
		"sileo",
		"zebra",
		"tweak",
		"filza",
		NULL
	};
	for (int i = 0; rules[i]; i++) {
		if (strstr(path, rules[i])) return true;
	}
	return false;
}

static bool hide_url_string(const char *url)
{
	if (!url) return false;
	if (!gHideJailbreakEnabled) return false;  // 未开启隐藏越狱，直接放行

	const char *rules[] = {
		"cydia://",
		"sileo://",
		"zebra://",
		"filza://",
		"dopamine://",
		"roothide://",
		"rootless://",
		"xina://",
		"unc0ver://",
		"checkra1n://",
		"palera1n://",
		"installer://",
		"saily://",
		"terminal://",
		"newterm://",
		"libhooker://",
		"substrate://",
		NULL
	};
	for (int i = 0; rules[i]; i++) {
		if (strstr(url, rules[i])) return true;
	}
	return false;
}

static int (*orig_access)(const char *, int);
static int hide_access(const char *path, int mode)
{
	if (hide_path_string(path)) {
		errno = ENOENT;
		return -1;
	}
	return orig_access(path, mode);
}

static int (*orig_stat)(const char *, struct stat *);
static int hide_stat(const char *path, struct stat *buf)
{
	if (hide_path_string(path)) {
		errno = ENOENT;
		return -1;
	}
	return orig_stat(path, buf);
}

static int (*orig_lstat)(const char *, struct stat *);
static int hide_lstat(const char *path, struct stat *buf)
{
	if (hide_path_string(path)) {
		errno = ENOENT;
		return -1;
	}
	return orig_lstat(path, buf);
}

static int (*orig_open)(const char *, int, ...);
static int hide_open(const char *path, int flags, ...)
{
	if (hide_path_string(path)) {
		errno = ENOENT;
		return -1;
	}
	if (flags & O_CREAT) {
		va_list ap;
		va_start(ap, flags);
		int mode = va_arg(ap, int);
		va_end(ap);
		return orig_open(path, flags, mode);
	}
	return orig_open(path, flags);
}

static char *(*orig_realpath)(const char *, char *);
static char *hide_realpath(const char *path, char *resolved)
{
	if (hide_path_string(path)) {
		errno = ENOENT;
		return NULL;
	}
	return orig_realpath(path, resolved);
}

// ============ 增强隐藏逻辑结束 ============

bool should_enable_tweaks(void)
{
	if (access(JBROOT_PATH("/basebin/.safe_mode"), F_OK) == 0) {
		return false;
	}

	char *tweaksDisabledEnv = getenv("DISABLE_TWEAKS");
	if (tweaksDisabledEnv) {
		if (!strcmp(tweaksDisabledEnv, "1")) {
			return false;
		}
	}

	if (jbclient_dopamine_is_jailbroken(NULL)) {
		return false;
	}

	const char *tweaksDisabledPathSuffixes[] = {
		"/usr/libexec/xpcproxy",
	};
	for (size_t i = 0; i < sizeof(tweaksDisabledPathSuffixes) / sizeof(const char*); i++) {
		if (string_has_suffix(gExecutablePath, tweaksDisabledPathSuffixes[i])) return false;
	}

	if (__builtin_available(iOS 16.0, *)) {
		const char *iOS16TweaksDisabledPaths[] = {
			"/usr/libexec/logd",
			"/usr/sbin/notifyd",
			"/usr/libexec/usermanagerd",
		};
		for (size_t i = 0; i < sizeof(iOS16TweaksDisabledPaths) / sizeof(const char*); i++) {
			if (!strcmp(gExecutablePath, iOS16TweaksDisabledPaths[i])) return false;
		}
	}

	return true;
}

int __posix_spawn_hook(pid_t *restrict pid, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char * const envp[restrict])
{
	return posix_spawn_hook_shared(pid, path, desc, argv, envp, (void *)__posix_spawn_inline, jbclient_trust_file_by_path, jbclient_platform_set_process_debugged, jbclient_jbsettings_get_double("jetsamMultiplier"));
}

int __posix_spawn_hook_with_filter(pid_t *restrict pid, const char *restrict path, char *const argv[restrict], char * const envp[restrict], struct _posix_spawn_args_desc *desc, int *ret)
{
	*ret = posix_spawn_hook_shared(pid, path, desc, argv, envp, (void *)__posix_spawn_inline, jbclient_trust_file_by_path, jbclient_platform_set_process_debugged, jbclient_jbsettings_get_double("jetsamMultiplier"));
	return 1;
}

int __execve_hook(const char *path, char *const argv[], char *const envp[])
{
	return execve_hook_shared(path, argv, envp, (void *)__execve_inline, jbclient_trust_file_by_path);
}

xpc_object_t copy_entitlements_xpc(void)
{
	pid_t pid = getpid();
	CS_GenericBlob hdr = {0};

	if (csops(pid, CS_OPS_ENTITLEMENTS_BLOB, &hdr, sizeof(hdr)) != 0) {
		if (errno != ERANGE) {
			return NULL;
		}
	}

	if (hdr.length <= sizeof(hdr)) {
		return NULL;
	}

	void *buf = malloc(hdr.length);
	if (!buf)
		return NULL;

	if (csops(pid, CS_OPS_ENTITLEMENTS_BLOB, buf, hdr.length) != 0) {
		free(buf);
		return NULL;
	}

	const void *plist = (const uint8_t *)buf + sizeof(CS_GenericBlob);
	size_t plist_size = hdr.length - sizeof(CS_GenericBlob);

	xpc_object_t obj = xpc_create_from_plist(plist, plist_size);

	free(buf);

	if (!obj || xpc_get_type(obj) != XPC_TYPE_DICTIONARY) {
		if (obj) xpc_release(obj);
		return NULL;
	}

	return obj;
}

bool process_requires_hookd(void)
{
	xpc_object_t entitlementsXdict = copy_entitlements_xpc();
	if (!entitlementsXdict) return true;

	bool requiresHookd = xpc_dictionary_get_bool(entitlementsXdict, "com.apple.private.cs.debugger") != true;
	xpc_release(entitlementsXdict);
	return requiresHookd;
}

const struct mach_header_64 *get_dyld_mach_header(void)
{
	static const struct mach_header_64 *dyldMachHeader = NULL;
	static dispatch_once_t onceToken;
	dispatch_once (&onceToken, ^{
		task_dyld_info_data_t dyldInfo;
		uint32_t count = TASK_DYLD_INFO_COUNT;
		kern_return_t kr = task_info(mach_task_self_, TASK_DYLD_INFO, (task_info_t)&dyldInfo, &count);
		if (kr == KERN_SUCCESS) {
			struct dyld_all_image_infos *infos = (struct dyld_all_image_infos *)dyldInfo.all_image_info_addr;
			dyldMachHeader = (const struct mach_header_64 *)infos->dyldImageLoadAddress;
		}
	});
	return dyldMachHeader;
}

int parse_dyldhook_jbinfo(char **jbRootPathOut, char **bootUUIDOut, char **sandboxExtensionsOut, bool *fullyDebuggedOut)
{
	const struct mach_header_64 *dyldHeader = get_dyld_mach_header();
	if (!dyldHeader) return -1;

	uuid_t dyldUUID;
	if (!_dyld_get_image_uuid((const struct mach_header *)dyldHeader, dyldUUID)) return -2;
	if (!string_has_prefix((char *)dyldUUID, "DOPA")) return -3;

	size_t jbInfoSize = 0;
	struct dyld_jbinfo *jbInfo = (struct dyld_jbinfo *)getsectiondata(dyldHeader, "__DATA", "__jbinfo", &jbInfoSize);
	if (!jbInfo) return -4;

	if (jbInfo->state != DYLD_STATE_CHECKED_IN) return -5;

	if (jbRootPathOut)        *jbRootPathOut        = jbInfo->jbRootPath;
	if (bootUUIDOut)          *bootUUIDOut          = jbInfo->bootUUID;
	if (sandboxExtensionsOut) *sandboxExtensionsOut = jbInfo->sandboxExtensions;
	if (fullyDebuggedOut)     *fullyDebuggedOut     = jbInfo->fullyDebugged;

	return 0;
}

__attribute__((constructor)) static void initializer(void)
{
	if (parse_dyldhook_jbinfo(&JB_RootPath, &JB_BootUUID, &JB_SandboxExtensions, &gFullyDebugged) != 0) {
		if (jbclient_process_checkin(&JB_RootPath, &JB_BootUUID, &JB_SandboxExtensions, &gFullyDebugged, NULL) == 0) {
			consume_tokenized_sandbox_extensions(JB_SandboxExtensions);
		}
		else {
			return;
		}
	}

	const char *dyldInsertLibraries = getenv("DYLD_INSERT_LIBRARIES");
	if (dyldInsertLibraries) {
		if (!strcmp(dyldInsertLibraries, HOOK_DYLIB_PATH)) {
			unsetenv("DYLD_INSERT_LIBRARIES");
		}
	}

	if (__builtin_available(iOS 19.0, *)) {
		void *dyld_jbclient_mach_hookd_send_msg = litehook_find_symbol(get_dyld_mach_header(), "_jbclient_mach_hookd_send_msg");
		if (dyld_jbclient_mach_hookd_send_msg) {
			hookd_send_msg = dyld_jbclient_mach_hookd_send_msg;
		}

		if (process_requires_hookd()) {
			litehook_hook_memory = litehook_hook_memory_hookd;
			litehook_hook_function(mach_vm_protect, mach_vm_protect_fixed);
			init_hookd_external_support();
		}
	}

	if (__builtin_available(iOS 16.0, *)) {
		litehook_hook_function(__posix_spawn, __posix_spawn_hook);
		litehook_hook_function(__execve,      __execve_hook);
	}
	else {
		void **posix_spawn_with_filter = litehook_find_dsc_symbol("/usr/lib/system/libsystem_kernel.dylib", "_posix_spawn_with_filter");
		void **execve_with_filter      = litehook_find_dsc_symbol("/usr/lib/system/libsystem_kernel.dylib", "_execve_with_filter");

		*posix_spawn_with_filter = __posix_spawn_hook_with_filter;
		*execve_with_filter      = __execve_hook;
	}

	void *dyld___fcntl = litehook_find_symbol(get_dyld_mach_header(), "___fcntl");
	extern int __fcntl(int fd, int op, ... /* arg */ );
	litehook_hook_function(__fcntl, dyld___fcntl);

	gLibSandboxHandle = dlopen("/usr/lib/libsandbox.1.dylib", RTLD_FIRST | RTLD_LOCAL | RTLD_LAZY);
	sandbox_apply_orig = dlsym(gLibSandboxHandle, "sandbox_apply");

	void ***gDyldPtr = litehook_find_dsc_symbol("/usr/lib/system/libdyld.dylib", "__ZN5dyld45gDyldE");
	if (gDyldPtr) {
		dyld_hook_routine(*gDyldPtr, 17, (void *)&dyld_dlsym_hook, (void **)&dyld_dlsym_orig, 0x839D);
	} else {
		void ***gAPIsPtr = litehook_find_dsc_symbol("/usr/lib/system/libdyld.dylib", "__ZN5dyld45gAPIsE");
		if (gAPIsPtr) {
			dyld_hook_routine(*gAPIsPtr, 16, (void *)&dyld_dlsym_hook, (void **)&dyld_dlsym_orig, 0x839D);
		}
	}

#ifdef __arm64e__
	if (sandbox_check(getpid(), "process-fork", SANDBOX_CHECK_NO_REPORT, NULL) == 0) {
		dlopen(JBROOT_PATH("/basebin/forkfix.dylib"), RTLD_NOW);
	}
#endif

	if (load_executable_path() == 0) {
		gHideJailbreakEnabled = jbclient_jbsettings_get_bool("hideJailbreak");
		

		if (gHideJailbreakEnabled) {
			litehook_hook_function(access, hide_access);
			litehook_hook_function(stat, hide_stat);
			litehook_hook_function(lstat, hide_lstat);
			litehook_hook_function(open, hide_open);
			litehook_hook_function(realpath, hide_realpath);
		}


		if (!strcmp(gExecutablePath, "/usr/sbin/cfprefsd") ||
			!strcmp(gExecutablePath, "/System/Library/CoreServices/SpringBoard.app/SpringBoard") ||
			!strcmp(gExecutablePath, "/usr/libexec/lsd")) {
			dlopen(JBROOT_PATH("/basebin/rootlesshooks.dylib"), RTLD_NOW);
		}
		else if (!strcmp(gExecutablePath, "/usr/libexec/watchdogd")) {
			dlopen(JBROOT_PATH("/basebin/watchdoghook.dylib"), RTLD_NOW);
		}

		if (string_has_suffix(gExecutablePath, "/debugserver")) {
			litehook_hook_function(ptrace, ptrace_hook);
		}

#ifndef __arm64e__
		litehook_hook_function(csops, csops_hook);
		litehook_hook_function(csops_audittoken, csops_audittoken_hook);
		if (__builtin_available(iOS 16.0, *)) {
			litehook_hook_function(necp_match_policy, necp_match_policy_hook);
			litehook_hook_function(necp_open, necp_open_hook);
			litehook_hook_function(necp_client_action, necp_client_action_hook);
			litehook_hook_function(necp_session_open, necp_session_open_hook);
			litehook_hook_function(necp_session_action, necp_session_action_hook);
		}
#endif
		if (should_enable_tweaks()) {
			const char *tweakLoaderPath = "/var/jb/usr/lib/TweakLoader.dylib";
			if (access(tweakLoaderPath, F_OK) == 0) {
				void *tweakLoaderHandle = dlopen(tweakLoaderPath, RTLD_NOW);
				if (tweakLoaderHandle != NULL) {
					dlclose(tweakLoaderHandle);
				}
			}
		}

#ifndef __arm64e__
		jbclient_cs_revalidate();
#endif
	}
}
