#if IOS==15 && __arm64e__

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sandbox.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <sys/mman.h>
#define TARGET_OS_SIMULATOR 0
#include <dyld_cache_format.h>

#include "machomerger_hook.h"

// Small unsigned-to-decimal helper (self-contained: no snprintf/libc pull-in).
static void __dsc_u32_to_str(char *out, uint32_t value)
{
	char tmp[12];
	int n = 0;
	do {
		tmp[n++] = (char)('0' + (value % 10));
		value /= 10;
	} while (value > 0);
	for (int i = 0; i < n; i++) out[i] = tmp[n - 1 - i];
	out[n] = '\0';
}

char *__locate_dsc(void)
{
	// We make two assumptions here
	// 1. This code is only called on iOS 15 arm64e (since the spinlock panic doesn't affect anything else)
	// 2. This code is only called if the shared cache has been mapped in via a shared region
	//
	// Unlike the previous hardcoded single path, probe the suffix candidates so a
	// device whose cache is named _arm64e vs _arm64 (or carries an _arm64e_x1
	// variant) still gets found. A wrong path would make open() fail and silently
	// skip the whole private-mapping pass, leaving every dsc __TEXT page shared.
	static char dscPath[PATH_MAX] = {};
	if (dscPath[0]) return dscPath;

	const char *base = "/System/Library/Caches/com.apple.dyld/dyld_shared_cache";
	const char *suffixes[] = { "_arm64e", "_arm64", "" };
	for (size_t i = 0; i < sizeof(suffixes) / sizeof(*suffixes); i++) {
		strlcpy(dscPath, base, sizeof(dscPath));
		strlcat(dscPath, suffixes[i], sizeof(dscPath));
		if (access(dscPath, F_OK) == 0) return dscPath;
	}
	// Fall back to the base name; open() may fail, in which case the caller bails.
	strlcpy(dscPath, base, sizeof(dscPath));
	return dscPath;
}

void __dsc_file_enumerate_mappings(int fd, struct dyld_cache_header *header, uintptr_t slide, bool (*enumeratorFunc)(int fd, struct dyld_cache_header *header, uintptr_t slide, struct dyld_cache_mapping_info *mapping))
{
	struct dyld_cache_mapping_info mappingInfos[header->mappingCount];
	lseek(fd, header->mappingOffset, SEEK_SET);
	if (read(fd, mappingInfos, sizeof(struct dyld_cache_mapping_info) * header->mappingCount) != sizeof(struct dyld_cache_mapping_info) * header->mappingCount) return;

	for (uint32_t i = 0; i < header->mappingCount; i++) {
		struct dyld_cache_mapping_info *mapping = &mappingInfos[i];
		enumeratorFunc(fd, header, slide, mapping);
	}
}

void __dsc_enumerate_mappings(uintptr_t slide, bool (*enumeratorFunc)(int fd, struct dyld_cache_header *header, uintptr_t slide, struct dyld_cache_mapping_info *mapping))
{
	char *dscPath = __locate_dsc();

	int dscFd = open(dscPath, O_RDONLY);
	if (dscFd < 0) return;

	struct dyld_cache_header header;
	if (read(dscFd, &header, sizeof(header)) != sizeof(header)) { close(dscFd); return; }

	__dsc_file_enumerate_mappings(dscFd, &header, slide, enumeratorFunc);

	struct dyld_subcache_entry_v1 subcacheEntries[header.subCacheArrayCount];
	lseek(dscFd, header.subCacheArrayOffset, SEEK_SET);
	if (read(dscFd, subcacheEntries, sizeof(struct dyld_subcache_entry_v1) * header.subCacheArrayCount) != sizeof(struct dyld_subcache_entry_v1) * header.subCacheArrayCount) { close(dscFd); return; };

	// Enumerate every subcache, including two-digit suffixes (.10, .11, ...). The
	// old loop hardcoded a single digit and produced garbage beyond ".9", leaving
	// those subcaches' executable mappings shared (and thus spinlock-unsafe).
	for (uint32_t i = 0; i < header.subCacheArrayCount; i++) {
		char subcachePath[PATH_MAX];
		strlcpy(subcachePath, dscPath, sizeof(subcachePath));
		strlcat(subcachePath, ".", sizeof(subcachePath));
		char suffix[12];
		__dsc_u32_to_str(suffix, i + 1);
		strlcat(subcachePath, suffix, sizeof(subcachePath));

		int subcacheFd = open(subcachePath, O_RDONLY);
		if (subcacheFd >= 0) {
			struct dyld_cache_header subcacheHeader;
			if (read(subcacheFd, &subcacheHeader, sizeof(subcacheHeader)) != sizeof(subcacheHeader)) { close(subcacheFd); continue; }
			__dsc_file_enumerate_mappings(subcacheFd, &subcacheHeader, slide, enumeratorFunc);
			close(subcacheFd);
		}
	}

	close(dscFd);
}

int __dsc_attach_signature(int fd, struct dyld_cache_header *header)
{
	fsignatures_t siginfo;
    siginfo.fs_file_start = 0;
    siginfo.fs_blob_start = (void*)header->codeSignatureOffset;
    siginfo.fs_blob_size  = (size_t)(header->codeSignatureSize);
    return fcntl(fd, F_ADDFILESIGS_RETURN, &siginfo);
}

bool __dsc_mapping_make_private(int fd, struct dyld_cache_header *header, uintptr_t slide, struct dyld_cache_mapping_info *mapping)
{
	if (!(mapping->initProt & PROT_EXEC)) return true;

	// Attach the cache's code signature to the fd so the MAP_PRIVATE executable
	// mapping below passes code-signing. If the attach fails we still attempt the
	// mmap: the cache file is already Apple-signed, and MAP_PRIVATE of it may
	// succeed without the extra fcntl attach on some builds.
	__dsc_attach_signature(fd, header);

	// MAP_FIXED | MAP_PRIVATE replaces the shared mapping with a private one, so
	// a later write hit a normal private COW page instead of the shared region's
	// spinlock-protected path. Check the result: a failure here (bad signature,
	// address already in use, fd closed) left the page SHARED, and that is exactly
	// the page whose later write deadlocks the spinlock → panic.
	void *mapped = mmap((void *)(mapping->address + slide), mapping->size,
	                    PROT_READ | PROT_EXEC, MAP_FIXED | MAP_PRIVATE,
	                    fd, mapping->fileOffset);
	return mapped != MAP_FAILED;
}

void dyld_make_dsc_text_private(uintptr_t slide)
{
	__dsc_enumerate_mappings(slide, __dsc_mapping_make_private);
}

extern bool ORIG(_ZN5dyld313loadDyldCacheERKNS_18SharedCacheOptionsEPNS_19SharedCacheLoadInfoE)(uintptr_t options, uintptr_t results);
bool HOOK(_ZN5dyld313loadDyldCacheERKNS_18SharedCacheOptionsEPNS_19SharedCacheLoadInfoE)(uintptr_t options, uintptr_t results)
{
	bool r = ORIG(_ZN5dyld313loadDyldCacheERKNS_18SharedCacheOptionsEPNS_19SharedCacheLoadInfoE)(options, results);

	bool forcePrivate = *(bool *)(options + 8);
	if (!forcePrivate) {
		long slide = *(long *)(results + 8);
		dyld_make_dsc_text_private(slide);
	}

	return r;
}

#endif