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

// Defined in main.c; defaults to false (legacy), and is set from the user's
// Dopamine "Enhanced Spinlock Fix" setting via checkin before loadDyldCache runs.
// When false, every function below takes its original (pre-fix) path.
extern bool gSpinlockFixEnhanced;

// Small unsigned-to-decimal helper (self-contained: no snprintf/libc pull-in).
// Only used by the enhanced subcache loop.
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
	static char dscPath[PATH_MAX] = {};
	if (dscPath[0]) return dscPath;

	if (!gSpinlockFixEnhanced) {
		// Legacy: hardcoded single path (pre-fix behaviour). If the cache is not
		// exactly this file, open() fails and the private-mapping pass skips.
		strlcpy(dscPath, "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e", sizeof(dscPath));
		return dscPath;
	}

	// Enhanced: probe suffix candidates so a device whose cache is named _arm64e
	// vs _arm64 (or carries a variant) still gets found.
	const char *base = "/System/Library/Caches/com.apple.dyld/dyld_shared_cache";
	const char *suffixes[] = { "_arm64e", "_arm64", "" };
	for (size_t i = 0; i < sizeof(suffixes) / sizeof(*suffixes); i++) {
		strlcpy(dscPath, base, sizeof(dscPath));
		strlcat(dscPath, suffixes[i], sizeof(dscPath));
		if (access(dscPath, F_OK) == 0) return dscPath;
	}
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

	for (uint32_t i = 0; i < header.subCacheArrayCount; i++) {
		char subcachePath[PATH_MAX];
		strlcpy(subcachePath, dscPath, sizeof(subcachePath));

		if (!gSpinlockFixEnhanced) {
			// Legacy: single-digit suffix only. Beyond ".9" this produces a bogus
			// name, so those subcaches' executable mappings stay shared.
			char suffix[3];
			suffix[0] = '.';
			suffix[1] = '1' + i;
			suffix[2] = '\0';
			strlcat(subcachePath, suffix, sizeof(subcachePath));
		}
		else {
			// Enhanced: correct decimal suffix for any number of subcaches.
			char suffix[12];
			char num[12];
			__dsc_u32_to_str(num, i + 1);
			suffix[0] = '.';
			suffix[1] = '\0';
			strlcat(subcachePath, suffix, sizeof(subcachePath));
			strlcat(subcachePath, num, sizeof(subcachePath));
		}

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

	if (!gSpinlockFixEnhanced) {
		// Legacy: only attempt the mmap when the fcntl attach succeeds, discard the
		// mmap result (the inner `r` shadows the outer one), and always report
		// success. This is the original pre-fix logic, bugs included.
		int r = __dsc_attach_signature(fd, header);
		if (r == 0) {
			void *r = mmap((void *)(mapping->address + slide), mapping->size, PROT_READ | PROT_EXEC, MAP_FIXED | MAP_PRIVATE, fd, mapping->fileOffset);
		}
		return true;
	}

	// Enhanced: attach the cache's code signature so the MAP_PRIVATE executable
	// mapping passes code-signing. If the attach fails we still attempt the mmap —
	// the cache file is already Apple-signed, and MAP_PRIVATE of it may succeed
	// without the extra fcntl attach on some builds.
	__dsc_attach_signature(fd, header);

	// MAP_FIXED | MAP_PRIVATE replaces the shared mapping with a private one, so a
	// later write hits a normal private COW page instead of the shared region's
	// spinlock-protected path. Check the result: a failure here left the page
	// SHARED, and that is exactly the page whose later write deadlocks the spinlock.
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