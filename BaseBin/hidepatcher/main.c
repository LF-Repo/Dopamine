// hidepatcher — RootHide-style patcher for Hide for App.
//
// Adds LC_LOAD_WEAK_DYLIB -> /usr/lib/systemhook.dylib to an app's main
// executable so systemhook loads as a *legitimate dependency* (not a
// DYLD_INSERT_LIBRARIES injection), then applies the CoreTrust bypass signature
// so the modified binary still runs.
//
// Usage:
//   hidepatcher patch   <path/to/App.app>
//   hidepatcher unpatch <path/to/App.app>
//
// The original binary is backed up to <executable>.hidejb_backup and restored on
// unpatch. This reuses ChOma's dylib_insert + ct_bypass machinery (see
// ChOma/tests/dylib_insert and ChOma/tests/ct_bypass).

#include <choma/Fat.h>
#include <choma/MachO.h>
#include <choma/Host.h>
#include <choma/FileStream.h>
#include <choma/BufferedStream.h>
#include <choma/CodeDirectory.h>
#include <choma/Base64.h>
#include <choma/CSBlob.h>
#include <choma/MachOByteOrder.h>
#include "AppStoreCodeDirectory.h"
#include "DERTemplate.h"
#include "TemplateSignatureBlob.h"
#include "CADetails.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/cms.h>
#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <copyfile.h>
#include <dirent.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>

#define HIDE_DYLIB_PATH "/usr/lib/systemhook.dylib"
#define CPU_SUBTYPE_ARM64E_ABI_V2 0x80000000

// ---------------------------------------------------------------------------
// Mach-O helpers (from ChOma/tests/dylib_insert)
// ---------------------------------------------------------------------------

static char *extract_preferred_slice(const char *fatPath)
{
	Fat *fat = fat_init_from_path(fatPath);
	if (!fat) return NULL;
	MachO *macho = fat_find_preferred_slice(fat);

	if (!macho) {
		// arm64 fallbacks
		macho = fat_find_slice(fat, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_V8);
		if (!macho) macho = fat_find_slice(fat, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
		if (!macho) macho = fat_find_slice(fat, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_ARM64E_ABI_V2);
		if (!macho) macho = fat_find_slice(fat, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E);
		if (!macho) {
			fat_free(fat);
			return NULL;
		}
	}

	if (macho->machHeader.filetype != MH_EXECUTE) {
		fat_free(fat);
		return NULL;
	}

	char *temp = strdup("/tmp/hidepatcher.XXXXXX");
	int fd = mkstemp(temp);

	MemoryStream *outStream = file_stream_init_from_path(temp, 0, 0, FILE_STREAM_FLAG_WRITABLE | FILE_STREAM_FLAG_AUTO_EXPAND);
	MemoryStream *machoStream = macho_get_stream(macho);
	memory_stream_copy_data(machoStream, 0, outStream, 0, memory_stream_get_size(machoStream));

	fat_free(fat);
	memory_stream_free(outStream);
	close(fd);
	return temp;
}

static int check_load_commands(MachO *macho, bool *isInserted, bool *isSigned, bool *enoughFreeSpace, const char *dylibToInsert)
{
	macho_enumerate_load_commands(macho, ^(struct load_command lc, uint64_t offset, void *cmd, bool *stop) {
		if (lc.cmd == LC_CODE_SIGNATURE) {
			if (isSigned) *isSigned = true;
		}
		if (lc.cmd == LC_LOAD_DYLIB || lc.cmd == LC_LOAD_WEAK_DYLIB) {
			struct dylib_command *command = (struct dylib_command *)cmd;
			char *dylibName = NULL;
			macho_read_string_at_offset(macho, offset + command->dylib.name.offset, &dylibName);
			if (dylibName && !strcmp(dylibName, dylibToInsert)) {
				if (isInserted) *isInserted = true;
			}
		}
	});

	int insertionSize = sizeof(struct dylib_command) + strlen(dylibToInsert);
	struct dylib_command *emptySpace = malloc(insertionSize);
	memset(emptySpace, 0, insertionSize);

	struct dylib_command *endOfLoadCommands = malloc(insertionSize);
	macho_read_at_offset(macho, macho_get_mach_header_size(macho) + macho->machHeader.sizeofcmds, insertionSize, endOfLoadCommands);

	if (!memcmp(emptySpace, endOfLoadCommands, insertionSize)) {
		if (enoughFreeSpace) *enoughFreeSpace = true;
	}

	free(emptySpace);
	free(endOfLoadCommands);
	return 0;
}

static int insert_load_command(MachO *macho, const char *dylibPath, bool weakDylib)
{
	struct dylib_command command = { 0 };
	int insertionSize = sizeof(command) + strlen(dylibPath);

	command.cmd = weakDylib ? LC_LOAD_WEAK_DYLIB : LC_LOAD_DYLIB;
	command.cmdsize = (HOST_TO_LITTLE(insertionSize) + 3) & ~3;
	command.dylib.name.offset = HOST_TO_LITTLE((int)sizeof(command));
	command.dylib.timestamp = 0;
	command.dylib.current_version = 0;
	command.dylib.compatibility_version = 0;

	void *insertion = malloc(insertionSize);
	memcpy(insertion, &command, sizeof(command));
	memcpy(insertion + sizeof(command), dylibPath, strlen(dylibPath));

	macho_write_at_offset(macho, macho_get_mach_header_size(macho) + macho->machHeader.sizeofcmds, insertionSize, insertion);
	free(insertion);

	struct mach_header *header = malloc(sizeof(struct mach_header));
	memcpy(header, &macho->machHeader, sizeof(struct mach_header));
	MACH_HEADER_APPLY_BYTE_ORDER(header, LITTLE_TO_HOST_APPLIER);

	header->ncmds++;
	header->sizeofcmds += (insertionSize + 3) & ~3;
	MACH_HEADER_APPLY_BYTE_ORDER(header, HOST_TO_LITTLE_APPLIER);

	macho_write_at_offset(macho, 0, sizeof(struct mach_header), header);
	memcpy(&macho->machHeader, header, sizeof(struct mach_header));

	free(header);
	return 0;
}

// ---------------------------------------------------------------------------
// CoreTrust bypass signing (from ChOma/tests/ct_bypass)
// ---------------------------------------------------------------------------

static int update_signature_blob(CS_DecodedSuperBlob *superblob, void *appStoreSigBlob, size_t appStoreSigBlobLen)
{
	CS_DecodedBlob *sha1CD = csd_superblob_find_blob(superblob, CSSLOT_CODEDIRECTORY, NULL);
	if (!sha1CD) return -1;
	CS_DecodedBlob *sha256CD = csd_superblob_find_blob(superblob, CSSLOT_ALTERNATE_CODEDIRECTORIES, NULL);
	if (!sha256CD) return -1;

	uint8_t sha1CDHash[CC_SHA1_DIGEST_LENGTH];
	uint8_t sha256CDHash[CC_SHA256_DIGEST_LENGTH];

	{
		size_t dataSizeToRead = csd_blob_get_size(sha1CD);
		uint8_t *data = malloc(dataSizeToRead);
		memset(data, 0, dataSizeToRead);
		csd_blob_read(sha1CD, 0, dataSizeToRead, data);
		CC_SHA1(data, (CC_LONG)dataSizeToRead, sha1CDHash);
		free(data);
	}
	{
		size_t dataSizeToRead = csd_blob_get_size(sha256CD);
		uint8_t *data = malloc(dataSizeToRead);
		memset(data, 0, dataSizeToRead);
		csd_blob_read(sha256CD, 0, dataSizeToRead, data);
		CC_SHA256(data, (CC_LONG)dataSizeToRead, sha256CDHash);
		free(data);
	}

	const uint8_t *cmsDataPtr;
	size_t cmsDataSize;
	if (appStoreSigBlob) {
		cmsDataPtr = (uint8_t *)appStoreSigBlob + offsetof(CS_GenericBlob, data);
		cmsDataSize = appStoreSigBlobLen - sizeof(CS_GenericBlob);
	} else {
		cmsDataPtr = (const uint8_t *)AppStoreSignatureBlob + offsetof(CS_GenericBlob, data);
		cmsDataSize = AppStoreSignatureBlob_len - sizeof(CS_GenericBlob);
	}
	CMS_ContentInfo *cms = d2i_CMS_ContentInfo(NULL, &cmsDataPtr, (long)cmsDataSize);
	if (!cms) return -1;

	FILE *privateKeyFile = fmemopen((void *)CAKey, CAKeyLength, "r");
	if (!privateKeyFile) return -1;
	EVP_PKEY *privateKey = PEM_read_PrivateKey(privateKeyFile, NULL, NULL, NULL);
	fclose(privateKeyFile);
	if (!privateKey) return -1;

	FILE *certificateFile = fmemopen((void *)CACert, CACertLength, "r");
	if (!certificateFile) return -1;
	X509 *certificate = PEM_read_X509(certificateFile, NULL, NULL, NULL);
	fclose(certificateFile);
	if (!certificate) return -1;

	CMS_SignerInfo *newSigner = CMS_add1_signer(cms, certificate, privateKey, EVP_sha256(), CMS_PARTIAL | CMS_REUSE_DIGEST | CMS_NOSMIMECAP);
	if (!newSigner) return -1;

	CFMutableArrayRef cdHashesArray = CFArrayCreateMutable(NULL, 2, &kCFTypeArrayCallBacks);
	CFDataRef sha1CDHashData = CFDataCreate(NULL, sha1CDHash, CC_SHA1_DIGEST_LENGTH);
	CFArrayAppendValue(cdHashesArray, sha1CDHashData);
	CFRelease(sha1CDHashData);
	CFDataRef sha256CDHashData = CFDataCreate(NULL, sha256CDHash, CC_SHA1_DIGEST_LENGTH);
	CFArrayAppendValue(cdHashesArray, sha256CDHashData);
	CFRelease(sha256CDHashData);

	CFMutableDictionaryRef cdHashesDictionary = CFDictionaryCreateMutable(NULL, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDictionarySetValue(cdHashesDictionary, CFSTR("cdhashes"), cdHashesArray);
	CFRelease(cdHashesArray);

	CFDataRef cdHashesDictionaryData = CFPropertyListCreateData(NULL, cdHashesDictionary, kCFPropertyListXMLFormat_v1_0, 0, NULL);
	CFRelease(cdHashesDictionary);
	if (!cdHashesDictionaryData) return -1;

	CMS_signed_add1_attr_by_txt(newSigner, "1.2.840.113635.100.9.1", V_ASN1_OCTET_STRING, CFDataGetBytePtr(cdHashesDictionaryData), (int)CFDataGetLength(cdHashesDictionaryData));
	CFRelease(cdHashesDictionaryData);

	uint8_t cdHashesDER[78];
	memset(cdHashesDER, 0, sizeof(cdHashesDER));
	memcpy(cdHashesDER, CDHashesDERTemplate, sizeof(CDHashesDERTemplate));
	memcpy(cdHashesDER + CDHASHES_DER_SHA1_OFFSET, sha1CDHash, CC_SHA1_DIGEST_LENGTH);
	memcpy(cdHashesDER + CDHASHES_DER_SHA256_OFFSET, sha256CDHash, CC_SHA256_DIGEST_LENGTH);

	CMS_signed_add1_attr_by_txt(newSigner, "1.2.840.113635.100.9.2", V_ASN1_SEQUENCE, cdHashesDER, sizeof(cdHashesDER));

	if (!CMS_SignerInfo_sign(newSigner)) return -1;

	uint8_t *newCMSData = NULL;
	int newCMSDataSize = i2d_CMS_ContentInfo(cms, &newCMSData);
	if (newCMSDataSize <= 0) return -1;

	uint32_t newCMSDataBlobSize = sizeof(CS_GenericBlob) + newCMSDataSize;
	CS_GenericBlob *newCMSDataBlob = malloc(newCMSDataBlobSize);
	newCMSDataBlob->magic = HOST_TO_BIG(CSMAGIC_BLOBWRAPPER);
	newCMSDataBlob->length = HOST_TO_BIG(newCMSDataBlobSize);
	memcpy(newCMSDataBlob->data, newCMSData, newCMSDataSize);
	free(newCMSData);

	CS_DecodedBlob *oldSignatureBlob = csd_superblob_find_blob(superblob, CSSLOT_SIGNATURESLOT, NULL);
	if (oldSignatureBlob) {
		csd_superblob_remove_blob(superblob, oldSignatureBlob);
		csd_blob_free(oldSignatureBlob);
	}

	CS_DecodedBlob *signatureBlob = csd_blob_init(CSSLOT_SIGNATURESLOT, newCMSDataBlob);
	free(newCMSDataBlob);
	return csd_superblob_append_blob(superblob, signatureBlob);
}

static int apply_coretrust_bypass(const char *machoPath)
{
	MachO *macho = macho_init_for_writing(machoPath);
	if (!macho) return -1;

	if (macho_is_encrypted(macho)) {
		printf("Error: MachO is encrypted, please decrypt it first.\n");
		macho_free(macho);
		return 2;
	}

	CS_SuperBlob *superblob = macho_read_code_signature(macho);
	if (!superblob) {
		printf("Error: no code signature found.\n");
		macho_free(macho);
		return -1;
	}

	CS_DecodedSuperBlob *decodedSuperblob = csd_superblob_decode(superblob);
	uint64_t originalCodeSignatureSize = BIG_TO_HOST(superblob->length);
	free(superblob);

	CS_DecodedBlob *mainCodeDirBlob = csd_superblob_find_blob(decodedSuperblob, CSSLOT_CODEDIRECTORY, NULL);
	CS_DecodedBlob *alternateCodeDirBlob = csd_superblob_find_blob(decodedSuperblob, CSSLOT_ALTERNATE_CODEDIRECTORIES, NULL);

	if (!mainCodeDirBlob) {
		printf("Error: no code directory found.\n");
		return -1;
	}

	CS_DecodedBlob *realCodeDirBlob;
	if (alternateCodeDirBlob) {
		realCodeDirBlob = alternateCodeDirBlob;
		csd_superblob_remove_blob(decodedSuperblob, mainCodeDirBlob);
		csd_blob_free(mainCodeDirBlob);
	} else {
		realCodeDirBlob = mainCodeDirBlob;
	}

	if (csd_code_directory_get_hash_type(realCodeDirBlob) != CS_HASHTYPE_SHA256_256) {
		printf("Error: code directory is not SHA256.\n");
		return -1;
	}

	csd_superblob_remove_blob(decodedSuperblob, realCodeDirBlob);
	csd_blob_set_type(realCodeDirBlob, CSSLOT_ALTERNATE_CODEDIRECTORIES);
	csd_superblob_append_blob(decodedSuperblob, realCodeDirBlob);

	CS_DecodedBlob *appStoreCodeDirectoryBlob = csd_blob_init(CSSLOT_CODEDIRECTORY, (CS_GenericBlob *)AppStoreCodeDirectory);
	csd_superblob_insert_blob_at_index(decodedSuperblob, appStoreCodeDirectoryBlob, 0);

	CS_DecodedBlob *signatureBlob = csd_superblob_find_blob(decodedSuperblob, CSSLOT_SIGNATURESLOT, NULL);
	if (signatureBlob) {
		csd_superblob_remove_blob(decodedSuperblob, signatureBlob);
		csd_blob_free(signatureBlob);
	}

	char *appStoreTeamID = csd_code_directory_copy_team_id(appStoreCodeDirectoryBlob, NULL);
	if (!appStoreTeamID) return -1;
	if (csd_code_directory_set_team_id(realCodeDirBlob, appStoreTeamID) != 0) return -1;
	free(appStoreTeamID);

	csd_code_directory_set_flags(realCodeDirBlob, 0);

	if (update_signature_blob(decodedSuperblob, NULL, 0) != 0) return -1;

	CS_SuperBlob *encodedSuperblobUnsigned = csd_superblob_encode(decodedSuperblob);
	if (update_load_commands_for_coretrust_bypass(macho, encodedSuperblobUnsigned, originalCodeSignatureSize) != 0) {
		free(encodedSuperblobUnsigned);
		return -1;
	}
	free(encodedSuperblobUnsigned);

	csd_code_directory_update(realCodeDirBlob, macho);

	if (update_signature_blob(decodedSuperblob, NULL, 0) != 0) return -1;

	CS_SuperBlob *newSuperblob = csd_superblob_encode(decodedSuperblob);
	macho_replace_code_signature(macho, newSuperblob);

	csd_superblob_free(decodedSuperblob);
	free(newSuperblob);
	macho_free(macho);
	return 0;
}

// ---------------------------------------------------------------------------
// App bundle handling
// ---------------------------------------------------------------------------

static char *read_main_executable_path(const char *appBundlePath, char *outBuf, size_t outBufSize)
{
	char infoPlistPath[PATH_MAX];
	snprintf(infoPlistPath, sizeof(infoPlistPath), "%s/Info.plist", appBundlePath);

	CFURLRef url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault, (const UInt8 *)infoPlistPath, (CFIndex)strlen(infoPlistPath), false);
	if (!url) return NULL;
	CFDataRef data = NULL;
	Boolean ok = CFURLCreateDataAndPropertiesFromResource(kCFAllocatorDefault, url, &data, NULL, NULL, NULL);
	CFRelease(url);
	if (!ok || !data) return NULL;

	CFPropertyListRef plist = CFPropertyListCreateWithData(kCFAllocatorDefault, data, kCFPropertyListImmutable, NULL, NULL);
	CFRelease(data);
	if (!plist || CFGetTypeID(plist) != CFDictionaryGetTypeID()) { if (plist) CFRelease(plist); return NULL; }

	const void *exeName = CFDictionaryGetValue((CFDictionaryRef)plist, CFSTR("CFBundleExecutable"));
	if (!exeName || CFGetTypeID(exeName) != CFStringGetTypeID()) { CFRelease(plist); return NULL; }

	char name[256];
	if (!CFStringGetCString((CFStringRef)exeName, name, sizeof(name), kCFStringEncodingUTF8)) { CFRelease(plist); return NULL; }
	CFRelease(plist);

	snprintf(outBuf, outBufSize, "%s/%s", appBundlePath, name);
	return outBuf;
}

static int patch_app(const char *appBundlePath)
{
	char mainExe[PATH_MAX];
	if (!read_main_executable_path(appBundlePath, mainExe, sizeof(mainExe))) {
		printf("Error: failed to read main executable path from Info.plist\n");
		return -1;
	}

	if (access(mainExe, F_OK) != 0) {
		printf("Error: cannot access %s\n", mainExe);
		return -1;
	}

	char backupPath[PATH_MAX];
	snprintf(backupPath, sizeof(backupPath), "%s.hidejb_backup", mainExe);

	if (access(backupPath, F_OK) == 0) {
		printf("Already patched (backup exists at %s).\n", backupPath);
		return 0;
	}

	// Back up the original binary
	if (copyfile(mainExe, backupPath, 0, COPYFILE_ALL) != 0) {
		perror("copyfile backup");
		return -1;
	}

	char *slicePath = extract_preferred_slice(mainExe);
	if (!slicePath) {
		printf("Error: failed to extract preferred slice.\n");
		return -1;
	}

	MachO *macho = macho_init_for_writing(slicePath);
	if (!macho) return -1;

	bool isInserted = false, isSigned = false, enoughFreeSpace = false;
	check_load_commands(macho, &isInserted, &isSigned, &enoughFreeSpace, HIDE_DYLIB_PATH);

	if (isInserted) {
		printf("Load command already present.\n");
		macho_free(macho);
		unlink(slicePath);
		return 0;
	}
	if (!enoughFreeSpace) {
		printf("Error: no free space for the new load command.\n");
		macho_free(macho);
		unlink(slicePath);
		return -1;
	}

	if (insert_load_command(macho, HIDE_DYLIB_PATH, true) != 0) {
		printf("Error: failed to insert load command.\n");
		macho_free(macho);
		unlink(slicePath);
		return -1;
	}
	macho_free(macho);

	printf("Inserted load command, applying CoreTrust bypass...\n");
	int r = apply_coretrust_bypass(slicePath);
	if (r != 0) {
		printf("Error: CoreTrust bypass failed (%d).\n", r);
		unlink(slicePath);
		return r;
	}

	// Move patched slice back over the original
	if (copyfile(slicePath, mainExe, 0, COPYFILE_ALL | COPYFILE_MOVE | COPYFILE_UNLINK) != 0) {
		perror("copyfile replace");
		unlink(slicePath);
		return -1;
	}
	chmod(mainExe, 0755);
	printf("Patched %s\n", mainExe);
	return 0;
}

static int unpatch_app(const char *appBundlePath)
{
	char mainExe[PATH_MAX];
	if (!read_main_executable_path(appBundlePath, mainExe, sizeof(mainExe))) {
		printf("Error: failed to read main executable path from Info.plist\n");
		return -1;
	}

	char backupPath[PATH_MAX];
	snprintf(backupPath, sizeof(backupPath), "%s.hidejb_backup", mainExe);

	if (access(backupPath, F_OK) != 0) {
		printf("No backup found at %s, nothing to do.\n", backupPath);
		return 0;
	}

	if (copyfile(backupPath, mainExe, 0, COPYFILE_ALL | COPYFILE_MOVE | COPYFILE_UNLINK) != 0) {
		perror("copyfile restore");
		return -1;
	}
	chmod(mainExe, 0755);
	printf("Restored %s\n", mainExe);
	return 0;
}

int main(int argc, char *argv[])
{
	if (argc != 3) {
		printf("Usage: %s <patch|unpatch> <path/to/App.app>\n", argv[0]);
		return 1;
	}

	const char *cmd = argv[1];
	const char *appBundle = argv[2];

	if (!strcmp(cmd, "patch")) return patch_app(appBundle);
	if (!strcmp(cmd, "unpatch")) return unpatch_app(appBundle);

	printf("Unknown command %s\n", cmd);
	return 1;
}
