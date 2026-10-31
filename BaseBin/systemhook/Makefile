TARGET = systemhook.dylib
CC = clang

CFLAGS = -I../.include -I./src -I../_external/modules/litehook/src -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch arm64 -arch arm64e -miphoneos-version-min=15.0 -install_name @loader_path/$(TARGET) -Wno-deprecated-declarations -D BUILD_STANDALONE=$(BUILD_STANDALONE) -Os -moutline
# No -lellekit: hidejb.c resolves MSHookFunction at runtime (dlopen/dlsym), so
# systemhook carries no LC_LOAD_DYLIB for ellekit and dyld never has to load it
# into a hidden app, where its real procursus path and process state would show.
LDFLAGS = -dynamiclib -lobjc -framework CoreFoundation -L../_external/lib -rpath /var/jb/Library/Frameworks -rpath @loader_path/fallback

sign: $(TARGET)
	@ldid -Cadhoc -S $^

$(TARGET): $(wildcard src/*.[cSm] src/common/*.[cSm] ../libjailbreak/src/jbclient_*.c ../libjailbreak/src/inline_svc.[cS] ../libjailbreak/src/hookd.c ../_external/modules/litehook/src/*.c)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	@rm -f $(TARGET)
