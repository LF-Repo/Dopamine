TARGET = hidepatcher
CC = clang

# ChOma headers (built into .include by the top-level BaseBin Makefile) plus the
# ct_bypass data headers (App Store code directory / CA cert) that live in the
# ChOma tests directory.
CFLAGS = -framework Foundation -framework CoreFoundation \
	-I../.include \
	-I../ChOma/tests/ct_bypass \
	-isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) \
	-arch arm64 -arch arm64e -miphoneos-version-min=15.0 \
	-Wno-deprecated-declarations -Wno-pointer-to-int-cast -Wno-unused-command-line-argument

LDFLAGS = -L../.build -lchoma ../ChOma/external/ios/libcrypto.a

sign: $(TARGET)
	@ldid -Cadhoc -S../ChOma/external/ios/entitlements.plist $<

$(TARGET): main.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	@rm -f $(TARGET)
