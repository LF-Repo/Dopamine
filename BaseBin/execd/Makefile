TARGET = execd

CC = clang

CFLAGS = -I../.include -I./src -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch arm64 -arch arm64e -Wno-availability -miphoneos-version-min=15.0
LDFLAGS = -lbsm

sign: $(TARGET)
	@ldid -Cadhoc -Sentitlements.plist $<

$(TARGET): $(wildcard src/*.c)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	@rm -f $(TARGET)
