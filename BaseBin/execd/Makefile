TARGET = execd

CC = clang

CFLAGS = -framework Foundation -framework CoreServices -framework Security -I../.include -I./src -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch arm64 -arch arm64e -Wno-availability -miphoneos-version-min=15.0 -D BUILD_STANDALONE=$(BUILD_STANDALONE)
LDFLAGS = -lbsm -L../.build -ljailbreak -lchoma

sign: $(TARGET)
	@ldid -Cadhoc -Sentitlements.plist $<

$(TARGET): $(wildcard src/*.c)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	@rm -f $(TARGET)
