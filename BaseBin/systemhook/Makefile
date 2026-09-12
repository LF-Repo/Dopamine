TARGET = systemhook.dylib
CC = clang

CFLAGS = -I../.include -I./src -I../_external/modules/litehook/src -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch arm64 -arch arm64e -miphoneos-version-min=15.0 -install_name @loader_path/$(TARGET) -Wno-deprecated-declarations -D BUILD_STANDALONE=$(BUILD_STANDALONE) -Os -moutline
LDFLAGS = -dynamiclib -lobjc

SOURCES_C = $(wildcard src/*.c src/common/*.c ../libjailbreak/src/jbclient_*.c ../libjailbreak/src/hookd.c ../_external/modules/litehook/src/*.c)
SOURCES_M = $(wildcard src/*.m src/common/*.m)
SOURCES_S = $(wildcard src/*.S src/common/*.S ../libjailbreak/src/inline_svc.S)
OBJECTS = $(SOURCES_C:.c=.o) $(SOURCES_M:.m=.o) $(SOURCES_S:.S=.o)

sign: $(TARGET)
	@ldid -Cadhoc -S $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.m
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(OBJECTS)

clean:
	@rm -f $(TARGET) $(OBJECTS)