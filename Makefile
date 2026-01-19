CC?= gcc
CFLAGS?=-Wall -Wextra -std=c11 -pedantic -O2 -fPIC -D_POSIX_C_SOURCE=200809L
DEBUG_FLAGS?=-g -DDEBUG -DHBC_DEBUG_LOGGING=1

VERSION=$(shell grep vers meson.build| cut -d "'" -f 2)

VH=include/hbc/version.h

# Directories
SRC_DIR = src/lib
BUILD_DIR = build
BIN_DIR = bin

## Source files
UTILS_SRC = $(wildcard $(SRC_DIR)/utils/*.c)
PARSERS_SRC = $(wildcard $(SRC_DIR)/parsers/*.c)
DISASM_SRC = $(wildcard $(SRC_DIR)/disassembly/*.c)
DECOMPILE_SRC = $(wildcard $(SRC_DIR)/decompilation/*.c)
OPCODES_SRC = $(filter-out $(SRC_DIR)/opcodes/%.inc.c,$(wildcard $(SRC_DIR)/opcodes/*.c))
# TODO: data provider must be refactored into struct with callbacks, right now we just move it away from libhbc to solve build problems
DATA_PROVIDER_SRC = $(SRC_DIR)/data_provider_file.c $(SRC_DIR)/data_provider_buffer.c
LIB_SRC = $(UTILS_SRC) $(PARSERS_SRC) $(DISASM_SRC) $(DECOMPILE_SRC) $(OPCODES_SRC) $(DATA_PROVIDER_SRC) \
          $(SRC_DIR)/hbc.c $(SRC_DIR)/opcodes/encoder.c $(SRC_DIR)/opcodes/decoder.c $(SRC_DIR)/r2.c
MAIN_SRC = src/tool/libhbctool.c

## Object files
LIB_OBJ = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(LIB_SRC))
MAIN_OBJ = $(BUILD_DIR)/libhbctool.o

## Artifacts
BIN_FILE = $(BIN_DIR)/libhbctool
STATIC_LIB = $(BUILD_DIR)/libhbc.a

# Include paths
INCLUDES = -Iinclude

all: $(BIN_FILE)

debug: CFLAGS += $(DEBUG_FLAGS)
debug: all

ASAN_FLAGS = -fsanitize=address -fno-omit-frame-pointer -g

asan:
	$(MAKE) clean
	$(MAKE) $(VH)
	$(MAKE) all CFLAGS="$(CFLAGS) $(ASAN_FLAGS)" LDFLAGS="$(LDFLAGS) -fsanitize=address"
	CFLAGS="$(ASAN_FLAGS)" LDFLAGS="-fsanitize=address" $(MAKE) -C src/r2
	$(MAKE) -C src/r2 user-install

format indent fmt:
	clang-format-radare2 $(shell find src include src/r2 | grep '\.[c|h]$$')

$(STATIC_LIB): $(LIB_OBJ)
	ar rcs $@ $^

$(BIN_FILE): $(STATIC_LIB) $(MAIN_OBJ) | $(shell mkdir -p $(BIN_DIR))
	$(CC) $(CFLAGS) -o $@ $(MAIN_OBJ) -L$(BUILD_DIR) -lhbc

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(VH)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(MAIN_OBJ): $(MAIN_SRC) | $(VH)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)/libhbctool
	rm -f $(VH)
	$(MAKE) -C src/r2 clean

# Testing
TEST_DIR = tests
TEST_SRC = $(wildcard $(TEST_DIR)/*.c)
TEST_BIN = $(BIN_DIR)/run_tests


r2 test:
	$(MAKE) -C src/r2 && $(MAKE) -C src/r2 user-install
	r2r -i test/db/extras

r2one:
	$(MAKE) -C src/r2 r2one

user-install user-uninstall:
	$(MAKE) -C src/r2
	$(MAKE) -C src/r2 $@

$(VH):
	@mkdir -p $(dir $@)
	echo '#ifndef LIBHBC_VERSION' > $@
	echo '#define LIBHBC_VERSION "$(VERSION)"' >> $@
	echo '#define LIBHBC_VERSION_MAJOR "$(shell echo $(VERSION) | cut -d . -f 1)"' >> $@
	echo '#define LIBHBC_VERSION_MINOR "$(shell echo $(VERSION) | cut -d . -f 2)"' >> $@
	echo '#define LIBHBC_VERSION_PATCH "$(shell echo $(VERSION) | cut -d . -f 3)"' >> $@
	echo '#endif' >> $@

.PHONY: r2 test test2 all clean debug asan
