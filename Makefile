CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -pedantic -O2 -fPIC -D_POSIX_C_SOURCE=200809L
DEBUG_FLAGS = -g -DDEBUG -DHBC_DEBUG_LOGGING=1

# Directories
SRC_DIR = src/lib
INCLUDE_DIR = include
BUILD_DIR = build
BIN_DIR = bin

## Source files
UTILS_SRC = $(wildcard $(SRC_DIR)/utils/*.c)
PARSERS_SRC = $(wildcard $(SRC_DIR)/parsers/*.c)
DISASM_SRC = $(wildcard $(SRC_DIR)/disassembly/*.c)
DECOMPILE_SRC = $(wildcard $(SRC_DIR)/decompilation/*.c)
OPCODES_SRC = $(filter-out $(SRC_DIR)/opcodes/%.inc.c,$(wildcard $(SRC_DIR)/opcodes/*.c))
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
INCLUDES = -I$(INCLUDE_DIR)

# Targets
.PHONY: all clean debug asan

all: prepare $(BIN_FILE)

debug: CFLAGS += $(DEBUG_FLAGS)
debug: all

ASAN_FLAGS = -fsanitize=address -fno-omit-frame-pointer -g

asan:
	$(MAKE) clean
	$(MAKE) all CFLAGS="$(CFLAGS) $(ASAN_FLAGS)" LDFLAGS="$(LDFLAGS) -fsanitize=address"
	CFLAGS="$(ASAN_FLAGS)" LDFLAGS="-fsanitize=address" $(MAKE) -C src/r2
	$(MAKE) -C src/r2 user-install

format indent fmt:
	clang-format-radare2 $(shell find src include src/r2 | grep '\.[c|h]$$')

prepare:
	@mkdir -p $(BUILD_DIR)/utils
	@mkdir -p $(BUILD_DIR)/parsers
	@mkdir -p $(BUILD_DIR)/disassembly
	@mkdir -p $(BUILD_DIR)/decompilation
	@mkdir -p $(BUILD_DIR)/opcodes
	@mkdir -p $(BUILD_DIR)/lib
	@mkdir -p $(BIN_DIR)

$(STATIC_LIB): $(LIB_OBJ)
	ar rcs $@ $^

$(BIN_FILE): $(STATIC_LIB) $(MAIN_OBJ)
	$(CC) $(CFLAGS) -o $@ $(MAIN_OBJ) -L$(BUILD_DIR) -lhbc

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(MAIN_OBJ): $(MAIN_SRC)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)/libhbctool
	$(MAKE) -C src/r2 clean

# Testing
TEST_DIR = tests
TEST_SRC = $(wildcard $(TEST_DIR)/*.c)
TEST_BIN = $(BIN_DIR)/run_tests

.PHONY: r2 test test2

r2 test:
	$(MAKE) -C src/r2 && $(MAKE) -C src/r2 user-install
	r2r -i test/db/extras

user-install user-uninstall:
	$(MAKE) -C src/r2
	$(MAKE) -C src/r2 $@

test2:
	./bin/libhbctool d ../main.jsbundle 2>&1 |head -n 100

otest: prepare $(TEST_BIN)
	$(TEST_BIN)

$(TEST_BIN): $(STATIC_LIB) $(TEST_SRC:.c=.o)
	$(CC) $(CFLAGS) -o $@ $(TEST_SRC:.c=.o) -L$(BUILD_DIR) -lhbc

$(TEST_DIR)/%.o: $(TEST_DIR)/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@
