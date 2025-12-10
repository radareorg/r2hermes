CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c11 -pedantic -O2
DEBUG_FLAGS = -g -DDEBUG

# Directories
SRC_DIR = src
INCLUDE_DIR = include
BUILD_DIR = build
BIN_DIR = bin

## Source files
UTILS_SRC = $(wildcard $(SRC_DIR)/utils/*.c)
PARSERS_SRC = $(wildcard $(SRC_DIR)/parsers/*.c)
DISASM_SRC = $(wildcard $(SRC_DIR)/disassembly/*.c)
DECOMPILE_SRC = $(wildcard $(SRC_DIR)/decompilation/*.c)
OPCODES_SRC = $(wildcard $(SRC_DIR)/opcodes/*.c)
LIB_SRC = $(UTILS_SRC) $(PARSERS_SRC) $(DISASM_SRC) $(DECOMPILE_SRC) $(OPCODES_SRC) \
          $(SRC_DIR)/lib/hbc.c $(SRC_DIR)/hermes_encoder.c
MAIN_SRC = $(SRC_DIR)/main.c

## Object files
LIB_OBJ = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(LIB_SRC))
MAIN_OBJ = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(MAIN_SRC))

## Artifacts
BIN_FILE = $(BIN_DIR)/hermes-dec
STATIC_LIB = $(BUILD_DIR)/libhbc.a

# Include paths
INCLUDES = -I$(INCLUDE_DIR)

# Targets
.PHONY: all clean debug

all: prepare $(BIN_FILE)

debug: CFLAGS += $(DEBUG_FLAGS)
debug: all

format indent fmt:
	clang-format-radare2 $(shell find src include | grep '\.[c|h]$$')

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
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

# Testing
TEST_DIR = tests
TEST_SRC = $(wildcard $(TEST_DIR)/*.c)
TEST_BIN = $(BIN_DIR)/run_tests

.PHONY: r2 test test2

r2 test:
	$(MAKE) -C r2 && $(MAKE) -C r2 user-install

user-install user-uninstall:
	$(MAKE) -C r2

test2:
	./bin/hermes-dec d ../main.jsbundle 2>&1 |head -n 100

otest: prepare $(TEST_BIN)
	$(TEST_BIN)

$(TEST_BIN): $(STATIC_LIB) $(TEST_SRC:.c=.o)
	$(CC) $(CFLAGS) -o $@ $(TEST_SRC:.c=.o) -L$(BUILD_DIR) -lhbc

$(TEST_DIR)/%.o: $(TEST_DIR)/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@
