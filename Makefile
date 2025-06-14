CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c11 -pedantic -O2
DEBUG_FLAGS = -g -DDEBUG

# Directories
SRC_DIR = src
INCLUDE_DIR = include
BUILD_DIR = build
BIN_DIR = bin

# Source files
UTILS_SRC = $(wildcard $(SRC_DIR)/utils/*.c)
PARSERS_SRC = $(wildcard $(SRC_DIR)/parsers/*.c)
DISASM_SRC = $(wildcard $(SRC_DIR)/disassembly/*.c)
DECOMPILE_SRC = $(wildcard $(SRC_DIR)/decompilation/*.c)
OPCODES_SRC = $(wildcard $(SRC_DIR)/opcodes/*.c)
MAIN_SRC = $(SRC_DIR)/main.c

# All source files
SRC_FILES = $(UTILS_SRC) $(PARSERS_SRC) $(DISASM_SRC) $(DECOMPILE_SRC) $(OPCODES_SRC) $(MAIN_SRC)

# Object files
OBJ_FILES = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRC_FILES))

# Binary file
BIN_FILE = $(BIN_DIR)/hermes-dec

# Include paths
INCLUDES = -I$(INCLUDE_DIR)

# Targets
.PHONY: all clean debug

all: prepare $(BIN_FILE)

debug: CFLAGS += $(DEBUG_FLAGS)
debug: all

prepare:
	@mkdir -p $(BUILD_DIR)/utils
	@mkdir -p $(BUILD_DIR)/parsers
	@mkdir -p $(BUILD_DIR)/disassembly
	@mkdir -p $(BUILD_DIR)/decompilation
	@mkdir -p $(BUILD_DIR)/opcodes
	@mkdir -p $(BIN_DIR)

$(BIN_FILE): $(OBJ_FILES)
	$(CC) $(CFLAGS) -o $@ $^

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

# Testing
TEST_DIR = tests
TEST_SRC = $(wildcard $(TEST_DIR)/*.c)
TEST_BIN = $(BIN_DIR)/run_tests

.PHONY: test

test: prepare $(TEST_BIN)
	$(TEST_BIN)

$(TEST_BIN): $(filter-out $(BUILD_DIR)/main.o,$(OBJ_FILES)) $(TEST_SRC:.c=.o)
	$(CC) $(CFLAGS) -o $@ $^

$(TEST_DIR)/%.o: $(TEST_DIR)/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@