# Makefile for Hermes radare2 plugins
# Standalone build system for the Hermes Bytecode radare2 plugins

# Compiler and flags
CC ?= gcc
CFLAGS += -Wall -Wextra -std=c11 -O2 -fPIC
CFLAGS += -I../../include
CFLAGS += $(shell pkg-config --cflags r_core 2>/dev/null || echo "-I/usr/local/include/libr")
R2_PLUGDIR?=$(shell r2 -H R2_USER_PLUGINS)
R2_PREFIX?=$(shell r2 -H R2_PREFIX)
LDFLAGS += $(shell pkg-config --libs r_core 2>/dev/null || echo "-L/usr/local/lib -lr_core -lr_config -lr_debug -lr_bin -lr_lang -lr_anal -lr_bp -lr_egg -lr_asm -lr_arch -lr_esil -lr_flag -lr_reg -lr_search -lr_syscall -lr_fs -lr_io -lr_socket -lr_cons -lr_magic -lr_muta -lr_util -ldl")

# Detect platform for shared library extension
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	EXT_SO = dylib
	LDFLAGS += -dynamiclib
else ifeq ($(UNAME_S),Linux)
	EXT_SO = so
	LDFLAGS += -shared
else ifeq ($(UNAME_S),MINGW32_NT)
	EXT_SO = dll
	LDFLAGS += -shared
else
	EXT_SO = so
	LDFLAGS += -shared
endif

# Source files
ARCH_SRC = arch_hbc.c
BIN_SRC = bin_hbc.c
ASM_SRC = asm_hbc.c

# Object files
ARCH_OBJ = arch_hbc.o
BIN_OBJ = bin_hbc.o
ASM_OBJ = asm_hbc.o

# Target plugins
ARCH_PLUGIN = arch_hbc.$(EXT_SO)
BIN_PLUGIN = bin_hbc.$(EXT_SO)
ASM_PLUGIN = asm_hbc.$(EXT_SO)

# Library paths
HERMES_LIB_DIR = ../../build
HERMES_LIB = $(HERMES_LIB_DIR)/libhbc.a

# All targets
ALL_TARGETS = $(ARCH_PLUGIN) $(BIN_PLUGIN) $(ASM_PLUGIN)

.PHONY: all clean install help check-r2

all: check-deps $(ALL_TARGETS)

# Check if radare2 development headers are available
check-deps: $(HERMES_LIB)
	@echo "Checking for radare2 development headers..."
	@if [ ! -f "/usr/include/libr/r_anal.h" ] && [ ! -f "/usr/local/include/libr/r_anal.h" ] && [ ! -f "/opt/radare2/include/libr/r_anal.h" ]; then \
		echo "Warning: radare2 development headers not found in standard locations."; \
		echo "The plugins will be built but may not work without proper radare2 headers."; \
		echo "Please install radare2 development packages or set RADARE2_INCLUDE_PATH."; \
	else \
		echo "radare2 development headers found."; \
	fi

# Architecture plugin
$(ARCH_PLUGIN): $(ARCH_OBJ) $(HERMES_LIB)
	$(CC) $(LDFLAGS) -o $@ $(ARCH_OBJ) $(HERMES_LIB)

# Binary format plugin
$(BIN_PLUGIN): $(BIN_OBJ) $(HERMES_LIB)
	$(CC) $(LDFLAGS) -o $@ $(BIN_OBJ) $(HERMES_LIB)

# Assembler/pseudo plugin
$(ASM_PLUGIN): $(ASM_OBJ)
	$(CC) $(LDFLAGS) -o $@ $(ASM_OBJ)

# Compile object files
$(ARCH_OBJ): $(ARCH_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN_OBJ): $(BIN_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(ASM_OBJ): $(ASM_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(ARCH_OBJ) $(BIN_OBJ) $(ASM_OBJ) $(ALL_TARGETS)

# Install plugins (optional - requires radare2 installation)
install: $(ALL_TARGETS)
	cp $(ARCH_PLUGIN) $(R2_PREFIX)/lib/radare2/last/
	cp $(BIN_PLUGIN) $(R2_PREFIX)/lib/radare2/last/

user-install:
	mkdir -p $(R2_PLUGDIR)
	rm -f $(R2_PLUGDIR)/*hbc.$(EXT_SO)
	cp -f $(ARCH_PLUGIN) $(R2_PLUGDIR)
	cp -f $(BIN_PLUGIN) $(R2_PLUGDIR)
	cp -f $(ASM_PLUGIN) $(R2_PLUGDIR)

user-uninstall:
	rm -f $(R2_PLUGDIR)/$(ARCH_PLUGIN)
	rm -f $(R2_PLUGDIR)/$(BIN_PLUGIN)
	rm -f $(R2_PLUGDIR)/$(ASM_PLUGIN)

# Uninstall plugins
uninstall:
	rm -f $(R2_PREFIX)/lib/radare2/last/$(ARCH_PLUGIN)
	rm -f $(R2_PREFIX)/lib/radare2/last/$(BIN_PLUGIN)

# Check radare2 installation
check-r2:
	@echo "Checking radare2 installation..."
	@if command -v r2 >/dev/null 2>&1; then \
		R2_PATH=$$(which r2); \
		R2_DIR=$$(dirname $$R2_PATH); \
		if [ -d "$$R2_DIR/../lib/radare2/plugins" ]; then \
			echo "Found radare2 plugin directory: $$R2_DIR/../lib/radare2/plugins"; \
			echo "Use: make install R2_PLUGDIR=$$R2_DIR/../lib/radare2/plugins"; \
		elif [ -d "$$R2_DIR/../lib64/radare2/plugins" ]; then \
			echo "Found radare2 plugin directory: $$R2_DIR/../lib64/radare2/plugins"; \
			echo "Use: make install R2_PLUGDIR=$$R2_DIR/../lib64/radare2/plugins"; \
		else \
			echo "radare2 found at $$R2_PATH but plugin directory not found."; \
		fi \
	else \
		echo "radare2 not found. Please install radare2 first."; \
		exit 1; \
	fi

# Show help
help:
	@echo "Hermes radare2 Plugin Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all         - Build all plugins (default)"
	@echo "  clean       - Remove build artifacts"
	@echo "  install     - Install plugins to radare2"
	@echo "  uninstall   - Remove plugins from radare2"
	@echo "  check-r2    - Check radare2 installation and find plugin directory"
	@echo "  help        - Show this help"
	@echo ""
	@echo "Variables:"
	@echo "  R2_PLUGDIR  - Path to radare2 plugin directory for installation"
	@echo "  CC          - C compiler (default: gcc)"
	@echo "  CFLAGS      - Additional compiler flags"
	@echo ""
	@echo "Usage:"
	@echo "  make                    # Build plugins"
	@echo "  make check-r2           # Find radare2 plugin directory"
	@echo "  make install R2_PLUGDIR=/path/to/r2/plugins  # Build and install"
	@echo "  make uninstall R2_PLUGDIR=/path/to/r2/plugins # Remove plugins"
	@echo ""
	@echo "Requirements:"
	@echo "  - libhbc (built automatically)"
	@echo "  - radare2 development headers (for proper compilation)"
	@echo "  - radare2 installation (for plugin loading)"

# Dependencies
$(HERMES_LIB):
	@echo "Building libhbc library..."
	$(MAKE) -C .. all

# Default target
.DEFAULT_GOAL := all
