HBC_CORE_WD=$(LIBR)/xps/p/r2hermes
HBC_CORE_R2_CFLAGS=-I$(LIBR) -I$(LIBR)/include -I$(LIBR)/../shlr -I$(LIBR)/../subprojects/sdb/include
CFLAGS+=-I$(HBC_CORE_WD)/include $(HBC_CORE_R2_CFLAGS)
HBC_CORE_SRC=$(HBC_CORE_WD)/src/lib/utils/string_buffer.c \
	$(HBC_CORE_WD)/src/lib/utils/buffer_reader.c \
	$(HBC_CORE_WD)/src/lib/parsers/hbc_file_parser.c \
	$(HBC_CORE_WD)/src/lib/parsers/hbc_bytecode_parser.c \
	$(HBC_CORE_WD)/src/lib/decompilation/translator.c \
	$(HBC_CORE_WD)/src/lib/decompilation/token.c \
	$(HBC_CORE_WD)/src/lib/decompilation/literals.c \
	$(HBC_CORE_WD)/src/lib/decompilation/decompiler.c \
	$(HBC_CORE_WD)/src/lib/opcodes/isa.c \
	$(HBC_CORE_WD)/src/lib/opcodes/encoder.c \
	$(HBC_CORE_WD)/src/lib/opcodes/decoder.c \
	$(HBC_CORE_WD)/src/lib/hbc.c \
	$(HBC_CORE_WD)/src/lib/literals_api.c \
	$(HBC_CORE_WD)/src/lib/r2.c
HBC_CORE_LIB_OBJS=$(patsubst $(HBC_CORE_WD)/src/lib/%.c,$(HBC_CORE_WD)/build/r2plugin/%.o,$(HBC_CORE_SRC))
HBC_CORE_HEADERS=$(shell find $(HBC_CORE_WD)/include -name '*.h')
HBC_CORE_OBJ=$(HBC_CORE_WD)/src/r2/core_hbc_one.o
EXTERNAL_STATIC_OBJS+=$(HBC_CORE_LIB_OBJS) $(HBC_CORE_OBJ)

$(HBC_CORE_LIB_OBJS) $(HBC_CORE_OBJ): $(HBC_CORE_HEADERS)

$(HBC_CORE_WD)/build/r2plugin/%.o: $(HBC_CORE_WD)/src/lib/%.c
	@mkdir -p $(dir $@)
	$(CC) -c $(CFLAGS) -o $@ $<
