HBC_ASM_WD=$(LIBR)/plugs/p/r2hermes
CFLAGS+=-I$(HBC_ASM_WD)/include
HBC_ASM_OBJ=$(HBC_ASM_WD)/src/r2/asm_hbc.o
LDFLAGS+=$(HBC_ASM_WD)/build/libhbc.a
EXTERNAL_STATIC_OBJS+=$(HBC_ASM_OBJ)
