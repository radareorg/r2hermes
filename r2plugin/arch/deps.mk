HBC_ARCH_WD=$(LIBR)/plugs/p/r2hermes
CFLAGS+=-I$(HBC_ARCH_WD)/include
HBC_ARCH_OBJ=$(HBC_ARCH_WD)/src/r2/arch_hbc.o
LDFLAGS+=$(HBC_ARCH_WD)/build/libhbc.a
# XXX - stop using r_bin_get_info
LDFLAGS+=-lr_bin
EXTERNAL_STATIC_OBJS+=$(HBC_ARCH_OBJ)
