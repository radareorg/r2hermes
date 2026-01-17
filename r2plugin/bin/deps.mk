HBC_BIN_WD=$(LIBR)/plugs/p/r2hermes
CFLAGS+=-I$(LIBR)/plugs/p/r2hermes/include
HBC_BIN_OBJ=$(HBC_BIN_WD)/src/r2/bin_hbc.o
LDFLAGS+=$(HBC_BIN_WD)/build/libhbc.a
EXTERNAL_STATIC_OBJS+=$(HBC_BIN_OBJ)
