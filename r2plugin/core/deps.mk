HBC_CORE_WD=$(LIBR)/xps/p/r2hermes
HBC_CORE_LIB=$(HBC_CORE_WD)/build/libhbc.a
HBC_CORE_R2_CFLAGS=-I$(LIBR) -I$(LIBR)/include -I$(LIBR)/../shlr -I$(LIBR)/../subprojects/sdb/include
CFLAGS+=-I$(HBC_CORE_WD)/include
HBC_CORE_OBJ=$(HBC_CORE_WD)/src/r2/core_hbc_one.o
LDFLAGS+=$(HBC_CORE_LIB)
EXTERNAL_STATIC_OBJS+=$(HBC_CORE_OBJ)

$(HBC_CORE_OBJ): $(HBC_CORE_LIB)

$(HBC_CORE_LIB):
	$(MAKE) -C $(HBC_CORE_WD) build/libhbc.a CC="$(CC)" R2_CFLAGS="$(HBC_CORE_R2_CFLAGS)"
