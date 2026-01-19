HBC_CORE_WD=$(LIBR)/xps/p/r2hermes
CFLAGS+=-I$(HBC_CORE_WD)/include
HBC_CORE_OBJ=$(HBC_CORE_WD)/src/r2/core_hbc_one.o
HBC_CORE_OBJ+=$(HBC_CORE_WD)/src/r2/data_provider_r2.o
LDFLAGS+=$(HBC_CORE_WD)/build/libhbc.a
EXTERNAL_STATIC_OBJS+=$(HBC_CORE_OBJ)
