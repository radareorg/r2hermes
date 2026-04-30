include ./CONFIG

UNAME=$(shell uname)
SUDO?=sudo
PWD=$(shell pwd)
PACKAGE_DIR?=$(PWD)
R2_VERSION=$(shell r2 -qv 2>/dev/null || echo last)
R2PLUGDIR?=/usr/lib/radare2/$(R2_VERSION)
R2_PLUGINS=arch_hbc.so asm_hbc.so bin_hbc.so core_hbc.so

all: root
	$(SUDO) rm -rf control data
	$(MAKE) clean
	mkdir -p data
	cp -rf root/* data
	$(MAKE) control
	$(MAKE) deb

root:
ifneq ($(UNAME),Linux)
	@echo "Debian packages must be built on Linux so radare2 plugins are built as .so files."
	@false
else
	cd ../.. && $(MAKE) clean && $(MAKE) && $(MAKE) -C src/r2
	rm -rf root
	mkdir -p root/usr/bin
	cp -f ../../bin/libhbctool root/usr/bin/
	mkdir -p root/usr/lib
	cp -f ../../build/libhbc.a root/usr/lib/
	mkdir -p root/usr/include
	cp -rf ../../include/hbc root/usr/include/
	mkdir -p root/$(R2PLUGDIR)
	for plugin in $(R2_PLUGINS); do cp -f ../../src/r2/$$plugin root/$(R2PLUGDIR)/; done
endif

purge: clean
	rm -rf root

summary:
	echo $(VERSION)

include deb.mk
