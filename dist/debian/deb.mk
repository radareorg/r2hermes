# Create .deb without using dpkg tools.
#
# Author: Tim Wegener <twegener@madabar.com>
#
# Use 'include deb.mk' after defining the user variables in a local
# makefile.

ifeq ($(shell uname),Darwin)
MD5SUM=md5
else
MD5SUM=md5sum
endif

GAWK=awk
PACKAGE_DIR=$(shell pwd)
CONTROL_EXTRAS ?= ${wildcard preinst postinst prerm postrm}

${PACKAGE_DIR}/control: ${PACKAGE_DIR}/data ${CONTROL_EXTRAS} DESCR \
			${ICON_SOURCE}
	mkdir -p $@
ifneq (${CONTROL_EXTRAS},)
	cp ${CONTROL_EXTRAS} $@
endif
	echo "Package: ${PACKAGE}" > $@/control
	echo "Version: ${VERSION}" >> $@/control
	echo "Section: ${SECTION}" >> $@/control
	echo "Priority: ${PRIORITY}" >> $@/control
	echo "Architecture: ${ARCH}" >> $@/control
ifneq (${DEPENDS},)
	echo "Depends: ${DEPENDS}" >> $@/control
endif
	echo "Installed-Size: ${shell du -s ${PACKAGE_DIR}/data|cut -f1}" \
		>> $@/control
	echo "Maintainer: ${MAINTAINER}" >> $@/control
	printf "Description:" >> $@/control
	cat DESCR | ${GAWK} '{print " "$$0;}' >> $@/control
	cd ${PACKAGE_DIR}/data && find . -type f -exec ${MD5SUM} {} \; \
		| sed -e 's| \./||' \
		> $@/md5sums

${PACKAGE_DIR}/debian-binary:
	echo "2.0" > $@

${PACKAGE_DIR}/clean:
	rm -rf ${PACKAGE_DIR}/data ${PACKAGE_DIR}/control ${PACKAGE_DIR}/build *.deb

${PACKAGE_DIR}/build: ${PACKAGE_DIR}/debian-binary ${PACKAGE_DIR}/control \
			${PACKAGE_DIR}/data
	rm -rf $@
	mkdir $@
	cp ${PACKAGE_DIR}/debian-binary $@/
	cd ${PACKAGE_DIR}/control && tar czvf $@/control.tar.gz *
	cd ${PACKAGE_DIR}/data && \
		COPY_EXTENDED_ATTRIBUTES_DISABLE=true \
		COPYFILE_DISABLE=true \
		tar cpzvf $@/data.tar.gz *

${PACKAGE_DIR}/${PACKAGE}_${VERSION}_${ARCH}.deb: ${PACKAGE_DIR}/build
	ar -rc $@ $</debian-binary $</control.tar.gz $</data.tar.gz

.PHONY: data
data: ${PACKAGE_DIR}/data

.PHONY: control
control: ${PACKAGE_DIR}/control

.PHONY: build
build: ${PACKAGE_DIR}/build

.PHONY: clean
clean: ${PACKAGE_DIR}/clean $(EXTRA_CLEAN)
	rm -f debian-binary

.PHONY: deb
deb: ${PACKAGE_DIR}/${PACKAGE}_${VERSION}_${ARCH}.deb

clobber::
	rm -rf ${PACKAGE_DIR}/debian_binary ${PACKAGE_DIR}/control \
		${PACKAGE_DIR}/data ${PACKAGE_DIR}/build

push:
	scp *.deb radare.org:/srv/http/radareorg/cydia/debs

mrproper: clean
	rm -rf root
