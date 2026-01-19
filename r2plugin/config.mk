EXTERNAL_PLUGINS+=r2hermes
# EXTERNAL_PLUGINS+=hi

.PHONY: r2hermes

r2hermes: p/r2hermes

p/r2hermes:
	cd p && git clone https://github.com/radareorg/r2hermes
	cd p/r2hermes && git checkout r2plugone
