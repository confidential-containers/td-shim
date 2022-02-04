export CARGO=cargo
export STABLE_TOOLCHAIN:=1.58.1
export NIGHTLY_TOOLCHAIN:=nightly-2021-08-20
export BUILD_TYPE:=debug
export PREFIX:=/usr/local

export TOPDIR=$(shell pwd)
ifeq (${BUILD_TYPE},release)
	export BUILD_TYPE_FLAG= --release
else
	export BUILD_TYPE_FLAG=
endif

LIB_CRATES = td-layout td-paging
SHIM_CRATES = 
TEST_CRATES = 
TOOL_CRATES = 

# Targets for normal artifacts
all: install-devtools build test

build: $(SHIM_CRATES:%=uefi-build-%) $(TOOL_CRATES:%=build-%)

check: $(SHIM_CRATES:%=uefi-check-%) $(TOOL_CRATES:%=check-%)

clean: $(SHIM_CRATES:%=uefi-clean-%) $(TOOL_CRATES:%=clean-%)

test: $(SHIM_CRATES:%=test-%) $(TOOL_CRATES:%=test-%)

install: $(TOOL_CRATES:%=install-tool-%)

uninstall: $(TOOL_CRATES:%=uninstall-tool-%)

# Targets to catch them all
full-build: lib-build build integration-build

full-check: lib-check check integration-check

full-test: lib-test test integration-test

full-clean: lib-clean clean integration-clean clean-subdir-devtools

# Targets for development tools
install-devtools: build-subdir-devtools install-subdir-devtools $(TOOL_CRATES:%=install-devtool-%)

uninstall-devtools: uninstall-subdir-devtools $(TOOL_CRATES:%=uninstall-devtool-%)

install-devtool-%: build-%
	mkdir -p ${TOPDIR}/devtools/bin
	install -m u+rx ${TOPDIR}/target/${BUILD_TYPE}/$(patsubst install-devtool-%,%,$@) ${TOPDIR}/devtools/bin/

uninstall-devtool-%:
	rm ${TOPDIR}/devtools/bin/$(patsubst uninstall-devtool-%,%,$@)

# Targets for tool crates
install-tool-%: build-%
	mkdir -p ${TOPDIR}/devtools/bin
	install -m u+rx ${TOPDIR}/target/${BUILD_TYPE}/$(patsubst install-tool-%,%,$@) ${PREFIX}/bin/

uninstall-tool-%:
	rm ${PREFIX}/bin/$(patsubst uninstall-tool-%,%,$@)

# Targets for library crates
lib-build: $(LIB_CRATES:%=build-%)

lib-check: $(LIB_CRATES:%=check-%)

lib-test: $(LIB_CRATES:%=test-%)

lib-clean: $(LIB_CRATES:%=clean-%)

# Targets for integration test crates
integration-build: $(TEST_CRATES:%=integration-build-%)

integration-check: $(TEST_CRATES:%=integration-check-%)

integration-test: $(TEST_CRATES:%=integration-test-%)

integration-clean: $(TEST_CRATES:%=integration-clean-%)

# Target for crates which should be compiled with `x86_64-unknown-uefi` target
uefi-build-%:
	${CARGO} +${NIGHTLY_TOOLCHAIN} xbuild --target x86_64-unknown-uefi -p $(patsubst uefi-build-%,%,$@) ${BUILD_TYPE_FLAG}

uefi-check-%:
	 ${CARGO} +${NIGHTLY_TOOLCHAIN}xcheck --target x86_64-unknown-uefi -p $(patsubst uefi-check-%,%,$@) ${BUILD_TYPE_FLAG}

uefi-clean-%:
	${CARGO} +${NIGHTLY_TOOLCHAIN} clean --target x86_64-unknown-uefi -p $(patsubst uefi-clean-%,%,$@) ${BUILD_TYPE_FLAG}

# Target for integration test crates which should be compiled with `x86_64-custom.json` target
integration-build-%:
	${CARGO} +${NIGHTLY_TOOLCHAIN} xbuild --target ${TOPDIR}/devtools/rustc-targets/x86_64-custom.json -p $(patsubst integration-build-%,%,$@) ${BUILD_TYPE_FLAG}

integration-check-%:
	${CARGO} +${NIGHTLY_TOOLCHAIN} xcheck --target ${TOPDIR}/devtools/rustc-targets/x86_64-custom.json -p $(patsubst integration-check-%,%,$@) ${BUILD_TYPE_FLAG}

integration-test-%:
	${CARGO} +${NIGHTLY_TOOLCHAIN} xtest --target ${TOPDIR}/devtools/rustc-targets/x86_64-custom.json -p $(patsubst integration-test-%,%,$@) ${BUILD_TYPE_FLAG}

integration-clean-%:
	${CARGO} +${NIGHTLY_TOOLCHAIN} clean --target ${TOPDIR}/devtools/rustc-targets/x86_64-custom.json -p $(patsubst integration-clean-%,%,$@) ${BUILD_TYPE_FLAG}

# Targets for normal library/binary crates
build-%:
	${CARGO} +${STABLE_TOOLCHAIN} build -p $(patsubst build-%,%,$@) ${BUILD_TYPE_FLAG}

check-%:
	${CARGO} +${STABLE_TOOLCHAIN} check -p $(patsubst check-%,%,$@) ${BUILD_TYPE_FLAG}

clean-%:
	${CARGO} +${STABLE_TOOLCHAIN} clean -p $(patsubst clean-%,%,$@) ${BUILD_TYPE_FLAG}

test-%:
	${CARGO} +${STABLE_TOOLCHAIN} test -p $(patsubst test-%,%,$@) ${BUILD_TYPE_FLAG}

# Targets for subdirectories
build-subdir-%:
	make -C $(patsubst build-subdir-%,%,$@) build

check-subdir-%:
	make -C $(patsubst check-subdir-%,%,$@) check

clean-subdir-%:
	make -C $(patsubst clean-subdir-%,%,$@) clean

install-subdir-%:
	make -C $(patsubst install-subdir-%,%,$@) install

uninstall-subdir-%:
	make -C $(patsubst uninstall-subdir-%,%,$@) uninstall
