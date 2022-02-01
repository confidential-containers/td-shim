export CARGO=cargo
export BUILD_TYPE:=debug
export PREFIX:=/usr/local

export TOPDIR=$(shell pwd)
ifeq (${BUILD_TYPE},release)
	export BUILD_TYPE_FLAG= --release
else
	export BUILD_TYPE_FLAG=
endif

LIB_CRATES = pe-loader td-layout td-paging
SHIM_CRATES = rust-tdshim td-payload
TEST_CRATES = test-td-paging test-td-payload
TOOL_CRATES = td-shim-ld td-shim-enroll-key td-shim-sign-payload

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
integration-build: $(LIB_CRATES:%=integration-build-%)

integration-check: $(LIB_CRATES:%=integration-check-%)

integration-test: $(LIB_CRATES:%=integration-test-%)

integration-clean: $(LIB_CRATES:%=integration-clean-%)

# Target for crates which should be compiled with `x86_64-unknown-uefi` target
uefi-build-%:
	cargo xbuild --target x86_64-unknown-uefi -p $(patsubst uefi-build-%,%,$@) ${BUILD_TYPE_FLAG}

uefi-check-%:
	cargo xcheck --target x86_64-unknown-uefi -p $(patsubst uefi-check-%,%,$@) ${BUILD_TYPE_FLAG}

uefi-clean-%:
	cargo clean --target x86_64-unknown-uefi -p $(patsubst uefi-clean-%,%,$@) ${BUILD_TYPE_FLAG}

# Target for integration test crates which should be compiled with `x86_64-custom.json` target
integration-build-%:
	cargo xbuild --target ${TOPDIR}/devtools/rustc-targets/x86_64-custom.json -p $(patsubst integration-build-%,%,$@) ${BUILD_TYPE_FLAG}

integration-check-%:
	cargo xcheck --target ${TOPDIR}/devtools/rustc-targets/x86_64-custom.json -p $(patsubst integration-check-%,%,$@) ${BUILD_TYPE_FLAG}

integration-test-%:
	cargo xtest --target ${TOPDIR}/devtools/rustc-targets/x86_64-custom.json -p $(patsubst integration-test-%,%,$@) ${BUILD_TYPE_FLAG}

integration-clean-%:
	cargo clean --target ${TOPDIR}/devtools/rustc-targets/x86_64-custom.json -p $(patsubst integration-clean-%,%,$@) ${BUILD_TYPE_FLAG}

# Targets for normal library/binary crates
build-%:
	cargo build -p $(patsubst build-%,%,$@) ${BUILD_TYPE_FLAG}

check-%:
	cargo check -p $(patsubst check-%,%,$@) ${BUILD_TYPE_FLAG}

clean-%:
	cargo clean -p $(patsubst clean-%,%,$@) ${BUILD_TYPE_FLAG}

test-%:
	cargo test -p $(patsubst test-%,%,$@) ${BUILD_TYPE_FLAG}

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
