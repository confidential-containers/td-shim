export CARGO=cargo
export BUILD_TYPE:=debug

export TOPDIR=$(shell pwd)
ifeq (${BUILD_TYPE},release)
	export BUILD_TYPE_FLAG= --release
else
	export BUILD_TYPE_FLAG=
endif

LIB_CRATES = td-layout td-paging
LIB_TEST_CRATES = test-td-paging test-td-payload
SHIM_CRATES = rust-tdshim
PAYLOAD_CRATES = tdx-payload

# Targets for normal artifacts
all: install-devtools build test

build: $(SHIM_CRATES:%=uefi-build-%) $(PAYLOAD_CRATES:%=td-build-%)

check: $(SHIM_CRATES:%=uefi-check-%) $(PAYLOAD_CRATES:%=td-check-%)

clean: $(SHIM_CRATES:%=clean-%) $(PAYLOAD_CRATES:%=clean-%)

test: $(SHIM_CRATES:%=test-%) $(PAYLOAD_CRATES:%=test-%)

install:

uninstall:

# Targets for whole project
full-build: lib-build build

full-check: lib-check check

full-test: lib-test test

full-clean: lib-clean clean clean-subdir-devtools

# Targets for development tools
install-devtools: build-subdir-devtools install-subdir-devtools

uninstall-devtools: uninstall-subdir-devtools

# Targets for subdirectory
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

# Targets for library crates
lib-build: $(LIB_CRATES:%=build-%) $(LIB_TEST_CRATES:%=td-build-%)

lib-check: $(LIB_CRATES:%=check-%) $(LIB_TEST_CRATES:%=td-check-%)

lib-test: $(LIB_CRATES:%=test-%) $(LIB_TEST_CRATES:%=td-test-%)

lib-clean: $(LIB_CRATES:%=clean-%) $(LIB_TEST_CRATES:%=clean-%)

# Target for crates which should be compiled for `x86_64-unknown-uefi` target
uefi-build-%:
	cargo xbuild --target x86_64-unknown-uefi -p $(patsubst uefi-build-%,%,$@) ${BUILD_TYPE_FLAG}

uefi-check-%:
	cargo xcheck --target x86_64-unknown-uefi -p $(patsubst uefi-check-%,%,$@) ${BUILD_TYPE_FLAG}

uefi-test-%:
	cargo xtest --target x86_64-unknown-uefi -p $(patsubst uefi-test-%,%,$@) ${BUILD_TYPE_FLAG}

# Target for crates which should be compiled for `x86_64-custom.json` target
td-build-%:
	cargo xbuild --target ${TOPDIR}/devtools/rustc-targets/x86_64-custom.json -p $(patsubst td-build-%,%,$@) ${BUILD_TYPE_FLAG}

td-check-%:
	cargo xcheck --target ${TOPDIR}/devtools/rustc-targets/x86_64-custom.json -p $(patsubst td-check-%,%,$@) ${BUILD_TYPE_FLAG}

td-test-%:
	cargo xtest --target ${TOPDIR}/devtools/rustc-targets/x86_64-custom.json -p $(patsubst td-test-%,%,$@) ${BUILD_TYPE_FLAG}

# Targets for normal library/binary crates
build-%:
	cargo build -p $(patsubst build-%,%,$@) ${BUILD_TYPE_FLAG}

check-%:
	cargo check -p $(patsubst check-%,%,$@) ${BUILD_TYPE_FLAG}

clean-%:
	cargo clean -p $(patsubst clean-%,%,$@) ${BUILD_TYPE_FLAG}

test-%:
	cargo test -p $(patsubst test-%,%,$@) ${BUILD_TYPE_FLAG}
