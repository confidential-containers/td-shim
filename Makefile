export CARGO=cargo
export BUILD_TYPE:=release
export PREFIX:=/usr/local

export TOPDIR=$(shell pwd)
ifeq (${BUILD_TYPE},release)
	export BUILD_TYPE_FLAG= --release
else
	export BUILD_TYPE_FLAG=
endif

LIB_CRATES = td-loader td-exception td-layout td-logger td-paging tdx-tdcall
SHIM_CRATES = td-shim td-payload
TEST_CRATES = test-td-exception test-td-paging test-td-payload
TOOL_CRATES = td-shim-tools

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
	cargo install --bins --target-dir ${TOPDIR}/devtools/bin/ --path $(patsubst install-devtool-%,%,$@)

uninstall-devtool-%:
	cargo uninstall --root ${TOPDIR}/devtools/bin/ --path $(patsubst uninstall-devtool-%,%,$@)

# Targets for tool crates
install-tool-%: build-%
	cargo install --bins --path $(patsubst install-tool-%,%,$@)

uninstall-tool-%:
	cargo uninstall --path $(patsubst uninstall-devtool-%,%,$@)

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
	cargo xbuild --target x86_64-unknown-uefi -p $(patsubst uefi-build-%,%,$@) --features=main ${BUILD_TYPE_FLAG}

uefi-check-%:
	cargo xcheck --target x86_64-unknown-uefi -p $(patsubst uefi-check-%,%,$@) --features=main ${BUILD_TYPE_FLAG}

uefi-clean-%:
	cargo clean --target x86_64-unknown-uefi -p $(patsubst uefi-clean-%,%,$@) --features=main ${BUILD_TYPE_FLAG}

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
