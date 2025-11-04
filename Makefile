export CARGO=cargo
export STABLE_TOOLCHAIN:=1.88.0
export NIGHTLY_TOOLCHAIN:=nightly-2023-12-31
export BUILD_TYPE:=release
export PREFIX:=/usr/local

export TOPDIR=$(shell pwd)
ifeq (${BUILD_TYPE},release)
	export BUILD_TYPE_FLAG= --release
else
	export BUILD_TYPE_FLAG=
endif

LIB_CRATES = td-layout td-logger td-shim-interface td-loader cc-measurement td-exception td-paging tdx-tdcall
SHIM_CRATES = td-shim td-payload
TEST_CRATES = test-td-exception test-td-paging
TOOL_CRATES = td-shim-tools

# Targets for normal artifacts
all: preparation install-devtools build test afl-test libfuzzer-test

preparation: apply_patches

build: $(SHIM_CRATES:%=none-build-%) $(TOOL_CRATES:%=build-%)

check: $(SHIM_CRATES:%=none-check-%) $(TOOL_CRATES:%=check-%)

clean: $(SHIM_CRATES:%=none-clean-%) $(TOOL_CRATES:%=clean-%)

test: $(SHIM_CRATES:%=test-%) $(TOOL_CRATES:%=test-%)

install: $(TOOL_CRATES:%=install-tool-%)

uninstall: $(TOOL_CRATES:%=uninstall-tool-%)

# Targets to catch them all
full-build: lib-build build integration-build

full-check: lib-check check integration-check

full-test: lib-test test integration-test afl-test libfuzzer-test

full-clean: lib-clean clean integration-clean clean-subdir-devtools

# Targets for development tools
install-devtools: build-subdir-devtools install-subdir-devtools $(TOOL_CRATES:%=install-devtool-%)

uninstall-devtools: uninstall-subdir-devtools $(TOOL_CRATES:%=uninstall-devtool-%)

.PHONY: tools-devtools
tools-devtools: tools-subdir-devtools

install-devtool-%:
	mkdir -p ${TOPDIR}/devtools/bin
	${CARGO} install --bins --target-dir ${TOPDIR}/devtools/bin/ --path $(patsubst install-devtool-%,%,$@)

uninstall-devtool-%:
	${CARGO} uninstall --root ${TOPDIR}/devtools/bin/ --path $(patsubst uninstall-devtool-%,%,$@)

# Targets for tool crates
install-tool-%: build-%
	${CARGO} install --bins --path $(patsubst install-tool-%,%,$@)

uninstall-tool-%:
	${CARGO} uninstall --path $(patsubst uninstall-devtool-%,%,$@)

# Fuzzing test
afl-test: afl_test

libfuzzer-test: libfuzzer_test

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

# Target for crates which should be compiled with `x86_64-unknown-none` target
none-build-%:
	${CARGO} +${STABLE_TOOLCHAIN} build --target x86_64-unknown-none -p $(patsubst none-build-%,%,$@) ${BUILD_TYPE_FLAG}

none-check-%:
	 ${CARGO} +${STABLE_TOOLCHAIN} check --target x86_64-unknown-none -p $(patsubst none-check-%,%,$@) ${BUILD_TYPE_FLAG}

none-clean-%:
	${CARGO} +${STABLE_TOOLCHAIN} clean --target x86_64-unknown-none -p $(patsubst none-clean-%,%,$@) ${BUILD_TYPE_FLAG}

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

tools-subdir-%:
	make -C $(patsubst tools-subdir-%,%,$@) all-tools

apply_patches:
	bash sh_script/preparation.sh

afl_test:
	bash sh_script/fuzzing.sh -n afl_all -t 10

libfuzzer_test:
	bash sh_script/fuzzing.sh -n libfuzzer_all -t 20
