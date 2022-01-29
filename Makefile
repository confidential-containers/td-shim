export CARGO=cargo
export BUILD_TYPE:=debug

export TOPDIR=$(shell pwd)
ifeq (${BUILD_TYPE},release)
	export BUILD_TYPE_FLAG= --release
else
	export BUILD_TYPE_FLAG=
endif

CORE_CRATES = td-layout td-paging
TEST_CRATES = test-td-paging

# Global targets
all: devtools build test

build: $(CORE_CRATES:%=build-%) $(TEST_CRATES:%=build-%)

check: $(CORE_CRATES:%=check-%) $(TEST_CRATES:%=check-%)

clean: $(CORE_CRATES:%=clean-%) $(TEST_CRATES:%=clean-%)

test: $(CORE_CRATES:%=test-%)

full-test: $(CORE_CRATES:%=test-%) $(TEST_CRATES:%=test-%)

install:

uninstall:

# Devtools targets
build-devtools: build-subdir-devtools

install-devtools: build-devtools install-subdir-devtools

uninstall-devtools: uninstall-subdir-devtools

# Subdir targets
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

# Crate targets
build-%:
	cargo build -p $(patsubst build-%,%,$@) ${BUILD_TYPE_FLAG}

check-%:
	cargo check -p $(patsubst check-%,%,$@) ${BUILD_TYPE_FLAG}

clean-%:
	cargo clean -p $(patsubst clean-%,%,$@) ${BUILD_TYPE_FLAG}

test-%:
	cargo test -p $(patsubst test-%,%,$@) ${BUILD_TYPE_FLAG}
