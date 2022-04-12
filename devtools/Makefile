build:
	${CARGO} +${STABLE_TOOLCHAIN} build ${BUILD_TYPE_FLAG} -p td-layout-config
	${CARGO} +${NIGHTLY_TOOLCHAIN} build ${BUILD_TYPE_FLAG} -p td-benchmark
	${CARGO} +${NIGHTLY_TOOLCHAIN} build ${BUILD_TYPE_FLAG} -p test-runner-client
	${CARGO} +${STABLE_TOOLCHAIN} build ${BUILD_TYPE_FLAG} -p test-runner-server

check:
	${CARGO} +${STABLE_TOOLCHAIN} check ${BUILD_TYPE_FLAG} -p td-layout-config
	${CARGO} +${NIGHTLY_TOOLCHAIN} check ${BUILD_TYPE_FLAG} -p td-benchmark
	${CARGO} +${NIGHTLY_TOOLCHAIN} check ${BUILD_TYPE_FLAG} -p test-runner-client
	${CARGO} +${STABLE_TOOLCHAIN} check ${BUILD_TYPE_FLAG} -p test-runner-server

clean:
	${CARGO} +${STABLE_TOOLCHAIN} clean ${BUILD_TYPE_FLAG} -p td-layout-config
	${CARGO} +${NIGHTLY_TOOLCHAIN} clean ${BUILD_TYPE_FLAG} -p td-benchmark
	${CARGO} +${NIGHTLY_TOOLCHAIN} clean ${BUILD_TYPE_FLAG} -p test-runner-client
	${CARGO} +${STABLE_TOOLCHAIN} clean ${BUILD_TYPE_FLAG} -p test-runner-server

install:
	mkdir -p ${TOPDIR}/devtools/bin
	install -m u+rx ${TOPDIR}/target/${BUILD_TYPE}/td-layout-config ${TOPDIR}/devtools/bin/td-layout-config
	install -m u+rx ${TOPDIR}/target/${BUILD_TYPE}/test-runner-server ${TOPDIR}/devtools/bin/test-runner-server

uninstall:
	rm ${TOPDIR}/devtools/bin/td-layout-config
	rm ${TOPDIR}/devtools/bin/test-runner-server

tools-init:
	docker build -t tools dev_container

fuzz_test_afl: tools-init
	docker run -t --rm -v ${TOPDIR}:/td-shim -w /td-shim tools bash sh_script/fuzzing.sh afl

fuzz_test_libfuzzer: tools-init
	docker run -t --rm -v ${TOPDIR}:/td-shim -w /td-shim tools bash sh_script/fuzzing.sh

static_analyzer_rudra: tools-init
	mkdir -p ${TOPDIR}/target/report
	docker run -t --rm \
		--env RUDRA_REPORT_PATH=/td-shim/target/report/report \
		--env SCCACHE_DIR=/td-shim/target/sccache_home \
		--env SCCACHE_CACHE_SIZE=10T \
		-v ${TOPDIR}:/td-shim \
		-v ${TOPDIR}/target/report:/td-shim/target/report  \
		-w /td-shim tools bash sh_script/rudra.sh

all-tools: tools-init fuzz_test_afl fuzz_test_libfuzzer static_analyzer_rudra
