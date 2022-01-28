build:
	cargo build ${BUILD_TYPE_FLAG} -p td-layout-config
	cargo build ${BUILD_TYPE_FLAG} -p test-runner-server

check:
	cargo check ${BUILD_TYPE_FLAG} -p td-layout-config
	cargo check ${BUILD_TYPE_FLAG} -p test-runner-server

clean:
	cargo clean ${BUILD_TYPE_FLAG} -p td-layout-config
	cargo clean ${BUILD_TYPE_FLAG} -p test-runner-server

install:
	mkdir -p ${TOPDIR}/devtools/bin
	install -m u+rx ${TOPDIR}/target/${BUILD_TYPE}/td-layout-config ${TOPDIR}/devtools/bin/td-layout-config
	install -m u+rx ${TOPDIR}/target/${BUILD_TYPE}/test-runner-server ${TOPDIR}/devtools/bin/test-runner-server

uninstall:
	rm ${TOPDIR}/devtools/bin/td-layout-config
	rm ${TOPDIR}/devtools/bin/test-runner-server

