build:
	cargo build ${BUILD_TYPE_FLAG} -p td-layout-config

check:
	cargo check ${BUILD_TYPE_FLAG} -p td-layout-config

clean:
	cargo clean ${BUILD_TYPE_FLAG} -p td-layout-config

install:
	mkdir -p ${TOPDIR}/devtools/bin
	install -m u+rx ${TOPDIR}/target/${BUILD_TYPE}/td-layout-config ${TOPDIR}/devtools/bin/td-layout-config

uninstall:
	rm ${TOPDIR}/devtools/bin/td-layout-config

