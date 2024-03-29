project (xtest C)

include(${OPTEE_TEST_SDK}/host_include/conf.cmake)

################################################################################
# Packages
################################################################################
find_package(Threads REQUIRED)
if(NOT THREADS_FOUND)
	message(FATAL_ERROR "Threads not found")
endif()

find_package(OpenSSL)
if(OPENSSL_FOUND)
	add_compile_options(-DOPENSSL_FOUND=1)
	set (OPENSSL_PRIVATE_LINK crypto)
endif()

include(GNUInstallDirs)

macro(EMBED_8100FILE prefix infile)
	add_custom_command(
		OUTPUT  regression_8100_${prefix}.h
		COMMAND ../../scripts/file_to_c.py --inf ${infile}
	--out ${CMAKE_CURRENT_BINARY_DIR}/regression_8100_${prefix}.h
	--name regression_8100_${prefix}
		DEPENDS ../../scripts/file_to_c.py ${infile}
	)

	set_property(SOURCE regression_8100.c APPEND PROPERTY OBJECT_DEPENDS
		     ${CMAKE_CURRENT_BINARY_DIR}/regression_8100_${prefix}.h)
endmacro(EMBED_8100FILE)

EMBED_8100FILE(ca_crt ../../cert/ca.crt)
EMBED_8100FILE(mid_crt ../../cert/mid.crt)
EMBED_8100FILE(my_crt ../../cert/my.crt)
EMBED_8100FILE(my_csr ../../cert/my.csr)

set (SRC
	adbg/src/adbg_case.c
	adbg/src/adbg_enum.c
	adbg/src/adbg_expect.c
	adbg/src/adbg_log.c
	adbg/src/adbg_run.c
	adbg/src/security_utils_hex.c
	aes_perf.c
	benchmark_1000.c
	benchmark_2000.c
	regression_1000.c
	regression_4000.c
	regression_5000.c
	regression_6000.c
	regression_7000.c
	regression_8000.c
	regression_8100.c
	sha_perf.c
	xtest_helpers.c
	xtest_main.c
	xtest_test.c
	regression_nxp.c
)

if (CFG_GP_SOCKETS)
	list (APPEND SRC
		regression_2000.c
		sock_server.c
		rand_stream.c
	)
endif()

if (CFG_SECSTOR_TA_MGMT_PTA)
	list (APPEND SRC install_ta.c)
endif()

if (CFG_SECURE_DATA_PATH)
	list (APPEND SRC sdp_basic.c)
endif()

################################################################################
# Built binary
################################################################################
add_executable (${PROJECT_NAME} ${SRC})

target_compile_options (${PROJECT_NAME} PRIVATE -include conf.h)

target_include_directories(${PROJECT_NAME}
	PRIVATE .
	PRIVATE adbg/include
	PRIVATE xml/include
	PRIVATE ${OPTEE_TEST_SDK}/host_include
)

target_link_libraries (${PROJECT_NAME}
	PRIVATE ${CMAKE_THREAD_LIBS_INIT}
	PRIVATE xtest-ta-headers
	PRIVATE teec
	PRIVATE m
	PRIVATE ${OPENSSL_PRIVATE_LINK}
)

################################################################################
# Install targets
################################################################################
install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
