include_directories(
	"${CMAKE_CURRENT_BINARY_DIR}"
	${PROJECT_SOURCE_DIR}/lib
	${PROJECT_SOURCE_DIR}/src
	)

SET(TEST_SOURCES
	test_shard.c
	)

add_executable(unit_test EXCLUDE_FROM_ALL ${TEST_SOURCES})
add_test(unit_test unit_test)
add_dependencies(check unit_test)

target_link_libraries(
	unit_test
	zcore
	pcap gmp m
	${DNET_LIBRARIES}
	${REDIS_LIBS}
	${JSON_LIBRARIES}
	)