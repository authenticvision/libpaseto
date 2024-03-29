cmake_minimum_required(VERSION 3.10)
project(libpaseto
	VERSION 1.0
	LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_EXTENSIONS OFF)
add_compile_options(-Wall -Wextra -Wno-unused-parameter -Wno-unused-result -Werror)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)
include_directories(${SODIUM_INCLUDE_DIRS})

include_directories(include)
set(PASETO_SOURCES
	src/paseto_v2_local.c
	src/paseto_v2_public.c
	src/paseto.c
	src/helpers.c
	src/helpers.h
	include/paseto.h)

configure_file("paseto.pc.in" "paseto.pc" @ONLY)


# shared library build
add_library(paseto SHARED ${PASETO_SOURCES})
target_link_libraries(paseto ${SODIUM_LIBRARIES})
install(TARGETS paseto
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib)
install(FILES include/paseto.h
	DESTINATION include)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/paseto.pc"
	DESTINATION lib/pkgconfig)

# test executable
add_executable(pasetotest
	test/main.c
	test/helpers.h
	test/helpers.c
	test/test.h
	test/test.c
	test/v2vectors.h
	test/v2vectors.c
	test/v2publicvectors.c)
target_compile_definitions(pasetotest PRIVATE _POSIX_C_SOURCE=200809L)
target_link_libraries(pasetotest ${SODIUM_LIBRARIES} paseto)

# examples
set(EXAMPLES example_v2_local example_v2_public gen-keys paseto-v2-local-encrypt paseto-v2-local-decrypt)
foreach(EXAMPLE ${EXAMPLES})
	add_executable(${EXAMPLE} examples/${EXAMPLE}.c)
	target_link_libraries(${EXAMPLE} ${SODIUM_LIBRARIES} paseto)
endforeach()
