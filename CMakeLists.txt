cmake_minimum_required(VERSION 3.10)
project(libpaseto C)

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

# shared library build
add_library(paseto SHARED ${PASETO_SOURCES})
target_link_libraries(paseto ${SODIUM_LIBRARIES})

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

# example executable
add_executable(example example.c)
target_link_libraries(example ${SODIUM_LIBRARIES} paseto)
