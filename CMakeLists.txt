cmake_minimum_required(VERSION 3.20)
project(mcs C)

set(CMAKE_C_STANDARD 99)

FIND_PATH(LIBSODIUM_INCLUDE_DIR NAMES sodium.h PATHS /usr/include/ /usr/local/include/)
FIND_LIBRARY(LIBSODIUM_LIBRARY NAMES sodium libsodium.a PATHS /usr/lib /usr/local/lib)
IF (LIBSODIUM_INCLUDE_DIR AND LIBSODIUM_LIBRARY)
    SET(LIBSODIUM_FOUND TRUE)
ENDIF (LIBSODIUM_INCLUDE_DIR AND LIBSODIUM_LIBRARY)

IF (LIBSODIUM_FOUND)
    IF (NOT LIBSODIUM_FIND_QUIETLY)
        MESSAGE(STATUS "Found libsodium:")
        MESSAGE(STATUS "  (Headers)       ${LIBSODIUM_INCLUDE_DIR}")
        MESSAGE(STATUS "  (Library)       ${LIBSODIUM_LIBRARY}")
    ENDIF (NOT LIBSODIUM_FIND_QUIETLY)
ELSE (LIBSODIUM_FOUND)
    MESSAGE(FATAL_ERROR "Could not find libsodium")
ENDIF (LIBSODIUM_FOUND)

include_directories("/opt/homebrew/include")
include_directories("/Users/halis/GitHub/Msc/inc")
include_directories("/opt/homebrew/opt/openssl@1.1/include")
include_directories("/opt/homebrew/opt/openssl/include")

add_executable(mcs main.c
        src/file.c inc/file.h
        src/lamport.c inc/lamport.h)

target_link_libraries(mcs ${LIBSODIUM_LIBRARY})