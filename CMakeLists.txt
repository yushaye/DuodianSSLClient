cmake_minimum_required(VERSION 3.10.2)
set(CMAKE_C_STANDARD 99)

option(CONF_ENABLE "Enable config file" ON)

project(duodian_openssl C)
set(SOURCE_FILES main.c)

if(WIN32)
    set(libs WS2_32 Util)
    include_directories(../../../../../OpenSSL/include)
    link_directories(../../../../../OpenSSL/lib)
    link_libraries(libssl libcrypto)
else(WIN32)
    set(libs Util)
    link_directories(lib)
    link_libraries(ssl crypto)
endif(WIN32)

if(CONF_ENABLE)
    CONFIGURE_FILE(file/duodian.conf duodian.conf)
endif()

add_subdirectory(util)
AUX_SOURCE_DIRECTORY(. DIR_SRCS)

add_executable(duodian_openssl ${SOURCE_FILES})
target_link_libraries(duodian_openssl ${libs})