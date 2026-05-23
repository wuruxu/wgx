# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.22.1)
project("wgx-android")

set(WGX_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../..")
set(WGX_SRC "${WGX_ROOT}/src")
set(THIRD_PARTY "${CMAKE_CURRENT_SOURCE_DIR}/third_party")

add_link_options(LINKER:--build-id=none)

set(LIBUV_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(LIBUV_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(LIBUV_BUILD_BENCH OFF CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
add_subdirectory("${THIRD_PARTY}/libuv" "${CMAKE_CURRENT_BINARY_DIR}/libuv")
add_subdirectory("${THIRD_PARTY}/libsodium" "${CMAKE_CURRENT_BINARY_DIR}/libsodium")

add_library(wgx SHARED
        wgx_jni.c
        ${WGX_SRC}/allowedips.c
        ${WGX_SRC}/blake2s.c
        ${WGX_SRC}/crypto.c
        ${WGX_SRC}/device.c
        ${WGX_SRC}/noise.c
        ${WGX_SRC}/replay.c
        ${WGX_SRC}/tai64n.c
        ${WGX_SRC}/timers.c
        ${WGX_SRC}/tun.c
        ${WGX_SRC}/uapi.c)

target_include_directories(wgx PRIVATE ${WGX_SRC})
target_compile_definitions(wgx PRIVATE _GNU_SOURCE WGX_ANDROID)
target_compile_options(wgx PRIVATE -Wall -Werror -std=c11)
target_link_libraries(wgx PRIVATE uv_a sodium log)
