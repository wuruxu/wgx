cmake_minimum_required(VERSION 3.22)
project(wgx_windows C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(WGX_ROOT "${CMAKE_CURRENT_LIST_DIR}/../..")

add_executable(wgx-win
    wgx_win_main.c
    tun_windows.c
    wintun_loader.c
    uapi_windows_stub.c
    "${WGX_ROOT}/src/blake2s.c"
    "${WGX_ROOT}/src/crypto.c"
    "${WGX_ROOT}/src/tai64n.c"
    "${WGX_ROOT}/src/replay.c"
    "${WGX_ROOT}/src/allowedips.c"
    "${WGX_ROOT}/src/noise.c"
    "${WGX_ROOT}/src/device.c"
    "${WGX_ROOT}/src/timers.c"
    "${WGX_ROOT}/src/conf.c"
)

target_compile_definitions(wgx-win PRIVATE
    _GNU_SOURCE
    WGX_WINDOWS
)

target_include_directories(wgx-win PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/compat"
    "${WGX_ROOT}/src"
    "${WGX_ROOT}/wintun/include"
    "${CMAKE_CURRENT_LIST_DIR}"
)

target_link_libraries(wgx-win PRIVATE
    uv
    sodium
    cares
    pthread
    ws2_32
    iphlpapi
    userenv
    ntdll
)
