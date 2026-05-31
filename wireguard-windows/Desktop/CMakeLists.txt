cmake_minimum_required(VERSION 3.22)
project(wgx_windows_desktop C CXX RC)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(WGX_UI_RESOURCE_DEPS
    "${CMAKE_CURRENT_SOURCE_DIR}/resource.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/wgx-ui.manifest"
    "${CMAKE_CURRENT_SOURCE_DIR}/wgx-app.ico"
    "${CMAKE_CURRENT_SOURCE_DIR}/systray-unlock.ico"
    "${CMAKE_CURRENT_SOURCE_DIR}/systray-lock.ico"
    "${CMAKE_CURRENT_SOURCE_DIR}/import-from-qr.ico"
    "${CMAKE_CURRENT_SOURCE_DIR}/menu-add.ico"
    "${CMAKE_CURRENT_SOURCE_DIR}/menu-edit.ico"
    "${CMAKE_CURRENT_SOURCE_DIR}/menu-exit.ico"
    "${CMAKE_CURRENT_SOURCE_DIR}/menu-remove.ico"
    "${CMAKE_CURRENT_SOURCE_DIR}/wg-off.ico"
    "${CMAKE_CURRENT_SOURCE_DIR}/wg-on.ico"
    "${CMAKE_CURRENT_SOURCE_DIR}/wg-connecting.ico"
)

add_executable(wgx-ui WIN32
    main.cpp
    resources.rc
    ../third_party/quirc/lib/quirc.c
    ../third_party/quirc/lib/identify.c
    ../third_party/quirc/lib/decode.c
    ../third_party/quirc/lib/version_db.c
)

set_source_files_properties(resources.rc PROPERTIES
    OBJECT_DEPENDS "${WGX_UI_RESOURCE_DEPS}"
)

target_compile_definitions(wgx-ui PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
)

target_include_directories(wgx-ui PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/../third_party/quirc/lib"
)

target_link_libraries(wgx-ui PRIVATE
    comctl32
    comdlg32
    shell32
    uxtheme
    user32
    gdi32
)

if(MINGW)
    target_link_libraries(wgx-ui PRIVATE m)
    target_link_options(wgx-ui PRIVATE -municode)
endif()
