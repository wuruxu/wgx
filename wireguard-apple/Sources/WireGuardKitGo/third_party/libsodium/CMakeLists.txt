# SPDX-License-Identifier: ISC

cmake_minimum_required(VERSION 3.10)
project(sodium C)

add_library(sodium STATIC
        crypto_aead/chacha20poly1305/aead_chacha20poly1305.c
        crypto_aead/xchacha20poly1305/aead_xchacha20poly1305.c
        crypto_core/ed25519/ref10/ed25519_ref10.c
        crypto_core/hchacha20/core_hchacha20.c
        crypto_onetimeauth/poly1305/onetimeauth_poly1305.c
        crypto_onetimeauth/poly1305/donna/poly1305_donna.c
        crypto_scalarmult/curve25519/ref10/x25519_ref10.c
        crypto_scalarmult/curve25519/scalarmult_curve25519.c
        crypto_stream/chacha20/ref/chacha20_ref.c
        crypto_stream/chacha20/stream_chacha20.c
        crypto_verify/verify.c
        randombytes/randombytes.c
        randombytes/sysrandom/randombytes_sysrandom.c
        sodium/utils.c
        sodium_minimal.c)

target_include_directories(sodium PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/include/sodium)

target_compile_definitions(sodium PRIVATE
        CONFIGURED=1
        NATIVE_LITTLE_ENDIAN
        SODIUM_STATIC
        HAVE_ATOMIC_OPS)

target_compile_options(sodium PRIVATE
        -std=c11
        -Wno-unused-parameter
        -Wno-unused-function)
