# SPDX-License-Identifier: MIT
#
# Build the wgx C backend behind the existing WireGuardKitGo ABI.
# The output keeps the historical libwg-go.a name so the Xcode project does
# not need to change its framework references.

ARCHS ?= x86_64 arm64
PLATFORM_NAME ?= macosx
SDKROOT ?= $(shell xcrun --sdk $(PLATFORM_NAME) --show-sdk-path)
CONFIGURATION_BUILD_DIR ?= $(CURDIR)/out
CONFIGURATION_TEMP_DIR ?= $(CURDIR)/.tmp

export CC ?= clang
AR ?= ar
RANLIB ?= ranlib
LIPO ?= lipo
LIBTOOL ?= libtool
DESTDIR ?= $(CONFIGURATION_BUILD_DIR)
BUILDDIR ?= $(CONFIGURATION_TEMP_DIR)/wgx-apple

WGX_DIR := $(CURDIR)/wgx
APPLE_DIR := $(CURDIR)/wgx_apple
THIRD_PARTY := $(CURDIR)/third_party

WGX_SRCS := \
	$(WGX_DIR)/allowedips.c \
	$(WGX_DIR)/blake2s.c \
	$(WGX_DIR)/crypto.c \
	$(WGX_DIR)/device.c \
	$(WGX_DIR)/noise.c \
	$(WGX_DIR)/replay.c \
	$(WGX_DIR)/tai64n.c \
	$(WGX_DIR)/timers.c \
	$(WGX_DIR)/uapi.c \
	$(APPLE_DIR)/api-wgx-apple.c \
	$(APPLE_DIR)/tun_apple.c

CFLAGS_COMMON := \
	-isysroot $(SDKROOT) \
	-fembed-bitcode-marker \
	-std=c11 \
	-D_GNU_SOURCE \
	-DWGX_ANDROID \
	-DWGX_APPLE_BACKEND \
	-include $(APPLE_DIR)/apple_compat.h \
	-I$(WGX_DIR) \
	-I$(APPLE_DIR) \
	-I$(THIRD_PARTY)/libuv/include \
	-I$(THIRD_PARTY)/libsodium/include \
	-I$(THIRD_PARTY)/libsodium/include/sodium \
	-Wall \
	-Wno-unused-function \
	-Wno-unused-parameter

ifeq ($(PLATFORM_NAME),iphoneos)
CMAKE_SYSTEM_NAME := iOS
else
CMAKE_SYSTEM_NAME := Darwin
endif

build: $(DESTDIR)/libwg-go.a
version-header: $(DESTDIR)/wireguard-go-version.h

define build-arch
$(BUILDDIR)/$(1)/libuv/libuv.a:
	cmake -S "$(THIRD_PARTY)/libuv" -B "$(BUILDDIR)/$(1)/libuv" \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_SYSTEM_NAME=$(CMAKE_SYSTEM_NAME) \
		-DCMAKE_OSX_SYSROOT="$(SDKROOT)" \
		-DCMAKE_OSX_ARCHITECTURES="$(1)" \
		-DLIBUV_BUILD_SHARED=OFF \
		-DLIBUV_BUILD_TESTS=OFF \
		-DLIBUV_BUILD_BENCH=OFF \
		-DBUILD_TESTING=OFF
	cmake --build "$(BUILDDIR)/$(1)/libuv" --config Release

$(BUILDDIR)/$(1)/libsodium/libsodium.a:
	cmake -S "$(THIRD_PARTY)/libsodium" -B "$(BUILDDIR)/$(1)/libsodium" \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_SYSTEM_NAME=$(CMAKE_SYSTEM_NAME) \
		-DCMAKE_OSX_SYSROOT="$(SDKROOT)" \
		-DCMAKE_OSX_ARCHITECTURES="$(1)"
	cmake --build "$(BUILDDIR)/$(1)/libsodium" --config Release

$(BUILDDIR)/$(1)/libwg-go.a: $$(WGX_SRCS) $(BUILDDIR)/$(1)/libuv/libuv.a $(BUILDDIR)/$(1)/libsodium/libsodium.a
	mkdir -p "$(BUILDDIR)/$(1)/obj"
	set -e; for src in $$(WGX_SRCS); do \
		base=`basename "$$$$src" .c`; \
		obj="$(BUILDDIR)/$(1)/obj/$$$$base.o"; \
		$$(CC) $$(CFLAGS_COMMON) -arch $(1) -c "$$$$src" -o "$$$$obj"; \
	done
	$(LIBTOOL) -static -o "$$@" "$(BUILDDIR)/$(1)"/obj/*.o "$(BUILDDIR)/$(1)/libuv/libuv.a" "$(BUILDDIR)/$(1)/libsodium/libsodium.a"
endef
$(foreach ARCH,$(ARCHS),$(eval $(call build-arch,$(ARCH))))

$(DESTDIR)/libwg-go.a: $(foreach ARCH,$(ARCHS),$(BUILDDIR)/$(ARCH)/libwg-go.a)
	@mkdir -p "$(DESTDIR)"
	$(LIPO) -create -output "$@" $^

$(DESTDIR)/wireguard-go-version.h:
	@mkdir -p "$(DESTDIR)"
	printf '%s\n' '#define WIREGUARD_GO_VERSION "260527"' > "$@"

clean:
	rm -rf "$(BUILDDIR)" "$(DESTDIR)/libwg-go.a" "$(DESTDIR)/wireguard-go-version.h"

install: build

.PHONY: clean build version-header install
