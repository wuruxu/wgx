# SPDX-License-Identifier: MIT
# Makefile for wireguard-c

CC      := gcc
TARGET  := wgx
SRCDIR  := src
OBJDIR  := build

SRCS := \
	$(SRCDIR)/main.c        \
	$(SRCDIR)/blake2s.c     \
	$(SRCDIR)/crypto.c      \
	$(SRCDIR)/tai64n.c      \
	$(SRCDIR)/replay.c      \
	$(SRCDIR)/allowedips.c  \
	$(SRCDIR)/noise.c       \
	$(SRCDIR)/tun.c         \
	$(SRCDIR)/device.c      \
	$(SRCDIR)/timers.c      \
	$(SRCDIR)/uapi.c        \
	$(SRCDIR)/tcpstack.c    \
	$(SRCDIR)/socks5.c      \
	$(SRCDIR)/conf.c

OBJS := $(SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

CFLAGS := \
	-std=c11 \
	-Wall \
	-Wextra \
	-Wpedantic \
	-Wshadow \
	-Wstrict-prototypes \
	-O2 \
	-g \
	-D_GNU_SOURCE \
	-I$(SRCDIR)

LDFLAGS := \
	-luv \
	-lpthread \
	-lssl \
	-lcrypto \
	-ldl \
	-lrt \
	-lm

.PHONY: all clean

all: $(OBJDIR) $(TARGET)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)
	@echo "Built: $@"

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(TARGET)

install: $(TARGET)
	install -m 0755 $(TARGET) /usr/bin/

.PHONY: fmt
fmt:
	clang-format -i $(SRCDIR)/*.c $(SRCDIR)/*.h
