#   Copyright (C) 2024 John Törnblom
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not see
# <http://www.gnu.org/licenses/>.

PS5_HOST ?= ps5
PS5_PORT ?= 9021

# The owner's public key and this console's name, pinned into the build.
# The host build's test key, whose private half is in the repository, must
# never be pinned: this stops the build before the SDK is even read.
ARIEL_PUBKEY ?=
ARIEL_RECOVERY_PUBKEY ?=
ARIEL_CONSOLE_ID ?= ps5
ARIEL_TEST_PUBKEY := 299e18435f88e321120e74f83f1b3f3f530ca0d51cad39f3ed45b86b8007f922

ifeq ($(ARIEL_PUBKEY),$(ARIEL_TEST_PUBKEY))
    $(error ARIEL_PUBKEY is the host test key; the PS5 build never pins it)
endif

ifeq ($(ARIEL_RECOVERY_PUBKEY),$(ARIEL_TEST_PUBKEY))
    $(error ARIEL_RECOVERY_PUBKEY is the host test key; the PS5 build never pins it)
endif

ifneq ($(ARIEL_PUBKEY),)
ifeq ($(ARIEL_RECOVERY_PUBKEY),)
    $(error ARIEL_PUBKEY is set but ARIEL_RECOVERY_PUBKEY is empty; the anchor needs both keys)
endif
endif

ifneq ($(ARIEL_RECOVERY_PUBKEY),)
ifeq ($(ARIEL_RECOVERY_PUBKEY),$(ARIEL_PUBKEY))
    $(error ARIEL_RECOVERY_PUBKEY must differ from ARIEL_PUBKEY)
endif
endif

# `make test` sends ariel-ps5.elf to a console. It runs only when the owner
# asks for it by name, and refuses before the SDK is read or anything is built.
ifneq ($(filter test,$(MAKECMDGOALS)),)
ifneq ($(ARIEL_DEPLOY),yes)
    $(error make test sends ariel-ps5.elf to the console at $(PS5_HOST); run it with ARIEL_DEPLOY=yes to deploy on purpose)
endif
endif

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

CFLAGS := -Wall -Werror -O2

SUBDIRS := bundles/core bundles/http2_get bundles/suspend \
           bundles/launch bundles/hbldr bundles/pkg_install

TOPTARGETS := all clean

$(TOPTARGETS): $(SUBDIRS)

$(SUBDIRS):
	make -j1 -C $@ $(MAKECMDGOALS)

.PHONY: $(TOPTARGETS) $(SUBDIRS)

.NOTPARALLEL:

all: ariel-ps5.elf sh.elf controller-spike.elf primitives-probe.elf network-spike.elf

# The agent protocol, the store and the token are shared with the host
# build, which compiles the same sources from hostbuild/.
ARIEL_OBJS := agent.o agent_server.o store.o state.o token.o approval.o runner.o answer.o diagnostics.o json.o addon.o \
              http.o allowlist.o release.o \
              protected.o runs.o fileops.o zip.o tar.o tweetnacl.o autoload.o

shsrv.o: sh.elf.inc

# TweetNaCl is vendored as published, so it is not held to -Wall -Werror.
tweetnacl.o: CFLAGS += -w

# The key and the console name are pinned into the platform and nowhere else.
platform_ps5.o: CFLAGS += -DARIEL_PUBKEY_HEX=\"$(ARIEL_PUBKEY)\" \
                          -DARIEL_RECOVERY_PUBKEY_HEX=\"$(ARIEL_RECOVERY_PUBKEY)\" \
                          -DARIEL_CONSOLE_ID=\"$(ARIEL_CONSOLE_ID)\"

ariel-ps5.elf: shsrv.o platform_ps5.o readers_ps5.o $(ARIEL_OBJS) elfldr.o \
               pt.o notify.o sha256.o
	$(CC) -lkernel_sys -o $@ $^

sh.elf: sh.o builtin.o elfldr.o pt.o libtelnet.o
	$(CC) -lkernel_sys -o $@ $^ \
	      -Wl,--whole-archive bundles/core/lib.a \
	      -Wl,--whole-archive bundles/http2_get/lib.a \
	      -Wl,--whole-archive bundles/launch/lib.a \
	      -Wl,--whole-archive bundles/suspend/lib.a \
	      -Wl,--whole-archive bundles/hbldr/lib.a \
	      -Wl,--whole-archive bundles/pkg_install/lib.a

sh.elf.inc: sh.elf
	xxd -i $^ > $@

# The controller spike is a separate payload. It is never linked into
# ariel-ps5.elf; the operator sends it to elfldr on its own.
controller-spike.elf: controller_spike.o notify.o pt.o
	$(CC) -lkernel_sys -lScePad -lSceUserService -lSceSystemService \
	      -lSceRegMgr -o $@ $^

# The capture spike is a separate payload, answering issue #55. It is never
# linked into ariel-ps5.elf; the operator sends it to elfldr on its own.
capture-spike.elf: capture_spike.o notify.o
	$(CC) -lkernel_sys -o $@ $^

# The share spike is a separate payload, answering issue #100. It is never
# linked into ariel-ps5.elf; the operator sends it to elfldr on its own.
share-spike.elf: share_spike.o notify.o
	$(CC) -lkernel_sys -o $@ $^

# The network spike is a separate payload, answering issue #112. It is never
# linked into ariel-ps5.elf; the operator sends it to elfldr on its own.
network-spike.elf: network_spike.o notify.o
	$(CC) -lkernel_sys -o $@ $^

# The primitives probe is a separate payload. It is never linked into
# ariel-ps5.elf; the operator sends it to elfldr on its own. ps5_at.h is a
# header, so the probe needs no extra object.
primitives-probe.elf: primitives_probe.o
	$(CC) -lkernel_sys -o $@ $^

# The reference addon is the example docs/addons.md describes. It is built on
# request and never part of all; the owner installs it on the console out of
# band (ADR-0010).
addon-sight: addons/sight/sight.elf

addons/sight/sight.elf: addons/sight/sight.c
	$(CC) $(CFLAGS) -o $@ $<

# The ftp addon moves files through the console's ftpsrv. It is one program,
# built once and installed under four names, and it shares the payload's
# protected-path checks, so it links protected.c. Built on request and never
# part of all, the same as the reference addon.
addon-ftp: addons/ftp/ftp.elf

addons/ftp/ftp.elf: addons/ftp/ftp.c protected.c protected.h
	$(CC) $(CFLAGS) -Wextra -O2 -I. -o $@ addons/ftp/ftp.c protected.c

.PHONY: addon-sight addon-ftp

clean:
	rm -f *.o *.elf addons/sight/*.elf addons/ftp/*.elf

test: ariel-ps5.elf
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^

