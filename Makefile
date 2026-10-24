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
ARIEL_CONSOLE_ID ?= ps5
ARIEL_TEST_PUBKEY := 299e18435f88e321120e74f83f1b3f3f530ca0d51cad39f3ed45b86b8007f922

ifeq ($(ARIEL_PUBKEY),$(ARIEL_TEST_PUBKEY))
    $(error ARIEL_PUBKEY is the host test key; the PS5 build never pins it)
endif

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

CFLAGS := -Wall -Werror

SUBDIRS := bundles/core bundles/http2_get bundles/suspend \
           bundles/launch bundles/hbldr bundles/pkg_install

TOPTARGETS := all clean

$(TOPTARGETS): $(SUBDIRS)

$(SUBDIRS):
	make -j1 -C $@ $(MAKECMDGOALS)

.PHONY: $(TOPTARGETS) $(SUBDIRS)

.NOTPARALLEL:

all: shsrv-ps5.elf sh.elf controller-spike.elf primitives-probe.elf

# The agent protocol, the store and the token are shared with the host
# build, which compiles the same sources from hostbuild/.
ARIEL_OBJS := agent.o agent_server.o store.o state.o token.o approval.o runner.o \
              protected.o runs.o fileops.o tweetnacl.o

shsrv.o: sh.elf.inc

# TweetNaCl is vendored as published, so it is not held to -Wall -Werror.
tweetnacl.o: CFLAGS += -w

# The key and the console name are pinned into the platform and nowhere else.
platform_ps5.o: CFLAGS += -DARIEL_PUBKEY_HEX=\"$(ARIEL_PUBKEY)\" \
                          -DARIEL_CONSOLE_ID=\"$(ARIEL_CONSOLE_ID)\"

shsrv-ps5.elf: shsrv.o platform_ps5.o readers_ps5.o $(ARIEL_OBJS) elfldr.o \
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
# shsrv-ps5.elf; the operator sends it to elfldr on its own.
controller-spike.elf: controller_spike.o notify.o pt.o
	$(CC) -lkernel_sys -lScePad -lSceUserService -lSceSystemService \
	      -lSceRegMgr -o $@ $^

# The primitives probe is a separate payload. It is never linked into
# shsrv-ps5.elf; the operator sends it to elfldr on its own. ps5_at.h is a
# header, so the probe needs no extra object.
primitives-probe.elf: primitives_probe.o
	$(CC) -lkernel_sys -o $@ $^

clean:
	rm -f *.o *.elf

test: shsrv-ps5.elf
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^

