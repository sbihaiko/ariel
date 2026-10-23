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

all: shsrv-ps5.elf sh.elf controller-spike.elf

# The agent protocol, the store and the token are shared with the host
# build, which compiles the same sources from hostbuild/.
ARIEL_OBJS := agent.o agent_server.o store.o token.o

shsrv.o: sh.elf.inc

shsrv-ps5.elf: shsrv.o platform_ps5.o $(ARIEL_OBJS) elfldr.o pt.o notify.o \
               sha256.o
	$(CC) -lkernel_sys -lScePad -lSceUserService -o $@ $^

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
controller-spike.elf: controller_spike.o notify.o
	$(CC) -lkernel_sys -lScePad -lSceUserService -o $@ $^

clean:
	rm -f *.o *.elf

test: shsrv-ps5.elf
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^

