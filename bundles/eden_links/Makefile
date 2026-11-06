#   Copyright (C) 2026 Sandro Bihaiko
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 3, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not see <http://www.gnu.org/licenses/>.

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

# The payload reads the mount tables and makes one symlink: no SCE library.
CFLAGS := -Wall -Werror

all: eden_links.elf

eden_links.elf: eden_links.o
	$(CC) $(LDADD) -o $@ $^

clean:
	rm -f *.o *.elf

test:
