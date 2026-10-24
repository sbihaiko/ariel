/* Ariel: the platform port for the PS5.

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#ifndef ARIEL_PLATFORM_PS5_H
#define ARIEL_PLATFORM_PS5_H

#include "platform.h"

/**
 * The PS5 implementation of the platform port. token is the agent access
 * token, shown with every approval prompt so the owner always has it at
 * hand. Approvals come from the owner's signature, checked against the key
 * pinned at build time. Returns the port; the platform lives as long as
 * the process.
 **/
platform_t *platform_ps5(const char *token);

/**
 * Take the ELF loader's lock around a spawn that does not go through the
 * port, such as the telnet shell's sh.elf, and release it as soon as the
 * child is loaded. The loader uses process-wide state, so every spawn is
 * serialized under this one mutex. A payload's wait is outside the lock.
 **/
void platform_ps5_loader_lock(void);
void platform_ps5_loader_unlock(void);

#endif /* ARIEL_PLATFORM_PS5_H */
