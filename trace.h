/* Ariel: the named record of the console's state.

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not see
<http://www.gnu.org/licenses/>.  */

#ifndef ARIEL_TRACE_H
#define ARIEL_TRACE_H

#include "platform.h"

/** Keep the named records in state_dir/trace. **/
void trace_init(const char *state_dir);

/**
 * trace NAME [--replace]: write the console's state under NAME, then answer
 * the record and exit 0. A name that exists answers trace_exists unless
 * --replace is given.
 **/
void trace_command(platform_t *platform, int fd, int argc, char *argv[]);

#endif /* ARIEL_TRACE_H */
