/* Ariel: the readers that need the platform.

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

#ifndef ARIEL_READERS_H
#define ARIEL_READERS_H

/**
 * Run one platform reader of the agent port: ps, procstat, sysctl, authid,
 * dmesg, sysinfo, ifconfig and ping. The arguments are as for runner_run, and json
 * is 1 for the --json form, which ps, sysinfo and ifconfig answer. Returns 0
 * and the reader's status when argv[0]
 * is a reader, or -1 when it is not one, or when the arguments ask for
 * something a reader does not do, such as a sysctl write.
 **/
int readers_run(int json, int argc, char *const argv[], int outfd, int errfd,
                int *status);

#endif /* ARIEL_READERS_H */
