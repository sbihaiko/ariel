/* Ariel: the noninteractive command runner.

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

#ifndef ARIEL_RUNNER_H
#define ARIEL_RUNNER_H

// The most bytes one answer holds, the cut marker included (ADR-0012).
#define OUTPUT_CAP (64 * 1024)

/**
 * Run one command of the agent port: argv[0] is the command, argv[argc] is
 * NULL. Output goes to outfd and diagnostics to errfd. A connection has no
 * working directory, so every path is absolute and cd is an error. Returns
 * 0 and the command's status in status when the command is known, or -1
 * when it is not a runner command.
 **/
int runner_run(int argc, char *const argv[], int outfd, int errfd,
               int *status);

#endif /* ARIEL_RUNNER_H */
