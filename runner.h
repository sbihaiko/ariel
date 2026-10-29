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

#include <stdint.h>

#include "platform.h"
#include "sha256.h"

/** The most bytes of output one answer carries, the cut marker included
    (ADR-0012). A reader cuts past it. **/
#define OUTPUT_CAP (64UL * 1024)

/**
 * Run one command of the agent port: argv[0] is the command, argv[argc] is
 * NULL. Output goes to outfd and diagnostics to errfd. session names the
 * working directory the command runs in and receives the one a cd chose,
 * or is NULL for a connection with no working directory, where every path
 * is absolute and cd is an error. Returns 0 and the command's status in
 * status when the command is known, or -1 when it is not a runner command.
 * platform is the port a command that waits runs on, such as sleep.
 **/
int runner_run(platform_t *platform, int argc, char *const argv[], int outfd,
               int errfd, runner_session_t *session, int *status);

/**
 * Resolve one path against a session's directory: a relative path is joined
 * to it, an absolute one is normalised as it stands. The join is lexical,
 * so no symbolic link is followed, and a ".." that would leave the root
 * answers bad_path. With no session a relative path answers relative_path,
 * exactly as it always has. Returns 0 when out holds the path.
 **/
int runner_resolve(const runner_session_t *session, const char *path,
                   char *out, size_t size, int errfd);

/**
 * The part of the installed title at root/user/app/<title> that is missing:
 * package, sfo, appmeta or licence, the first finding its checks make. Returns
 * 1 with part set, or 0 when the title is whole.
 **/
int runner_title_missing(const char *root, const char *title, const char **part);

/**
 * The install part a verify finding names, given the text after "finding ".
 **/
const char *runner_title_part(const char *finding);

/**
 * The byte count of the regular file at path, and its SHA-256 read once. Returns
 * 0 with both set, 1 when path is not a regular file or cannot be read, and 2
 * with only the byte count set when it is over the verify ceiling, which is not
 * read.
 **/
int runner_package_fact(const char *path, uint64_t *bytes,
                        char hex[SHA256_HEX_LEN + 1]);

#endif /* ARIEL_RUNNER_H */
