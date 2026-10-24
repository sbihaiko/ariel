/* Ariel: one bounded answer of the agent port.

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

#ifndef ARIEL_ANSWER_H
#define ARIEL_ANSWER_H

#include <stddef.h>

#include "runner.h"

/** The room kept under the output cap for the cut marker and the exit line. **/
#define MARKER_RESERVE 64

/** The most bytes of content one answer carries, the marker left out. **/
#define CONTENT_CAP (OUTPUT_CAP - MARKER_RESERVE)

/**
 * The lines or objects one bounded answer shows. A line that does not fit
 * ends the content but not the walk: the total keeps counting, so a cut
 * answer can say how much it left out. `limit` is the caller's own bound,
 * and a directory walk passes SIZE_MAX.
 **/
typedef struct {
  int fd;
  size_t limit;
  size_t shown;
  size_t total;
  size_t bytes;
  int full;
} answer_t;

/** Write the cut marker `truncated <shown> of <total>`. **/
void say_cut(int fd, size_t shown, size_t total);

void answer_init(answer_t *answer, int fd, size_t limit);

/** Admit one line of len bytes; 0 when the answer is already full or the
    line does not fit, 1 when the caller should write it. **/
int answer_admit(answer_t *answer, size_t len);

void answer_line(answer_t *answer, const char *text, size_t len);

/** One JSON object of one string member, budgeted by its encoded length. **/
void answer_json(answer_t *answer, const char *key, const char *value);

/** A path as a plain line or a `{"path":...}` object. **/
void answer_path(answer_t *answer, int json, const char *path);

/** End the answer, writing the cut marker when it left something out. **/
void answer_done(answer_t *answer);

#endif /* ARIEL_ANSWER_H */
