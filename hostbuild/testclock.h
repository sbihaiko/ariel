/* Ariel host build: the test clock, a host-only test aid.

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

#ifndef ARIEL_TESTCLOCK_H
#define ARIEL_TESTCLOCK_H

/*
 * The test clock exists only in the host build. A PS5 build never defines
 * ARIEL_HOST_BUILD, so it cannot compile this file in: the virtual
 * controller and a clock the network can move have no place on a console.
 */
#ifndef ARIEL_HOST_BUILD
#error "the test clock is host-only"
#endif

#include <stddef.h>
#include <time.h>

/**
 * Start the test clock at zero and clear the wake pipes. Safe to call more
 * than once.
 **/
void testclock_init(void);

/** Read the test clock. Time moves only when testclock_advance runs. **/
void testclock_now(struct timespec *now);

/**
 * Advance the test clock by ms and write every wake pipe, so each wait that
 * polls one recomputes its deadline. A scenario moves time with this and
 * never sleeps.
 **/
void testclock_advance(long ms);

/**
 * Create the wake pipe of one connection and return its read end, or -1 on
 * error. The clock holds the write end until testclock_wake_close.
 **/
int testclock_wake_new(void);

/** Close a wake pipe made by testclock_wake_new. **/
void testclock_wake_close(int fd);

/**
 * Mark the waiter of wake pipe wake idle or busy. An idle mark holds only
 * when neither the pipe nor fd (when fd >= 0) has anything to read: the
 * waiter has seen the latest advance and has nothing to do until the next
 * one. An advance clears every mark.
 **/
void testclock_wake_idle(int wake, int fd, int idle);

/**
 * Wait until the test clock has moved ms past where it is now. Only an
 * advance ends it, so a builtin that sleeps blocks on the clock a scenario
 * moves instead of on real time. It is a cancellation point: the connection
 * deadline cancels a thread that is asleep. ms <= 0 returns at once.
 **/
void testclock_sleep_ms(long ms);

/**
 * Handle one line of the host build's control input and write the line to
 * answer into reply. Returns 1 for a clock line and 0 for any other line.
 * "clock advance <ms>" answers "clock <now>". "clock settle <n>" waits until
 * exactly n wake pipes exist and every waiter is idle, then answers
 * "settled <n>"; a waiter that does not settle soon answers
 * "unsettled <pipes> <idle>".
 **/
int testclock_handle_line(const char *line, char *reply, size_t size);

#endif /* ARIEL_TESTCLOCK_H */
