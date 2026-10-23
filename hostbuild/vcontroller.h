/* Ariel host build: the virtual controller, a host-only test aid.

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

#ifndef ARIEL_VCONTROLLER_H
#define ARIEL_VCONTROLLER_H

#include <stddef.h>

#include "platform.h"

/**
 * The virtual controller is the host build's approval source. It stands in
 * for the owner's controller and exists only in the host build, so no
 * payload sent to a console can approve itself.
 *
 * It reports each pending prompt on standard output, one line:
 *
 *   prompt <approval-id> <the text the owner would see>
 *
 * It is driven by lines on standard input:
 *
 *   approve <approval-id>   answers approved <approval-id>
 *   deny <approval-id>      answers denied <approval-id>
 **/

/** Start the controller's input reader. Safe to call more than once. **/
void vcontroller_start(void);

/** Request approval; see platform_t.approval_request. **/
int vcontroller_request(const approval_facts_t *facts, char *id, size_t idlen);

#endif /* ARIEL_VCONTROLLER_H */
