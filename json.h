/* Ariel: JSON text for the --json output of the table commands.

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

#ifndef ARIEL_JSON_H
#define ARIEL_JSON_H

/**
 * Write text to fd as a JSON string, quotes included. A quote, a backslash
 * and a control byte are escaped; every other byte is written as it is.
 **/
void json_say_string(int fd, const char *text);

#endif /* ARIEL_JSON_H */
