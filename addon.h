/* Ariel: the addon directory and the refusal of an addon by name.

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

#ifndef ARIEL_ADDON_H
#define ARIEL_ADDON_H

/** Set the state directory whose addons directory the checks read. **/
void addon_init(const char *state_dir);

/** Answer `addon check <name>`: the verdict on one addon, asked of nobody. **/
void addon_check(int fd, const char *name);

/** Answer `addon list`: one verdict line per addon, then exit 0. **/
void addon_list(int fd);

#endif /* ARIEL_ADDON_H */
