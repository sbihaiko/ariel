/* Ariel: the controller input the approval source reads.

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

#ifndef ARIEL_PAD_H
#define ARIEL_PAD_H

#include <stddef.h>
#include <stdint.h>

/** The standard controller. **/
#define PAD_PORT_TYPE_STANDARD 0
#define PAD_PORT_TYPE_SPECIAL  2
#define PAD_PORT_TYPE_COUNT    3
#define PAD_LOGIN_USERS        4
#define PAD_USER_INVALID       (-1)

/** The system consumed this input before it reached the pad reader. **/
#define PAD_BUTTON_INTERCEPTED 0x80000000u

/** The two buttons that answer an approval prompt. **/
#define PAD_BUTTON_CIRCLE 0x00002000u
#define PAD_BUTTON_CROSS  0x00004000u


/**
 * ScePadData as the PS5 lays it out. The SDK ships the library but no
 * header, so the layout is declared here. The buffer is padded to 1 KiB
 * because the system may write more than the documented 120 bytes.
 **/
typedef struct pad_data {
  uint32_t buttons;
  uint8_t  left_stick[2];
  uint8_t  right_stick[2];
  uint8_t  analog[2];
  uint16_t padding;
  float    orientation[4];
  float    acceleration[3];
  float    angular_velocity[3];
  uint8_t  touch[24];
  uint8_t  connected;
  uint64_t timestamp;
  uint8_t  ext[16];
  uint8_t  count;
  uint8_t  unknown[15];
  uint8_t  reserved[1024 - 120];
} pad_data_t;


_Static_assert(offsetof(pad_data_t, connected) == 76, "pad layout");
_Static_assert(offsetof(pad_data_t, timestamp) == 80, "pad layout");
_Static_assert(sizeof(pad_data_t) == 1024, "pad buffer size");


int sceUserServiceInitialize(void* init_params);
int sceUserServiceTerminate(void);
int sceUserServiceGetInitialUser(int* user_id);
int sceUserServiceGetForegroundUser(int* user_id);
int sceUserServiceGetLoginUserIdList(int* user_ids);
int sceUserServiceGetUserName(int user_id, char* name, size_t size);

int sceRegMgrGetInt(int entity, int* value);
int scePadInit(void);
int scePadOpen(int user_id, int type, int index, void* param);
int scePadGetHandle(int user_id, int type, int index);
int scePadSetProcessPrivilege(int privilege);
int scePadReadState(int handle, pad_data_t* data);
int scePadClose(int handle);

#endif /* ARIEL_PAD_H */
