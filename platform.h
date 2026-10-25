/* Ariel: the narrow platform port.

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

#ifndef ARIEL_PLATFORM_H
#define ARIEL_PLATFORM_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#include "approval.h"

/** The longest payload name the agent port accepts. **/
#define PAYLOAD_NAME_MAX 32

/** An approval ID is short, for example a-1. **/
#define APPROVAL_ID_MAX 32

/** The longest path a gated file command names, the longest argv[0] of an
    unimplemented command. **/
#define APPROVAL_TARGET_MAX 128
/** The longest signal name and process start identity a kill carries. **/
#define SIGNAL_NAME_MAX  8
#define PROCESS_START_MAX 31
/** The hash of an exec's arguments, in hex. **/
#define ARGS_HASH_MAX 64
/** The arguments a gated built-in binds after its target. **/
#define BUILTIN_ARGS_MAX 5

/**
 * The immutable fact record an approval is bound to: what exactly the
 * owner approves. A copy of it, never a pointer, is what the platform
 * holds, so a caller cannot change the facts after the request.
 *
 * A payload commit fills the name, size, hash, staging ID and run. A gated
 * action, a file command or an unimplemented command, fills the target
 * instead, with its entry's kind, device and inode, or its argument count.
 * For kill, name is the target pid, and signal and start are its signal and
 * start identity; for anything else they are empty.
 * chmod, chown and chgrp also fill value with the requested mode or owner.
 * A transfer, cp, mv or ln, also fills dest with its destination path.
 * For exec, the target is the program, sha256 its bytes, argc the arguments
 * after it and args their hash. For export, sha256 is the hash of the value.
 * A PS5 built-in fills arg with its arguments after the target, as text.
 * For a run, argc counts the arguments after its name and arg holds each one.
 **/

/** The most arguments a run can sign, and each one's longest value. **/
#define RUN_ARGS_MAX 8

typedef struct {
  char command[APPROVAL_COMMAND_MAX + 1];
  char name[PAYLOAD_NAME_MAX + 1];
  uint64_t size;
  char sha256[65];
  char staging_id[APPROVAL_ID_MAX];
  int run;  /** The approved build will be executed. **/
  char target[APPROVAL_TARGET_MAX + 1];
  char dest[APPROVAL_TARGET_MAX + 1];
  char kind[8];  /** file, dir, link, other or absent. **/
  uint64_t dev;
  uint64_t ino;
  int recursive;  /** rm or cp: the whole tree below the target. **/
  uint64_t argc;
  char signal[SIGNAL_NAME_MAX + 1];
  char start[PROCESS_START_MAX + 1];
  char value[16];  /** The requested mode or owner or group, canonical. **/
  char fstype[16];  /** mount: the file system type. **/
  char from[APPROVAL_TARGET_MAX + 1];  /** mount: the source path. **/
  char url[APPROVAL_URL_MAX + 1];  /** http2_get: the URL fetched. **/
  char type[2];  /** mknod: b or c. **/
  uint64_t major;
  uint64_t minor;
  char replaces[65];  /** The build a rollback replaces; empty otherwise. **/
  char tag[65];  /** install: the release tag the asset came from. **/
  uint64_t release;  /** install: the release ID; 0 for any other action. **/
  uint64_t asset;  /** install: the asset ID. **/
  char args[ARGS_HASH_MAX + 1];
  char arg[RUN_ARGS_MAX][APPROVAL_ARG_MAX + 1];  /** A built-in's or a run's. **/
  char server[APPROVAL_VALUE_MAX + 1];  /** An addon's server, from its server file. **/
} approval_facts_t;

/**
 * What the owner signs to approve one action: the approval ID, the console
 * it is for, the canonical action bytes, a nonce and the window it is good
 * for. issued_ms and expires_ms are on the platform clock.
 **/
typedef struct {
  char id[APPROVAL_ID_MAX];
  char console[APPROVAL_CONSOLE_MAX + 1];
  char action[APPROVAL_ACTION_MAX + 1];
  size_t action_len;
  uint32_t generation;
  unsigned char nonce[APPROVAL_NONCE_LEN];
  uint64_t issued_ms;
  uint64_t expires_ms;
} approval_challenge_t;

/**
 * The platform port: everything the agent port needs from the system it
 * runs on. Both builds share this header and the command logic above it;
 * platform_host.c and platform_ps5.c are the two implementations. The port
 * widens in Stage 2.
 **/
typedef struct platform platform_t;

/** Receives the next piece of a fetched body. Returns 0, or -1 to stop. **/
typedef int (*http_sink_t)(void *ctx, const unsigned char *data, size_t len);

struct platform {
  /**
   * The directory the file commands' absolute paths are under: empty on a
   * console, the test root on the host. Writable roots are below it.
   **/
  const char *fs_root;

  /** Return a socket listening on port, or -1 on error. **/
  int (*listen)(platform_t *self, uint16_t port);

  /** Return the next connection on srvfd, or -1 on error. **/
  int (*accept)(platform_t *self, int srvfd);

  /** Read the platform's monotonic clock. **/
  void (*clock)(platform_t *self, struct timespec *now);

  /**
   * Create the wake pipe of one connection and return its read end, or -1
   * when this platform has none. A wait polls the pipe together with its
   * socket, so moving the clock wakes it to recompute its deadline. On a
   * console no clock moves on its own, so the pipe is not needed.
   **/
  int (*wake_new)(platform_t *self);

  /** Close a wake pipe made by wake_new. **/
  void (*wake_close)(platform_t *self, int fd);

  /**
   * Tell the platform that the waiter of wake pipe wake is about to block
   * with nothing to read on fd (idle 1), or has woken (idle 0); fd is -1
   * for a waiter without a socket. A test clock uses this to tell a
   * scenario that every waiter has seen an advance. A console may leave it
   * NULL.
   **/
  void (*wake_idle)(platform_t *self, int wake, int fd, int idle);

  /**
   * Fill buf with len bytes from the system's cryptographic random source.
   * Returns 0, or -1 when it cannot.
   **/
  int (*random)(platform_t *self, unsigned char *buf, size_t len);

  /** The identity of this console: the text every signature names. **/
  const char *(*console_id)(platform_t *self);

  /**
   * Verify an Ed25519 signature of APPROVAL_SIG_LEN bytes over msg against
   * key. Returns 0 only for a valid one; with the build's anchor not pinned,
   * nothing is valid.
   **/
  int (*verify)(platform_t *self, const unsigned char key[APPROVAL_PUBKEY_LEN],
                const unsigned char *msg, size_t len,
                const unsigned char *signature);

  /**
   * The anchor pinned in this build: the primary and recovery public keys
   * that make generation 0. Returns 0 when both are pinned and distinct, and
   * -1 when this build pins no usable anchor.
   **/
  int (*anchor)(platform_t *self, unsigned char primary[APPROVAL_PUBKEY_LEN],
                unsigned char recovery[APPROVAL_PUBKEY_LEN]);

  /**
   * Ask the owner to approve the facts' action and show the prompt on the
   * console. On success fill challenge, what the owner signs, and return
   * 0; return -1 when no approval can be requested now.
   **/
  int (*approval_request)(platform_t *self, const approval_facts_t *facts,
                          approval_challenge_t *challenge);

  /**
   * Take the owner's signature for an approval: verify it behind the port
   * and, when it holds, mark the approval decided with its nonce recorded
   * as consumed. console and action_sha256 are the signer's envelope, both
   * NULL for a bare signature: a mismatch names the wrong console or action
   * instead of an invalid signature. Returns one of the STORE_GRANT_*
   * outcomes.
   **/
  int (*approval_grant)(platform_t *self, const char *id,
                        const unsigned char *signature,
                        const char *console, const char *action_sha256);

  /**
   * Run a payload in the foreground from its verified bytes: put the bytes
   * in a fresh file only Ariel can read, execute it with argv (argv[0] is
   * the payload's name) with its output on outfd, wait for it and return
   * its exit status in status. Returns 0 when the payload ran, -1 on a
   * platform error. The bytes are never loaded from a path.
   **/
  int (*spawn)(platform_t *self, const unsigned char *bytes, size_t size,
               char *const argv[], int outfd, int *status);

  /**
   * Start a payload from its verified bytes as spawn does, but return at
   * once: pid is the started payload, and its output goes to outfd. Returns
   * 0 when it started, -1 on a platform error.
   **/
  int (*spawn_start)(platform_t *self, const unsigned char *bytes, size_t size,
                     char *const argv[], int outfd, pid_t *pid);

  /**
   * Check on a payload that spawn_start started, without blocking. Returns 1
   * with its exit status in status once it has exited, 0 while it runs, and
   * -1 on a platform error. An exited payload is reaped by this call.
   **/
  int (*spawn_poll)(platform_t *self, pid_t pid, int *status);

  /** Stop a payload that spawn_start started, at once. Returns 0, or -1. **/
  int (*spawn_kill)(platform_t *self, pid_t pid);

  /**
   * Start a payload as spawn_start does, but with an empty environment: it
   * gets argv and outfd and nothing else of Ariel's environment.
   **/
  int (*spawn_start_isolated)(platform_t *self, const unsigned char *bytes,
                              size_t size, char *const argv[], int outfd,
                              pid_t *pid);

  /**
   * Run one noninteractive shell command: argv[0] is the command and
   * argv[argc] is NULL. Its output goes to outfd and its diagnostics to
   * errfd, and its own exit status comes back in status. A connection has
   * no working directory, so every path is absolute and cd is an error.
   * Returns 0 when the command ran, -1 when this platform has no such
   * command.
   **/
  int (*run)(platform_t *self, int argc, char *const argv[], int outfd,
             int errfd, int *status);

  /**
   * Perform a gated system command, mount, umount, chroot or mknod, on the
   * target the facts name, once the owner has signed them and the entry is
   * checked again. Returns 0 when it ran, 1 when this platform cannot run
   * such a command, and -1 on a platform error.
   **/
  int (*system_act)(platform_t *self, const approval_facts_t *facts);

  /**
   * Called at each named step of a store change, so a host build can end
   * Ariel there and a test can see what a restart recovers. NULL on the
   * console, where no fault is injected.
   **/
  void (*fault)(platform_t *self, const char *step);

  /**
   * Write the pids of the processes on this system into pids, at most max
   * of them. Returns how many, or -1 when the list cannot be read.
   **/
  int (*processes)(platform_t *self, int32_t *pids, size_t max);

  /**
   * Write the start identity of process pid into out: text that stays the
   * same while that process lives and differs for a later process that
   * reuses its pid. Returns 0, or -1 when there is no such process.
   **/
  int (*process_start)(platform_t *self, int32_t pid, char *out, size_t size);

  /**
   * Whether pid is a critical system process, which no command may signal
   * even with an approval. Returns 1 or 0.
   **/
  int (*process_critical)(platform_t *self, int32_t pid);

  /** Send signal sig to process pid. Returns 0, or -1 on error. **/
  int (*process_signal)(platform_t *self, int32_t pid, int sig);

  /**
   * Restart the console once the owner has approved a reboot. On success it
   * does not return. Returns -1 when the restart cannot be started.
   **/
  int (*reboot)(platform_t *self);

  /**
   * Fetch url over plain HTTP without following redirects. The reply status
   * is set in status and a redirect's Location is copied into location. The
   * body is passed to sink in order and may not exceed max bytes. Returns 0
   * when a reply arrived, or -1 for a refused URL, a failed transfer or a
   * body over max.
   **/
  int (*http_get)(platform_t *self, const char *url, size_t max,
                  http_sink_t sink, void *ctx, int *status, char *location,
                  size_t size);
};

/**
 * The implementation for the host operating system. run_dir is a directory
 * only Ariel can read, where the bytes of a run are written before they are
 * executed and removed afterwards. fs_root is the test root that file
 * commands' paths are under. exe is Ariel's own program, which a reboot
 * starts again.
 **/
platform_t *platform_host(const char *run_dir, const char *fs_root,
                          const char *exe);

#endif /* ARIEL_PLATFORM_H */
