/* Ariel host build: the MCP server's protocol, one JSON-RPC message per line.

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

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "../approval.h"
#include "../sha256.h"
#include "mcp.h"
#include "mcp_link.h"

#define MCP_LINE_MAX 65536
#define MCP_DEPTH_MAX 32
#define CONSOLE_LINE_MAX 4096
#define SESSION_HEX_LEN 32
#define INTEGER_DIGITS_MAX 18
#define WORD_MAX 32
#define APPROVAL_ID_MAX 40
#define FILE_CHUNK 8192
#define SIGNATURE_MAX (2 * APPROVAL_SIG_LEN + 1 + APPROVAL_CONSOLE_MAX + 1 + 2 * SHA256_DIGEST_LEN)

enum mcp_class {
  MCP_READ,
  MCP_WRITE,
  MCP_EXEC
};

enum mcp_kind {
  ARG_STRING,
  ARG_INTEGER,
  ARG_LOCAL
};

typedef struct {
  const char *key;
  enum mcp_kind kind;
  int required;
  const char *flag;
} mcp_arg_t;

typedef struct {
  const char *name;
  const char *description;
  enum mcp_class cls;
  const char *word;
  const mcp_arg_t *args;
} mcp_tool_t;

static const mcp_arg_t no_args[] = {
  { NULL, ARG_STRING, 0, NULL }
};

static const mcp_arg_t path_args[] = {
  { "path", ARG_STRING, 1, NULL },
  { NULL, ARG_STRING, 0, NULL }
};

static const mcp_arg_t name_args[] = {
  { "name", ARG_STRING, 1, NULL },
  { NULL, ARG_STRING, 0, NULL }
};

static const mcp_arg_t pid_args[] = {
  { "pid", ARG_INTEGER, 1, NULL },
  { NULL, ARG_STRING, 0, NULL }
};

static const mcp_arg_t ping_args[] = {
  { "address", ARG_STRING, 1, NULL },
  { "count", ARG_INTEGER, 0, "-c" },
  { "wait", ARG_INTEGER, 0, "-W" },
  { NULL, ARG_STRING, 0, NULL }
};

static const mcp_arg_t read_args[] = {
  { "path", ARG_STRING, 1, NULL },
  { "offset", ARG_INTEGER, 0, "--offset" },
  { "limit", ARG_INTEGER, 0, "--limit" },
  { "local_path", ARG_LOCAL, 0, NULL },
  { NULL, ARG_STRING, 0, NULL }
};

static const mcp_arg_t push_args[] = {
  { "name", ARG_STRING, 1, NULL },
  { "local_path", ARG_LOCAL, 0, NULL },
  { NULL, ARG_STRING, 0, NULL }
};

static const mcp_arg_t write_args[] = {
  { "path", ARG_STRING, 1, NULL },
  { "local_path", ARG_LOCAL, 0, NULL },
  { NULL, ARG_STRING, 0, NULL }
};

// The tool table is the whole surface: tools/list and tools/call both read it.
// A NULL name ends it. A row's word is the console command it runs.
static const mcp_tool_t mcp_tools[] = {
  { "ariel_ls", "List a directory on the console.", MCP_READ, "ls", path_args },
  { "ariel_cat", "Read a file on the console.", MCP_READ, "cat", path_args },
  { "ariel_stat", "Show a file's status on the console.", MCP_READ, "stat", path_args },
  { "ariel_df", "Show free space for a path on the console.", MCP_READ, "df", path_args },
  { "ariel_find", "Find files under a path on the console.", MCP_READ, "find", path_args },
  { "ariel_file", "Name a file's type on the console.", MCP_READ, "file", path_args },
  { "ariel_head", "Read the first lines of a file on the console.", MCP_READ, "head", path_args },
  { "ariel_tail", "Read the last lines of a file on the console.", MCP_READ, "tail", path_args },
  { "ariel_wc", "Count lines, words and bytes in a file on the console.", MCP_READ, "wc", path_args },
  { "ariel_du", "Show disk use under a path on the console.", MCP_READ, "du", path_args },
  { "ariel_pwd", "Show the working directory, or the session's inside a session.", MCP_READ, "pwd", no_args },
  { "ariel_sysinfo", "Show system information from the console.", MCP_READ, "sysinfo", no_args },
  { "ariel_sysctl", "Read one sysctl value from the console.", MCP_READ, "sysctl", name_args },
  { "ariel_ps", "List processes on the console.", MCP_READ, "ps", no_args },
  { "ariel_procstat", "Show one process's status on the console.", MCP_READ, "procstat", pid_args },
  { "ariel_dmesg", "Read the console's kernel log.", MCP_READ, "dmesg", no_args },
  { "ariel_ifconfig", "Show the console's network interfaces.", MCP_READ, "ifconfig", no_args },
  { "ariel_ping", "Ping an address from the console.", MCP_READ, "ping", ping_args },
  { "ariel_mkdir", "Create a directory on the console. The owner signs the challenge first; then call again with approval_id and signature.", MCP_WRITE, "mkdir", path_args },
  { "ariel_read", "Read a byte range of a file on the console. With local_path, an absolute path on this host, the server writes the range to that file and answers its path, size and hash, never the bytes.", MCP_READ, "read", read_args },
  { "ariel_payload_push", "Push a payload to the console. The server reads the bytes of local_path, an absolute path on this host, and streams them to the console. An upload that stops moving for 59 seconds is cut by the console, not by this server, and the console's word answers, such as upload_mismatch or staging_full. The owner signs the challenge first; then call again with approval_id and signature.", MCP_WRITE, "payload push", push_args },
  { "ariel_write", "Write a file on the console from local_path, an absolute path on this host that the server reads and streams to the console. The owner signs the challenge first; then call again with approval_id and signature.", MCP_WRITE, "write", write_args },
  { NULL, NULL, MCP_READ, NULL, NULL }
};

static const char empty_object[] = "{}";

struct command {
  char text[CONSOLE_LINE_MAX + 1];
  size_t len;
};

static const char null_id[] = "null";

typedef struct {
  const char *p;
  const char *end;
  int depth;
} cursor_t;


static void
skip_ws(cursor_t *c) {
  while(c->p < c->end && (*c->p == ' ' || *c->p == '\t' ||
                          *c->p == '\r' || *c->p == '\n')) {
    c->p++;
  }
}


static int
skip_string(cursor_t *c) {
  if(c->p >= c->end || *c->p != '"') {
    return -1;
  }

  for(c->p++; c->p < c->end; c->p++) {
    if(*c->p == '\\') {
      if(++c->p >= c->end) {
        return -1;
      }
    } else if(*c->p == '"') {
      c->p++;
      return 0;
    } else if((unsigned char)*c->p < 0x20) {
      return -1;
    }
  }

  return -1;
}


static int skip_value(cursor_t *c);


static int
skip_container(cursor_t *c) {
  char open = *c->p;
  char close = open == '{' ? '}' : ']';

  if(++c->depth > MCP_DEPTH_MAX) {
    return -1;
  }
  c->p++;
  skip_ws(c);
  if(c->p < c->end && *c->p == close) {
    c->p++;
    c->depth--;
    return 0;
  }

  for(;;) {
    skip_ws(c);
    if(open == '{') {
      if(skip_string(c)) {
        return -1;
      }
      skip_ws(c);
      if(c->p >= c->end || *c->p != ':') {
        return -1;
      }
      c->p++;
    }
    if(skip_value(c)) {
      return -1;
    }
    skip_ws(c);
    if(c->p >= c->end) {
      return -1;
    }
    if(*c->p == ',') {
      c->p++;
      continue;
    }
    if(*c->p == close) {
      c->p++;
      c->depth--;
      return 0;
    }
    return -1;
  }
}


static int
skip_word(cursor_t *c, const char *word) {
  size_t n = strlen(word);

  if((size_t)(c->end - c->p) < n || memcmp(c->p, word, n)) {
    return -1;
  }
  c->p += n;
  return 0;
}


static int
skip_digits(cursor_t *c) {
  const char *start = c->p;

  while(c->p < c->end && *c->p >= '0' && *c->p <= '9') {
    c->p++;
  }
  return c->p == start ? -1 : 0;
}


static int
skip_number(cursor_t *c) {
  if(c->p < c->end && *c->p == '-') {
    c->p++;
  }
  if(c->p < c->end && *c->p == '0') {
    c->p++;
  } else if(skip_digits(c)) {
    return -1;
  }
  if(c->p < c->end && *c->p == '.') {
    c->p++;
    if(skip_digits(c)) {
      return -1;
    }
  }
  if(c->p < c->end && (*c->p == 'e' || *c->p == 'E')) {
    c->p++;
    if(c->p < c->end && (*c->p == '+' || *c->p == '-')) {
      c->p++;
    }
    if(skip_digits(c)) {
      return -1;
    }
  }
  return 0;
}


static int
skip_value(cursor_t *c) {
  skip_ws(c);
  if(c->p >= c->end) {
    return -1;
  }

  switch(*c->p) {
  case '"':
    return skip_string(c);
  case '{':
  case '[':
    return skip_container(c);
  case 't':
    return skip_word(c, "true");
  case 'f':
    return skip_word(c, "false");
  case 'n':
    return skip_word(c, "null");
  default:
    return skip_number(c);
  }
}


/**
 * Find key in the object that spans p to end. It returns 1 and the value's
 * span when the key is present, 0 when it is not, and -1 when the text is not
 * one well-formed object. stop, when given, receives the end of the object.
 **/
static int
object_member(const char *p, const char *end, const char *key,
              const char **vs, const char **ve, const char **stop) {
  cursor_t c = { p, end, 0 };
  size_t klen = strlen(key);
  int found = 0;

  skip_ws(&c);
  if(c.p >= c.end || *c.p != '{') {
    return -1;
  }
  c.p++;
  skip_ws(&c);
  if(c.p < c.end && *c.p == '}') {
    c.p++;
    if(stop) {
      *stop = c.p;
    }
    return 0;
  }

  for(;;) {
    const char *k = c.p;
    const char *kend;
    const char *vb;

    if(skip_string(&c)) {
      return -1;
    }
    kend = c.p;
    skip_ws(&c);
    if(c.p >= c.end || *c.p != ':') {
      return -1;
    }
    c.p++;
    skip_ws(&c);
    vb = c.p;
    if(skip_value(&c)) {
      return -1;
    }
    if(!found && (size_t)(kend - k - 2) == klen && !memcmp(k + 1, key, klen)) {
      *vs = vb;
      *ve = c.p;
      found = 1;
    }

    skip_ws(&c);
    if(c.p >= c.end) {
      return -1;
    }
    if(*c.p == ',') {
      c.p++;
      skip_ws(&c);
      continue;
    }
    if(*c.p == '}') {
      c.p++;
      if(stop) {
        *stop = c.p;
      }
      return found;
    }
    return -1;
  }
}


static int
is_string(const char *vs) {
  return *vs == '"';
}


static int
is_method(const char *vs, const char *ve, const char *name) {
  size_t n = strlen(name);

  return (size_t)(ve - vs - 2) == n && !memcmp(vs + 1, name, n);
}


static int
valid_id(const char *p) {
  return *p == '"' || *p == '-' || *p == 'n' || (*p >= '0' && *p <= '9');
}


static const mcp_tool_t *
find_tool(const char *name, size_t len) {
  size_t i;

  for(i = 0; mcp_tools[i].name; i++) {
    if(strlen(mcp_tools[i].name) == len && !memcmp(mcp_tools[i].name, name, len)) {
      return &mcp_tools[i];
    }
  }
  return NULL;
}


static int
append(struct command *cmd, const char *text, size_t len) {
  if(len > CONSOLE_LINE_MAX - cmd->len) {
    return -1;
  }
  memcpy(cmd->text + cmd->len, text, len);
  cmd->len += len;
  cmd->text[cmd->len] = '\0';
  return 0;
}


static int
append_quoted(struct command *cmd, const char *text, size_t len) {
  size_t i;

  if(append(cmd, " \"", 2)) {
    return -1;
  }
  for(i = 0; i < len; i++) {
    if((text[i] == '"' || text[i] == '\\') && append(cmd, "\\", 1)) {
      return -1;
    }
    if(append(cmd, text + i, 1)) {
      return -1;
    }
  }
  return append(cmd, "\"", 1);
}


static int
hex_value(char c) {
  if(c >= '0' && c <= '9') {
    return c - '0';
  }
  if(c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if(c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}


static int
put_utf8(char *out, size_t *n, size_t cap, unsigned long cp) {
  size_t need = cp < 0x80 ? 1 : cp < 0x800 ? 2 : 3;

  if(*n + need > cap) {
    return -1;
  }
  if(need == 1) {
    out[(*n)++] = (char)cp;
  } else if(need == 2) {
    out[(*n)++] = (char)(0xC0 | (cp >> 6));
    out[(*n)++] = (char)(0x80 | (cp & 0x3F));
  } else {
    out[(*n)++] = (char)(0xE0 | (cp >> 12));
    out[(*n)++] = (char)(0x80 | ((cp >> 6) & 0x3F));
    out[(*n)++] = (char)(0x80 | (cp & 0x3F));
  }
  return 0;
}


/* The JSON text between the quotes at p..end, as the bytes it stands for. */
static int
decode_string(const char *p, const char *end, char *out, size_t cap, size_t *len) {
  size_t n = 0;

  while(p < end) {
    unsigned long cp;

    if(*p != '\\') {
      if((unsigned char)*p < 0x20 || n + 1 > cap) {
        return -1;
      }
      out[n++] = *p++;
      continue;
    }
    if(end - p < 2) {
      return -1;
    }
    if(p[1] == 'u') {
      int i;

      if(end - p < 6) {
        return -1;
      }
      cp = 0;
      for(i = 2; i < 6; i++) {
        int h = hex_value(p[i]);

        if(h < 0) {
          return -1;
        }
        cp = cp * 16 + (unsigned long)h;
      }
      p += 6;
    } else if(p[1] == '"' || p[1] == '\\' || p[1] == '/') {
      cp = (unsigned char)p[1];
      p += 2;
    } else {
      return -1;
    }
    if(cp < 0x20 || (cp >= 0xD800 && cp <= 0xDFFF) ||
       put_utf8(out, &n, cap, cp)) {
      return -1;
    }
  }
  *len = n;
  return 0;
}


static int
session_id(const char *text, size_t len) {
  size_t i;

  if(len != SESSION_HEX_LEN) {
    return 0;
  }
  for(i = 0; i < len; i++) {
    char c = text[i];

    if(!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
      return 0;
    }
  }
  return 1;
}


static int
whole_integer(const char *p, const char *end) {
  size_t digits;

  if(p < end && *p == '-') {
    p++;
  }
  digits = (size_t)(end - p);
  if(digits == 0 || digits > INTEGER_DIGITS_MAX) {
    return 0;
  }
  for(; p < end; p++) {
    if(!isdigit((unsigned char)*p)) {
      return 0;
    }
  }
  return 1;
}


static int
build_command(const mcp_tool_t *row, const char *as, const char *ae,
              struct command *cmd, char *why, size_t why_len) {
  char value[CONSOLE_LINE_MAX + 1];
  const mcp_arg_t *arg;
  const char *vs;
  const char *ve;
  size_t vlen = 0;
  int found;

  cmd->len = 0;
  cmd->text[0] = '\0';

  found = object_member(as, ae, "session", &vs, &ve, NULL);
  if(found < 0 || (found == 1 && (*vs != '"' ||
                   decode_string(vs + 1, ve - 1, value, sizeof(value), &vlen) ||
                   !session_id(value, vlen)))) {
    snprintf(why, why_len, "invalid params: session is not a session id");
    return -1;
  }
  if(found == 1 && (append(cmd, "@", 1) || append(cmd, value, vlen) ||
                    append(cmd, " ", 1))) {
    snprintf(why, why_len, "invalid params: the command is too long");
    return -1;
  }
  if(append(cmd, row->word, strlen(row->word))) {
    snprintf(why, why_len, "invalid params: the command is too long");
    return -1;
  }

  for(arg = row->args; arg->key; arg++) {
    if(arg->kind == ARG_LOCAL) {
      continue;
    }
    found = object_member(as, ae, arg->key, &vs, &ve, NULL);
    if(found < 0) {
      snprintf(why, why_len, "invalid params: arguments must be an object");
      return -1;
    }
    if(found == 0) {
      if(arg->required) {
        snprintf(why, why_len, "invalid params: %s is required", arg->key);
        return -1;
      }
      continue;
    }

    if(arg->flag && (append(cmd, " ", 1) || append(cmd, arg->flag, strlen(arg->flag)))) {
      snprintf(why, why_len, "invalid params: the command is too long");
      return -1;
    }
    if(arg->kind == ARG_STRING) {
      if(*vs != '"' || decode_string(vs + 1, ve - 1, value, sizeof(value), &vlen)) {
        snprintf(why, why_len, "invalid params: %s must be text", arg->key);
        return -1;
      }
      if(append_quoted(cmd, value, vlen)) {
        snprintf(why, why_len, "invalid params: the command is too long");
        return -1;
      }
    } else {
      if(!whole_integer(vs, ve)) {
        snprintf(why, why_len, "invalid params: %s must be a whole number", arg->key);
        return -1;
      }
      if(append(cmd, " ", 1) || append(cmd, vs, (size_t)(ve - vs))) {
        snprintf(why, why_len, "invalid params: the command is too long");
        return -1;
      }
    }
  }
  return 0;
}


static int
console_word(const char *text, size_t len, char *word) {
  size_t n = 0;

  while(n < len && (islower((unsigned char)text[n]) || text[n] == '_')) {
    n++;
  }
  if(n == 0 || n >= WORD_MAX) {
    return 0;
  }
  if(n < len && text[n] != ' ' && text[n] != '\t' && text[n] != '\n') {
    return 0;
  }
  memcpy(word, text, n);
  word[n] = '\0';
  return 1;
}


static int
cut_marker(const char *text, size_t len) {
  const char *line;
  unsigned long shown;
  unsigned long total;
  int used = 0;
  size_t i;

  if(len == 0 || text[len - 1] != '\n') {
    return 0;
  }
  i = len - 1;
  while(i > 0 && text[i - 1] != '\n') {
    i--;
  }
  line = text + i;
  if(sscanf(line, "truncated %lu of %lu%n", &shown, &total, &used) != 2) {
    return 0;
  }
  return line + used == text + len - 1;
}


static void
json_text(FILE *out, const char *text, size_t len) {
  size_t i;

  fputc('"', out);
  for(i = 0; i < len; i++) {
    unsigned char c = (unsigned char)text[i];

    switch(c) {
    case '"':
      fputs("\\\"", out);
      break;
    case '\\':
      fputs("\\\\", out);
      break;
    case '\n':
      fputs("\\n", out);
      break;
    case '\r':
      fputs("\\r", out);
      break;
    case '\t':
      fputs("\\t", out);
      break;
    default:
      if(c < 0x20) {
        fprintf(out, "\\u%04x", c);
      } else {
        fputc(c, out);
      }
    }
  }
  fputc('"', out);
}




static void
begin_result(FILE *out, const char *id, const char *idend) {
  if(!id) {
    id = null_id;
    idend = null_id + sizeof(null_id) - 1;
  }
  fprintf(out, "{\"jsonrpc\":\"2.0\",\"id\":%.*s,\"result\":",
          (int)(idend - id), id);
}


static void
end_reply(FILE *out) {
  fputs("}\n", out);
  fflush(out);
}


static void
write_result(FILE *out, const char *id, const char *idend, const char *result) {
  begin_result(out, id, idend);
  fputs(result, out);
  end_reply(out);
}


static void
write_error(FILE *out, const char *id, const char *idend, int code,
            const char *message) {
  if(!id) {
    id = null_id;
    idend = null_id + sizeof(null_id) - 1;
  }
  fprintf(out, "{\"jsonrpc\":\"2.0\",\"id\":%.*s,\"error\":{\"code\":%d,"
          "\"message\":\"%s\"}}\n", (int)(idend - id), id, code, message);
  fflush(out);
}


static void
write_failure(FILE *out, const char *id, const char *idend, const char *why) {
  begin_result(out, id, idend);
  fputs("{\"content\":[{\"type\":\"text\",\"text\":", out);
  json_text(out, why, strlen(why));
  fputs("}],\"isError\":true}", out);
  end_reply(out);
}


static const char approval_prefix[] = "approval_required ";
static const char challenge_prefix[] = "challenge ";
static const char approval_next[] =
  "Sign the challenge with ariel-sign sign <owner.key>, then call this tool "
  "again with approval_id and signature.";

static int
safe_text(const char *text, size_t len, size_t max, int spaces) {
  size_t i;

  if(len == 0 || len > max) {
    return 0;
  }
  for(i = 0; i < len; i++) {
    char c = text[i];

    if(!isalnum((unsigned char)c) && c != '-' && c != '_' && c != '.' &&
       !(spaces && c == ' ')) {
      return 0;
    }
  }
  return 1;
}


static int
one_token(const char *text, size_t len, size_t max) {
  size_t i;

  if(len == 0 || len > max) {
    return 0;
  }
  for(i = 0; i < len; i++) {
    unsigned char c = (unsigned char)text[i];

    if(c <= ' ' || c >= 0x7F || c == '"' || c == '\'' || c == '\\') {
      return 0;
    }
  }
  return 1;
}


/* The space-separated field n of text, when it is not empty. */
static int
nth_field(const char *text, size_t len, int n, const char **field, size_t *flen) {
  const char *p = text;
  const char *end = text + len;
  int i;

  for(i = 0; i < n; i++) {
    while(p < end && *p != ' ') {
      p++;
    }
    if(p >= end) {
      return 0;
    }
    p++;
  }
  *field = p;
  while(p < end && *p != ' ') {
    p++;
  }
  *flen = (size_t)(p - *field);
  return *flen > 0;
}


static const char *
approval_line(const char *text, const char *end) {
  const char *p = text;

  while(p < end) {
    if((size_t)(end - p) >= sizeof(approval_prefix) - 1 &&
       !memcmp(p, approval_prefix, sizeof(approval_prefix) - 1)) {
      return p;
    }
    p = memchr(p, '\n', (size_t)(end - p));
    if(!p) {
      return NULL;
    }
    p++;
  }
  return NULL;
}


/*
 * The owner's question in either shape of approval_required: the approval ID,
 * then the challenge line when the request opened the approval. A pending
 * approval answers the ID alone, and the structured body says so by lacking it.
 */
static void
write_approval(FILE *out, const struct mcp_answer *answer) {
  const char *end = answer->text + answer->len;
  const char *text;
  const char *line_end;
  const char *challenge = NULL;
  const char *field;
  size_t challenge_len = 0;
  size_t field_len;
  size_t id_len;

  if(answer->status != 75) {
    return;
  }
  text = approval_line(answer->text, end);
  if(!text) {
    return;
  }
  text += sizeof(approval_prefix) - 1;
  line_end = memchr(text, '\n', (size_t)(end - text));
  if(!line_end) {
    return;
  }
  id_len = (size_t)(line_end - text);
  if(!safe_text(text, id_len, APPROVAL_ID_MAX, 0)) {
    return;
  }
  fputs(",\"approval_id\":", out);
  json_text(out, text, id_len);

  text = line_end + 1;
  if((size_t)(end - text) >= sizeof(challenge_prefix) - 1 &&
     !memcmp(text, challenge_prefix, sizeof(challenge_prefix) - 1)) {
    const char *challenge_end = memchr(text, '\n', (size_t)(end - text));

    challenge = text;
    challenge_len = challenge_end ? (size_t)(challenge_end - text)
                                  : (size_t)(end - text);
  }
  if(challenge) {
    fputs(",\"challenge\":", out);
    json_text(out, challenge, challenge_len);
    if(nth_field(challenge, challenge_len, 2, &field, &field_len)) {
      fputs(",\"console\":", out);
      json_text(out, field, field_len);
    }
    if(nth_field(challenge, challenge_len, 6, &field, &field_len)) {
      fputs(",\"action\":", out);
      json_text(out, field, field_len);
    }
  }
  fputs(",\"next\":", out);
  json_text(out, approval_next, sizeof(approval_next) - 1);
}


static void
write_answer(FILE *out, const char *id, const char *idend,
             const struct mcp_answer *answer) {
  char word[WORD_MAX];
  int refused = answer->status != 0;

  begin_result(out, id, idend);
  fputs("{\"content\":[{\"type\":\"text\",\"text\":", out);
  json_text(out, answer->text, answer->len);
  fprintf(out, "}],\"structuredContent\":{\"exit\":%d,\"truncated\":%s",
          answer->status, cut_marker(answer->text, answer->len) ? "true" : "false");
  if(refused && console_word(answer->text, answer->len, word)) {
    fprintf(out, ",\"word\":\"%s\"", word);
  }
  write_approval(out, answer);
  fprintf(out, "},\"isError\":%s}", refused ? "true" : "false");
  end_reply(out);
}


static int
grant_requested(const char *as, const char *ae) {
  const char *vs = NULL;
  const char *ve = NULL;

  return object_member(as, ae, "approval_id", &vs, &ve, NULL) == 1 ||
         object_member(as, ae, "signature", &vs, &ve, NULL) == 1;
}


static void
refuse(FILE *out, const char *id, const char *idend, const char *word, int status) {
  struct mcp_answer answer;
  char text[WORD_MAX + 16];

  answer.len = (size_t)snprintf(text, sizeof(text), "%s\nexit %d\n", word, status);
  answer.text = text;
  answer.status = status;
  write_answer(out, id, idend, &answer);
}


/*
 * The owner's grant, relayed: the server holds no key and checks nothing the
 * agent does not. It refuses only text that could not be one line of the
 * agent's grammar; an id that is not one token could never have been issued.
 */
static void
grant_call(FILE *out, const char *ids, const char *ide, const char *as,
           const char *ae, const struct mcp_console *console) {
  const char *is = NULL;
  const char *ie = NULL;
  const char *ss = NULL;
  const char *se = NULL;
  char id[APPROVAL_ID_MAX + 1];
  char signature[SIGNATURE_MAX + 1];
  size_t idlen = 0;
  size_t siglen = 0;
  struct command cmd;
  struct mcp_answer answer;
  char why[MCP_LINK_WHY_MAX];

  if(object_member(as, ae, "approval_id", &is, &ie, NULL) != 1 ||
     object_member(as, ae, "signature", &ss, &se, NULL) != 1 ||
     !is_string(is) || !is_string(ss)) {
    write_error(out, ids, ide, -32602,
                "invalid params: approval_id and signature are both required");
    return;
  }
  if(decode_string(is + 1, ie - 1, id, APPROVAL_ID_MAX, &idlen) ||
     !one_token(id, idlen, APPROVAL_ID_MAX)) {
    refuse(out, ids, ide, "unknown_approval", 1);
    return;
  }
  if(decode_string(ss + 1, se - 1, signature, SIGNATURE_MAX, &siglen) ||
     !safe_text(signature, siglen, SIGNATURE_MAX, 1)) {
    refuse(out, ids, ide, "signature_malformed", 83);
    return;
  }

  cmd.len = 0;
  cmd.text[0] = '\0';
  if(append(&cmd, "approval grant ", 15) || append(&cmd, id, idlen) ||
     append(&cmd, " ", 1) || append(&cmd, signature, siglen)) {
    write_error(out, ids, ide, -32602, "invalid params: the command is too long");
    return;
  }
  if(mcp_exchange(console, cmd.text, &answer, why, sizeof(why))) {
    write_failure(out, ids, ide, why);
    return;
  }
  write_answer(out, ids, ide, &answer);
  free(answer.text);
}


static int
row_has_local(const mcp_tool_t *row) {
  const mcp_arg_t *arg;

  for(arg = row->args; arg->key; arg++) {
    if(arg->kind == ARG_LOCAL) {
      return 1;
    }
  }
  return 0;
}


/* The local_path argument: 1 when given, 0 when absent, -1 when not text. */
static int
local_member(const char *as, const char *ae, char *path, size_t cap, size_t *len) {
  const char *vs = NULL;
  const char *ve = NULL;
  int found;

  found = object_member(as, ae, "local_path", &vs, &ve, NULL);
  if(found != 1) {
    return found < 0 ? -1 : 0;
  }
  if(*vs != '"' || decode_string(vs + 1, ve - 1, path, cap, len)) {
    return -1;
  }
  path[*len] = '\0';
  return 1;
}


static void
local_failure(char *message, size_t cap, const char *verb, const char *local, int err) {
  snprintf(message, cap, "cannot %s local_path %s: %s", verb, local, strerror(err));
}


static int
hash_local(FILE *file, uint64_t *size, char hex[SHA256_HEX_LEN + 1]) {
  unsigned char chunk[FILE_CHUNK];
  unsigned char digest[SHA256_DIGEST_LEN];
  sha256_t hash;
  size_t n;

  sha256_init(&hash);
  *size = 0;
  while((n = fread(chunk, 1, sizeof(chunk), file)) > 0) {
    sha256_update(&hash, chunk, n);
    *size += n;
  }
  if(ferror(file)) {
    return -1;
  }
  sha256_final(&hash, digest);
  sha256_hex(digest, hex);
  return 0;
}


static void
upload_call(FILE *out, const char *ids, const char *ide, const mcp_tool_t *row,
            const char *as, const char *ae, const char *local,
            const struct mcp_console *console) {
  char message[CONSOLE_LINE_MAX + 128];
  char hex[SHA256_HEX_LEN + 1];
  char tail[SHA256_HEX_LEN + 32];
  struct command cmd;
  struct mcp_answer answer;
  char why[MCP_LINK_WHY_MAX];
  uint64_t size;
  FILE *file;
  int err;

  if(build_command(row, as, ae, &cmd, why, sizeof(why))) {
    write_error(out, ids, ide, -32602, why);
    return;
  }
  file = fopen(local, "rb");
  if(!file) {
    local_failure(message, sizeof(message), "read", local, errno);
    write_failure(out, ids, ide, message);
    return;
  }
  if(hash_local(file, &size, hex)) {
    err = errno;
    fclose(file);
    local_failure(message, sizeof(message), "read", local, err);
    write_failure(out, ids, ide, message);
    return;
  }
  rewind(file);

  snprintf(tail, sizeof(tail), " %llu %s", (unsigned long long)size, hex);
  if(append(&cmd, tail, strlen(tail))) {
    fclose(file);
    write_error(out, ids, ide, -32602, "invalid params: the command is too long");
    return;
  }
  if(mcp_upload(console, cmd.text, file, size, &answer, why, sizeof(why))) {
    fclose(file);
    write_failure(out, ids, ide, why);
    return;
  }
  fclose(file);
  write_answer(out, ids, ide, &answer);
  free(answer.text);
}


static int
bytes_frame(const struct mcp_answer *answer, unsigned long long *size,
            char hex[SHA256_HEX_LEN + 1], size_t *head) {
  char line[128];
  const char *nl = memchr(answer->text, '\n', answer->len);
  size_t n;

  if(!nl || (size_t)(nl - answer->text) >= sizeof(line)) {
    return -1;
  }
  n = (size_t)(nl - answer->text);
  memcpy(line, answer->text, n);
  line[n] = '\0';
  if(sscanf(line, "bytes %llu %64s", size, hex) != 2 || strlen(hex) != SHA256_HEX_LEN) {
    return -1;
  }
  *head = n + 1;
  return *size > answer->len - *head ? -1 : 0;
}


static void
write_local_read(FILE *out, const char *ids, const char *ide, const char *local,
                 unsigned long long size, const char *range, const char *whole,
                 const char *tail, size_t tail_len) {
  char summary[CONSOLE_LINE_MAX + 128];
  size_t n;
  char *text;

  n = (size_t)snprintf(summary, sizeof(summary), "wrote %llu bytes to %s, sha256 %s\n",
                       size, local, range);
  text = malloc(n + tail_len + 1);
  if(!text) {
    write_failure(out, ids, ide, "out of memory for the console's answer");
    return;
  }
  memcpy(text, summary, n);
  memcpy(text + n, tail, tail_len);

  begin_result(out, ids, ide);
  fputs("{\"content\":[{\"type\":\"text\",\"text\":", out);
  json_text(out, text, n + tail_len);
  fprintf(out, "}],\"structuredContent\":{\"exit\":0,\"truncated\":%s,\"path\":",
          cut_marker(tail, tail_len) ? "true" : "false");
  json_text(out, local, strlen(local));
  fprintf(out, ",\"size\":%llu,\"sha256\":\"%s\",\"file_sha256\":\"%s\"},\"isError\":false}",
          size, range, whole);
  end_reply(out);
  free(text);
}


static void
download_call(FILE *out, const char *ids, const char *ide, const mcp_tool_t *row,
              const char *as, const char *ae, const char *local,
              const struct mcp_console *console) {
  char message[CONSOLE_LINE_MAX + 128];
  unsigned char digest[SHA256_DIGEST_LEN];
  char whole[SHA256_HEX_LEN + 1];
  char range[SHA256_HEX_LEN + 1];
  struct command cmd;
  struct mcp_answer answer;
  char why[MCP_LINK_WHY_MAX];
  unsigned long long size;
  sha256_t hash;
  size_t head;
  FILE *file;
  int err;

  if(build_command(row, as, ae, &cmd, why, sizeof(why))) {
    write_error(out, ids, ide, -32602, why);
    return;
  }
  if(mcp_exchange_frame(console, cmd.text, &answer, why, sizeof(why))) {
    write_failure(out, ids, ide, why);
    return;
  }
  if(answer.status != 0) {
    write_answer(out, ids, ide, &answer);
    free(answer.text);
    return;
  }
  if(bytes_frame(&answer, &size, whole, &head)) {
    free(answer.text);
    write_failure(out, ids, ide, "the console answered without a bytes frame");
    return;
  }

  err = 0;
  file = fopen(local, "wb");
  if(!file) {
    err = errno;
  } else {
    if(fwrite(answer.text + head, 1, (size_t)size, file) != size) {
      err = errno ? errno : EIO;
    }
    if(fclose(file) && !err) {
      err = errno;
    }
  }
  if(err) {
    free(answer.text);
    local_failure(message, sizeof(message), "write", local, err);
    write_failure(out, ids, ide, message);
    return;
  }

  sha256_init(&hash);
  sha256_update(&hash, answer.text + head, (size_t)size);
  sha256_final(&hash, digest);
  sha256_hex(digest, range);
  write_local_read(out, ids, ide, local, size, range, whole,
                   answer.text + head + size, answer.len - head - (size_t)size);
  free(answer.text);
}


static void
call_tool(FILE *out, const char *ids, const char *ide, const char *ps,
          const char *pe, int has_params, const struct mcp_console *console) {
  const char *ns = NULL;
  const char *ne = NULL;
  const char *as = NULL;
  const char *ae = NULL;
  const mcp_tool_t *row;
  struct command cmd;
  struct mcp_answer answer;
  char local[CONSOLE_LINE_MAX + 2];
  size_t local_len = 0;
  char why[MCP_LINK_WHY_MAX];
  int found;

  if(has_params != 1 ||
     object_member(ps, pe, "name", &ns, &ne, NULL) != 1 || !is_string(ns)) {
    write_error(out, ids, ide, -32602, "invalid params: name is required");
    return;
  }
  row = find_tool(ns + 1, (size_t)(ne - ns - 2));
  if(!row) {
    write_error(out, ids, ide, -32602, "invalid params: unknown tool");
    return;
  }
  if(object_member(ps, pe, "arguments", &as, &ae, NULL) != 1) {
    as = empty_object;
    ae = empty_object + sizeof(empty_object) - 1;
  }
  if(*as != '{') {
    write_error(out, ids, ide, -32602, "invalid params: arguments must be an object");
    return;
  }
  if(row->cls != MCP_READ && grant_requested(as, ae)) {
    grant_call(out, ids, ide, as, ae, console);
    return;
  }
  if(row_has_local(row)) {
    found = local_member(as, ae, local, sizeof(local) - 1, &local_len);
    if(found < 0) {
      write_error(out, ids, ide, -32602, "invalid params: local_path must be text");
      return;
    }
    if(found == 0 && row->cls != MCP_READ) {
      write_error(out, ids, ide, -32602, "invalid params: local_path is required");
      return;
    }
    if(found == 1) {
      if(local_len == 0 || local[0] != '/') {
        write_error(out, ids, ide, -32602,
                    "invalid params: local_path must be an absolute path");
        return;
      }
      if(row->cls == MCP_READ) {
        download_call(out, ids, ide, row, as, ae, local, console);
      } else {
        upload_call(out, ids, ide, row, as, ae, local, console);
      }
      return;
    }
  }
  if(build_command(row, as, ae, &cmd, why, sizeof(why))) {
    write_error(out, ids, ide, -32602, why);
    return;
  }
  if(mcp_exchange(console, cmd.text, &answer, why, sizeof(why))) {
    write_failure(out, ids, ide, why);
    return;
  }
  write_answer(out, ids, ide, &answer);
  free(answer.text);
}


static void
handle(const char *text, const char *end, FILE *out, int *initialized,
       const struct mcp_console *console) {
  const char *ids = NULL;
  const char *ide = NULL;
  const char *ms = NULL;
  const char *me = NULL;
  const char *ps = NULL;
  const char *pe = NULL;
  const char *stop = NULL;
  int has_id;
  int has_method;
  int has_params;

  has_id = object_member(text, end, "id", &ids, &ide, &stop);
  if(has_id < 0) {
    write_error(out, NULL, NULL, -32700, "parse error");
    return;
  }
  for(; stop < end && (*stop == ' ' || *stop == '\t' || *stop == '\r'); stop++) {
  }
  if(stop != end) {
    write_error(out, NULL, NULL, -32700, "parse error");
    return;
  }

  if(has_id && !valid_id(ids)) {
    write_error(out, NULL, NULL, -32600, "invalid request id");
    return;
  }
  if(!has_id) {
    ids = NULL;
    ide = NULL;
  }

  has_method = object_member(text, end, "method", &ms, &me, NULL);
  has_params = object_member(text, end, "params", &ps, &pe, NULL);
  if(has_method != 1 || !is_string(ms)) {
    write_error(out, ids, ide, -32600, "invalid request");
    return;
  }
  if(!has_id) {
    return;
  }

  if(is_method(ms, me, "initialize")) {
    if(*initialized) {
      write_error(out, ids, ide, -32600, "initialize already answered");
      return;
    }
    *initialized = 1;
    write_result(out, ids, ide,
                 "{\"protocolVersion\":\"" MCP_PROTOCOL_REVISION "\","
                 "\"capabilities\":{\"tools\":{}},"
                 "\"serverInfo\":{\"name\":\"ariel\",\"version\":\""
                 MCP_SERVER_VERSION "\"}}");
  } else if(is_method(ms, me, "ping")) {
    write_result(out, ids, ide, "{}");
  } else if(is_method(ms, me, "tools/list")) {
    begin_result(out, ids, ide);
    mcp_write_tools(out);
    end_reply(out);
  } else if(is_method(ms, me, "tools/call")) {
    call_tool(out, ids, ide, ps, pe, has_params, console);
  } else {
    write_error(out, ids, ide, -32601, "method not found");
  }
}


int
mcp_serve(FILE *in, FILE *out, const struct mcp_console *console) {
  char *line = NULL;
  size_t cap = 0;
  int initialized = 0;
  ssize_t n;

  while((n = getline(&line, &cap, in)) >= 0) {
    size_t len = (size_t)n;

    while(len && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
      len--;
    }
    if(len == 0) {
      continue;
    }
    if(len > MCP_LINE_MAX) {
      write_error(out, NULL, NULL, -32600, "request too large");
      continue;
    }
    handle(line, line + len, out, &initialized, console);
  }

  free(line);
  return 0;
}


static void
write_schema(FILE *out, const mcp_tool_t *row) {
  const char *sep = "";
  const mcp_arg_t *arg;

  fputs("{\"type\":\"object\",\"properties\":{", out);
  for(arg = row->args; arg->key; arg++) {
    fprintf(out, "%s\"%s\":{\"type\":\"%s\"}", sep, arg->key,
            arg->kind == ARG_INTEGER ? "integer" : "string");
    sep = ",";
  }
  fprintf(out, "%s\"session\":{\"type\":\"string\"}", sep);
  if(row->cls != MCP_READ) {
    fputs(",\"approval_id\":{\"type\":\"string\"},"
          "\"signature\":{\"type\":\"string\"}", out);
  }
  fputs("}", out);

  fputs(",\"required\":[", out);
  sep = "";
  for(arg = row->args; arg->key; arg++) {
    if(arg->required) {
      fprintf(out, "%s\"%s\"", sep, arg->key);
      sep = ",";
    }
  }
  fputs("]}", out);
}


void
mcp_write_tools(FILE *out) {
  const char *sep = "";
  size_t i;

  fputs("{\"tools\":[", out);
  for(i = 0; mcp_tools[i].name; i++) {
    int read_only = mcp_tools[i].cls == MCP_READ;

    fprintf(out, "%s{\"name\":\"%s\",\"description\":\"%s\",\"inputSchema\":",
            sep, mcp_tools[i].name, mcp_tools[i].description);
    write_schema(out, &mcp_tools[i]);
    fprintf(out, ",\"annotations\":{\"readOnlyHint\":%s,\"destructiveHint\":%s}}",
            read_only ? "true" : "false", read_only ? "false" : "true");
    sep = ",";
  }
  fputs("]}", out);
}
