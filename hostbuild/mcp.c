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

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "mcp.h"

#define MCP_LINE_MAX 65536
#define MCP_DEPTH_MAX 32

enum mcp_class {
  MCP_READ,
  MCP_WRITE,
  MCP_EXEC
};

typedef struct {
  const char *name;
  const char *description;
  enum mcp_class cls;
} mcp_tool_t;

// The tool table is the whole surface. A NULL name ends it; it holds no rows
// yet, so tools/list answers an empty list.
static const mcp_tool_t mcp_tools[] = {
  { NULL, NULL, MCP_READ }
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
skip_number(cursor_t *c) {
  const char *start = c->p;

  while(c->p < c->end && *c->p && strchr("+-.0123456789eE", *c->p)) {
    c->p++;
  }
  return c->p == start ? -1 : 0;
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


static int
tool_is_known(const char *name, size_t len) {
  size_t i;

  for(i = 0; mcp_tools[i].name; i++) {
    if(strlen(mcp_tools[i].name) == len && !memcmp(mcp_tools[i].name, name, len)) {
      return 1;
    }
  }
  return 0;
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
handle(const char *text, const char *end, FILE *out, int *initialized) {
  const char *ids = NULL;
  const char *ide = NULL;
  const char *ms = NULL;
  const char *me = NULL;
  const char *ps = NULL;
  const char *pe = NULL;
  const char *ns = NULL;
  const char *ne = NULL;
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
    if(has_params != 1 ||
       object_member(ps, pe, "name", &ns, &ne, NULL) != 1 || !is_string(ns)) {
      write_error(out, ids, ide, -32602, "invalid params: name is required");
      return;
    }
    if(!tool_is_known(ns + 1, (size_t)(ne - ns - 2))) {
      write_error(out, ids, ide, -32602, "invalid params: unknown tool");
      return;
    }
    write_error(out, ids, ide, -32603, "internal error: no tool is implemented");
  } else {
    write_error(out, ids, ide, -32601, "method not found");
  }
}


int
mcp_serve(FILE *in, FILE *out) {
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
    handle(line, line + len, out, &initialized);
  }

  free(line);
  return 0;
}


void
mcp_write_tools(FILE *out) {
  const char *sep = "";
  size_t i;

  fputs("{\"tools\":[", out);
  for(i = 0; mcp_tools[i].name; i++) {
    int read_only = mcp_tools[i].cls == MCP_READ;

    fprintf(out, "%s{\"name\":\"%s\",\"description\":\"%s\","
            "\"inputSchema\":{\"type\":\"object\"},"
            "\"annotations\":{\"readOnlyHint\":%s,\"destructiveHint\":%s}}",
            sep, mcp_tools[i].name, mcp_tools[i].description,
            read_only ? "true" : "false", read_only ? "false" : "true");
    sep = ",";
  }
  fputs("]}", out);
}
