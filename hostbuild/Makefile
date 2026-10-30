# Host build of Ariel: the agent port tracer.

CC ?= cc
CFLAGS ?= -Wall -Wextra -Werror -O2 -std=c11 -D_POSIX_C_SOURCE=200809L
CFLAGS += -pthread -I.. -I. -DARIEL_HOST_BUILD=1
LDLIBS += -pthread

BIN  := ariel-host
MCP  := ariel-mcp
SIGNER := ariel-sign
CANONICAL_TEST := canonical_test
TITLE_PART_TEST := title_part_test

# The platform port, the agent protocol, the store and the token are shared
# with the PS5 build, so they live at the repository root.
SHARED_SRCS := ../agent.c ../agent_server.c ../store.c ../state.c \
               ../token.c ../approval.c ../runner.c ../answer.c ../diagnostics.c \
               ../protected.c ../addon.c \
               ../runs.c ../fileops.c ../autoload.c ../zip.c ../tar.c \
               ../http.c ../allowlist.c ../release.c ../json.c
SHARED_OBJS := $(notdir $(SHARED_SRCS:.c=.o))

SRCS := main.c platform_host.c readers_host.c vcontroller.c testclock.c
OBJS := $(SRCS:.c=.o) $(SHARED_OBJS) sha256.o tweetnacl.o

all: $(BIN) $(MCP) $(SIGNER) $(CANONICAL_TEST) $(TITLE_PART_TEST)

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

# The MCP server holds no key and carries no ARIEL_PUBKEY (ADR-0017). Its
# serverInfo.version is the newest release tag, read the same way the tests read it.
MCP_OBJS := mcp_main.o mcp.o mcp_link.o sha256.o
MCP_VERSION := $(or $(patsubst v%,%,$(shell git tag --list 'v[0-9]*' --sort=-v:refname 2>/dev/null | head -n 1)),0.0.0-unversioned)
$(MCP): $(MCP_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(MCP_OBJS) $(LDLIBS)

mcp.o: mcp.c mcp.h
	$(CC) $(CFLAGS) -DMCP_SERVER_VERSION=\"$(MCP_VERSION)\" -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(SHARED_OBJS): %.o: ../%.c
	$(CC) $(CFLAGS) -c -o $@ $<

# SHA-256 is vendored at the repository root and shared with the PS5 build.
sha256.o: ../sha256.c ../sha256.h
	$(CC) $(CFLAGS) -c -o $@ $<

# TweetNaCl is vendored unmodified at the repository root and shared with
# the PS5 build. It is third-party code written to a different warning
# standard, so it is built without warnings of its own.
tweetnacl.o: ../tweetnacl.c ../tweetnacl.h
	$(CC) $(CFLAGS) -w -c -o $@ $<

# The offline signer is a separate program: it makes keys, which needs a
# random source the server never has, so it compiles the approval code with
# ARIEL_SIGNER and brings its own.
signer.o: ../signer.c ../approval.h ../sha256.h ../tweetnacl.h
	$(CC) $(CFLAGS) -c -o $@ $<

approval_signer.o: ../approval.c ../approval.h ../tweetnacl.h
	$(CC) $(CFLAGS) -DARIEL_SIGNER -c -o $@ $<

$(SIGNER): signer.o approval_signer.o sha256.o tweetnacl.o
	$(CC) $(LDFLAGS) -o $@ $^

# The encoder's own tests, with the ambiguous inputs it must refuse.
$(CANONICAL_TEST): tests/canonical_test.c approval.o tweetnacl.o
	$(CC) $(CFLAGS) -o $@ $^

# The install part of each finding, read from the runner the host build links.
$(TITLE_PART_TEST): tests/title_part_test.c $(filter-out main.o,$(OBJS))
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f $(OBJS) $(BIN) signer.o approval_signer.o $(SIGNER) \
	      $(CANONICAL_TEST) $(TITLE_PART_TEST) $(MCP) $(MCP_OBJS)

test: $(BIN) $(MCP) $(SIGNER) $(CANONICAL_TEST) $(TITLE_PART_TEST)
	./$(CANONICAL_TEST)
	./$(TITLE_PART_TEST)
	sh tests/deploy_guard.sh
	sh ../tools/install/test-install.sh
	python3 tests/acceptance.py ./$(BIN)
	python3 tests/mcp_acceptance.py ./$(MCP) ./$(BIN)
	python3 tests/release_workflow_acceptance.py ./$(MCP)

.PHONY: all clean test
