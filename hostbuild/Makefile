# Host build of Ariel: the agent port tracer.

CC ?= cc
CFLAGS ?= -Wall -Wextra -Werror -O2 -std=c11 -D_POSIX_C_SOURCE=200809L
CFLAGS += -pthread -I.. -DARIEL_HOST_BUILD=1
LDLIBS += -pthread

BIN  := ariel-host
SIGNER := ariel-sign
CANONICAL_TEST := canonical_test

# The platform port, the agent protocol, the store and the token are shared
# with the PS5 build, so they live at the repository root.
SHARED_SRCS := ../agent.c ../agent_server.c ../store.c ../token.c \
               ../approval.c
SHARED_OBJS := $(notdir $(SHARED_SRCS:.c=.o))

SRCS := main.c platform_host.c vcontroller.c testclock.c
OBJS := $(SRCS:.c=.o) $(SHARED_OBJS) sha256.o tweetnacl.o

all: $(BIN) $(SIGNER) $(CANONICAL_TEST)

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

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

clean:
	rm -f $(OBJS) $(BIN) signer.o approval_signer.o $(SIGNER) \
	      $(CANONICAL_TEST)

test: $(BIN) $(SIGNER) $(CANONICAL_TEST)
	./$(CANONICAL_TEST)
	python3 tests/acceptance.py ./$(BIN)

.PHONY: all clean test
