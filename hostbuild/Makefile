# Host build of Ariel: the agent port tracer.

CC ?= cc
CFLAGS ?= -Wall -Wextra -Werror -O2 -std=c11 -D_POSIX_C_SOURCE=200809L
CFLAGS += -pthread -I.. -DARIEL_HOST_BUILD=1
LDLIBS += -pthread

BIN  := ariel-host

# The platform port, the agent protocol, the store and the token are shared
# with the PS5 build, so they live at the repository root.
SHARED_SRCS := ../agent.c ../agent_server.c ../store.c ../token.c
SHARED_OBJS := $(notdir $(SHARED_SRCS:.c=.o))

SRCS := main.c platform_host.c vcontroller.c testclock.c
OBJS := $(SRCS:.c=.o) $(SHARED_OBJS) sha256.o

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(SHARED_OBJS): %.o: ../%.c
	$(CC) $(CFLAGS) -c -o $@ $<

# SHA-256 is vendored at the repository root and shared with the PS5 build.
sha256.o: ../sha256.c ../sha256.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(BIN)

test: $(BIN)
	python3 tests/acceptance.py ./$(BIN)

.PHONY: all clean test
