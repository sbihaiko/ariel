# Host build of Ariel: the agent port tracer.

CC ?= cc
CFLAGS ?= -Wall -Wextra -Werror -O2 -std=c11 -D_POSIX_C_SOURCE=200809L
CFLAGS += -pthread -I..
LDLIBS += -pthread

BIN  := ariel-host
SRCS := main.c platform_host.c token.c agent.c vcontroller.c store.c
OBJS := $(SRCS:.c=.o) sha256.o

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# SHA-256 is vendored at the repository root and shared with the PS5 build.
sha256.o: ../sha256.c ../sha256.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(BIN)

test: $(BIN)
	python3 tests/acceptance.py ./$(BIN)

.PHONY: all clean test
