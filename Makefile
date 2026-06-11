CC ?= cc
CFLAGS ?= -O2 -g -Wall -Wextra -Wpedantic -std=c17
SODIUM_CFLAGS := $(shell pkg-config --cflags libsodium 2>/dev/null)
SODIUM_LIBS := $(shell pkg-config --libs libsodium 2>/dev/null)
CFLAGS += $(SODIUM_CFLAGS)
LDLIBS += $(SODIUM_LIBS)

ifeq ($(OS),Windows_NT)
LDLIBS += -lws2_32
endif

SRC := $(wildcard src/*.c)
OBJ := $(SRC:.c=.o)
BIN := file-transfer

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDLIBS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

test: $(BIN)
	bash tests/test_transfer.sh

clean:
	rm -f $(OBJ) $(BIN)

.PHONY: all clean test
