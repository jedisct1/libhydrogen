WFLAGS ?= -Wall -Wextra -Wmissing-prototypes -Wdiv-by-zero -Wbad-function-cast -Wcast-align -Wcast-qual -Wfloat-equal -Wmissing-declarations -Wnested-externs -Wno-unknown-pragmas -Wpointer-arith -Wredundant-decls -Wstrict-prototypes -Wswitch-enum -Wno-type-limits
CFLAGS ?= -Os -fno-exceptions $(WFLAGS)
CFLAGS += -I.
OBJ = hydrogen.o
AR ?= ar
RANLIB ?= ranlib

SRC = \
	hydrogen.c \
	hydrogen.h \
	impl/common.h \
	impl/core.h \
	impl/hash.h \
	impl/hash128.h \
	impl/hydrogen_p.h \
	impl/kdf.h \
	impl/random.h \
	impl/secretbox.h \
	impl/sign.h \
	impl/stream.h \
	impl/x25519.h

all: lib

lib: libhydrogen.a

test: tests/tests
	rm -f tests/tests.done
	tests/tests && touch tests/tests.done

tests/tests: $(SRC) tests/tests.c
	$(CC) $(CFLAGS) -O3 -o tests/tests hydrogen.c tests/tests.c

$(OBJ): $(SRC)

libhydrogen.a: $(OBJ)
	$(AR) -r $@ $^
	$(RANLIB) $@

.PHONY: clean

clean:
	rm -f libhydrogen.a $(OBJ)
	rm -f tests/tests tests/*.done
	rm -f $(ARDUINO_PACKAGE)
