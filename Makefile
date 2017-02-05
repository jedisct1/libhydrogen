WFLAGS ?= -Wall -Wextra -Wmissing-prototypes -Wdiv-by-zero -Wbad-function-cast -Wcast-align -Wcast-qual -Wfloat-equal -Wmissing-declarations -Wnested-externs -Wno-unknown-pragmas -Wpointer-arith -Wredundant-decls -Wstrict-prototypes -Wswitch-enum -Wno-type-limits
CFLAGS ?= -Os -fno-exceptions -ffunction-sections -fdata-sections -flto $(WFLAGS)
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
	impl/random.h \
	impl/secretbox.h \
	impl/stream.h

all: lib

lib: libhydrogen.a

$(OBJ): $(SRC)

libhydrogen.a: $(OBJ)
	$(AR) -r $@ $^
	$(RANLIB) $@

.PHONY: clean

clean:
	rm -f libhydrogen.a $(OBJ)
	rm -f tests/tests
	rm -f $(ARDUINO_PACKAGE)
