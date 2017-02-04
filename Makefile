TARGET_DEVICE = atmega2560
HWTYPE = HYDRO_TARGET_DEVICE_ATMEGA328
AR = avr-ar
CC = avr-gcc
RANLIB = avr-ranlib
WFLAGS = -Wall -Wextra -Wmissing-prototypes -Wdiv-by-zero -Wbad-function-cast -Wcast-align -Wcast-qual -Wfloat-equal -Wmissing-declarations -Wnested-externs -Wno-unknown-pragmas -Wpointer-arith -Wredundant-decls -Wstrict-prototypes -Wswitch-enum -Wno-type-limits
CFLAGS = -I. -mmcu=$(TARGET_DEVICE) -DHYDRO_HWTYPE=$(HYDRO_HWTYPE) -Os -mcall-prologues $(WFLAGS)
OBJ = hydrogen.o
ARDUINO_PACKAGE = hydrogen-crypto.zip
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

all: package
	7z a -tzip -mx=9 -r ${1}.zip $1

package: $(ARDUINO_PACKAGE)

$(ARDUINO_PACKAGE):
	7z a -tzip -mx=9 -r $(ARDUINO_PACKAGE) $(SRC)

lib: libhydrogen.a

$(OBJ): $(SRC)

libhydrogen.a: $(OBJ)
	$(AR) -ar cr $@ $^
	$(RANLIB) $@

.PHONY: clean

clean:
	rm -f libhydrogen.a $(OBJ)
	rm -f tests/tests
	rm -f $(ARDUINO_PACKAGE)
