# SE050 VCOM Library Makefile
# Builds shared library for Python ctypes bindings

CC = gcc
CFLAGS = -Wall -Wextra -fPIC -O2
LDFLAGS = -shared
LIBS = -lmbedcrypto -lmbedtls -lmbedx509

# Target shared library
TARGET = libse050.so.1.0
SONAME = libse050.so.1
LINKNAME = libse050.so

# Source files
SRCS = se050_vcom.c
OBJS = $(SRCS:.c=.o)

# Header files
HEADERS = se050_scp03.h

.PHONY: all clean test install

all: $(TARGET)
	ln -sf $(TARGET) $(SONAME)
	ln -sf $(TARGET) $(LINKNAME)
	@echo ""
	@echo "Build complete: $(LINKNAME) -> $(TARGET)"
	@echo ""

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -Wl,-soname,$(SONAME) -o $@ $^ $(LIBS)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# Build test program
test_vcom: test_vcom.c $(TARGET)
	$(CC) -Wall -O2 -o $@ $< -L. -lse050 -Wl,-rpath,. $(LIBS)

# Run test
test: test_vcom
	./test_vcom

# Install to system (optional)
install: $(TARGET)
	install -d /usr/local/lib
	install -m 755 $(TARGET) /usr/local/lib/
	install -d /usr/local/include
	install -m 644 $(HEADERS) /usr/local/include/
	ldconfig

# Clean build artifacts
clean:
	rm -f $(OBJS) $(TARGET) $(SONAME) $(LINKNAME) test_vcom

# Debug build
debug: CFLAGS += -g -DDEBUG
debug: clean all

# Show library symbols
symbols: $(TARGET)
	nm -D $(TARGET) | grep -E "^[0-9a-f]+ T"
