CC ?= gcc
CFLAGS ?= -Wall -Wextra -std=c11
CFLAGS += -DIPCSERVICE_STANDALONE
LDFLAGS ?=

TARGET := ipcservice_example
SOURCES := main.c standalone_nt.c

$(TARGET): $(SOURCES) ipcservice.c standalone_nt.h ntipcservice.h
	$(CC) $(CFLAGS) $(SOURCES) $(LDFLAGS) -o $@

.PHONY: clean
clean:
	rm -f $(TARGET)
