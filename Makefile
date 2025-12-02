CC := gcc
SRCS := common.c fatal.c nt_log.c nt_mutexs.c nt_phreads.c nt_base.c version.c

WARNINGS := -Wall -Wextra
CSTD := -std=c11

CPPFLAGS := -I.
CFLAGS := $(CSTD) $(WARNINGS) -pthread
LDFLAGS := -pthread

#CONFIG ?= Release
CONFIG ?= Debug
BUILD_ROOT ?= build
BUILD_ROOT := $(abspath $(BUILD_ROOT))
OUT_DIR := $(BUILD_ROOT)/$(CONFIG)

ifeq ($(CONFIG),Debug)
  CFLAGS += -g -O0 -DDEBUG
else
  CFLAGS += -O2
endif

TARGET := $(OUT_DIR)/nt_base
LIB := $(OUT_DIR)/libnt.a
OBJECTS := $(addprefix $(OUT_DIR)/,$(SRCS:.c=.o))
LIB_OBJECTS := $(filter-out $(OUT_DIR)/nt_base.o,$(OBJECTS))

.PHONY: all clean comms

all: $(TARGET) comms

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

$(OUT_DIR)/%.o: %.c | $(OUT_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(LIB): $(LIB_OBJECTS)
	ar rcs $@ $^

$(TARGET): $(LIB) $(OUT_DIR)/nt_base.o
	$(CC) $(CFLAGS) $(OUT_DIR)/nt_base.o $(LIB) -o $@

comms: $(OUT_DIR)
	$(MAKE) -C comms BUILD_ROOT=$(BUILD_ROOT) CONFIG=$(CONFIG)

clean:
	rm -rf $(BUILD_ROOT)
