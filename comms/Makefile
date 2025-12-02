CC      := gcc
WARNINGS := -Wall -Wextra
CSTD    := -std=c11

CONFIG ?= Release
BUILD_ROOT ?= $(abspath ../build)
OUT_DIR := $(BUILD_ROOT)/$(CONFIG)/comms

CPPFLAGS := -I. -I..
CFLAGS  := $(CSTD) $(WARNINGS) -pthread
LDFLAGS := -lpthread

ifeq ($(CONFIG),Debug)
  CFLAGS += -g -O0 -DDEBUG
else
  CFLAGS += -O2
endif

TARGET  := $(OUT_DIR)/comms

# comms 子目录里的源码
COMMS_SRCS := \
    base64.c \
    comms.c  \
    crypto.c \
    ip.c     \
    md5.c    \
    nt_hash.c \
    nt_num.c \
    nt_str.c \
    nt_time.c \
    iprange.c \
    misc.c    \
    compress.c \
    endian.c   \
    common_log.c \
    common_str.c \
    components_strings_representations.c \
    sha256crypto.c

# 上级 nt_base 中需要的基础组件（提供 nt_log / nt_malloc / 线程与锁等）
NT_BASE_SRCS := \
    ../common.c \
    ../fatal.c  \
    ../nt_log.c \
    ../nt_mutexs.c \
    ../nt_phreads.c

SRCS := $(COMMS_SRCS) $(NT_BASE_SRCS) main.c
OBJS := $(addprefix $(OUT_DIR)/,$(notdir $(SRCS:.c=.o)))

VPATH := . ..

.PHONY: all clean

all: $(TARGET)

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

$(TARGET): $(OBJS) | $(OUT_DIR)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

$(OUT_DIR)/%.o: %.c | $(OUT_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(OUT_DIR)/%.o: ../%.c | $(OUT_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_ROOT)
