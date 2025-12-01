CC      := gcc
CFLAGS  := -Wall -Wextra -g -O2 -I. -I..
LDFLAGS := -lpthread

TARGET  := main

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

OBJS := $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

../%.o: ../%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
