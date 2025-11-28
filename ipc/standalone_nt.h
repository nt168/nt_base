#ifndef STANDALONE_NT_H
#define STANDALONE_NT_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <fcntl.h>
#include <time.h>
#include <sys/select.h>

#define HAVE_IPCSERVICE 1

#ifndef timeradd
#define timeradd(a, b, result) \
    do { \
        (result)->tv_sec = (a)->tv_sec + (b)->tv_sec; \
        (result)->tv_usec = (a)->tv_usec + (b)->tv_usec; \
        if ((result)->tv_usec >= 1000000) { \
            ++(result)->tv_sec; \
            (result)->tv_usec -= 1000000; \
        } \
    } while (0)
#endif

#ifndef timercmp
#define timercmp(a, b, CMP) \
    (((a)->tv_sec == (b)->tv_sec) ? \
        ((a)->tv_usec CMP (b)->tv_usec) : \
        ((a)->tv_sec CMP (b)->tv_sec))
#endif

#define NT_THREAD_LOCAL __thread
#define NT_CONST_STRLEN(str) (sizeof(str) - 1)

#define SUCCEED 0
#define FAIL    -1

#define LOG_LEVEL_DEBUG 4
#define LOG_LEVEL_WARNING 3
#define LOG_LEVEL_CRIT 2
#define LOG_LEVEL_ERR 1

#define NT_DEFAULT_PTR_COMPARE_FUNC NULL

#define NT_IPC_PATH_MAX sizeof(((struct sockaddr_un *)0)->sun_path)
#define NT_IPC_SOCKET_BUFFER_SIZE 4096
#define NT_IPC_RECV_IMMEDIATE 0
#define NT_IPC_RECV_WAIT 1
#define NT_IPC_RECV_TIMEOUT 2
#define NT_IPC_WAIT_FOREVER -1

typedef uint32_t nt_uint32_t;
typedef uint64_t nt_uint64_t;
typedef int64_t nt_int64_t;
typedef struct timespec nt_timespec_t;

typedef struct nt_queue_ptr_struct
{
    void **values;
    size_t alloc;
    size_t head;
    size_t tail;
} *nt_queue_ptr_t;

void nt_queue_ptr_create(nt_queue_ptr_t *queue);
void nt_queue_ptr_destroy(nt_queue_ptr_t *queue);
void nt_queue_ptr_push(nt_queue_ptr_t *queue, void *value);
void *nt_queue_ptr_pop(nt_queue_ptr_t *queue);
void *nt_queue_ptr_shift(nt_queue_ptr_t *queue);
int nt_queue_ptr_empty(nt_queue_ptr_t *queue);
size_t nt_queue_ptr_values_num(nt_queue_ptr_t *queue);
void nt_queue_ptr_remove_value(nt_queue_ptr_t *queue, void *value);

typedef struct
{
    void **values;
    size_t values_num;
    size_t alloc;
} nt_vector_ipc_client_ptr_t;

void nt_vector_ipc_client_ptr_create(nt_vector_ipc_client_ptr_t *vector);
void nt_vector_ipc_client_ptr_append(nt_vector_ipc_client_ptr_t *vector, void *value);
void nt_vector_ipc_client_ptr_remove_noorder(nt_vector_ipc_client_ptr_t *vector, size_t index);
int nt_vector_ipc_client_ptr_search(nt_vector_ipc_client_ptr_t *vector, void *value, int (*compare_func)(const void *, const void *));
void nt_vector_ipc_client_ptr_destroy(nt_vector_ipc_client_ptr_t *vector);

void *nt_malloc(void *ptr, size_t size);
void *nt_calloc(void *ptr, size_t count, size_t size);
void *nt_realloc(void *ptr, size_t size);
void nt_free(void *ptr);
char *nt_strdup(const char *ptr, const char *src);
char *nt_dsprintf(char *str, const char *fmt, ...);

size_t nt_strlcpy(char *dst, const char *src, size_t dstsize);
size_t nt_strlcat(char *dst, const char *src, size_t dstsize);
char *nt_strdcat(char *dst, const char *src, size_t *alloc);
const char *nt_strerror(int errnum);
char *nt_strcpy_alloc(char **dest, size_t *alloc, size_t *offset, const char *src);
int nt_snprintf_alloc(char **dest, size_t *alloc, size_t *offset, const char *fmt, ...);

int nt_timespec_sub(nt_timespec_t *result, const nt_timespec_t *left, const nt_timespec_t *right);
int nt_timespec_compare(const nt_timespec_t *left, const nt_timespec_t *right);

void nt_log(int level, const char *fmt, ...);

const char *nt_result_string(int ret);

static inline int nt_ptr_compare(const void *a, const void *b)
{
    return (a > b) - (a < b);
}

#define NT_MAX_UINT64 0xFFFFFFFFFFFFFFFFULL

typedef int evutil_socket_t;

typedef struct event_base event_base;

typedef struct event
{
    evutil_socket_t fd;
    short what;
    void (*cb_func)(int, short, void *);
    void *cb_arg;
    struct timeval timeout;
    int pending;
    int active;
    struct event_base *base;
} event;

struct timeval;

#define EV_TIMEOUT 0x01
#define EV_READ    0x02
#define EV_WRITE   0x04
#define EV_PERSIST 0x10
#define EVLOOP_ONCE    0x01
#define EVLOOP_NONBLOCK 0x02

struct event *event_new(struct event_base *ev, evutil_socket_t fd, short what,
                void(*cb_func)(int, short, void *), void *cb_arg);
int event_add(struct event *ev, const struct timeval *tv);
int event_del(struct event *ev);
void event_free(struct event *ev);

struct event_base *event_base_new(void);
void event_base_free(struct event_base *base);
int event_base_loop(struct event_base *base, int flags);
void event_set_log_callback(void (*cb)(int, const char *));
void event_set(struct event *ev, evutil_socket_t fd, short what, void (*cb_func)(int, short, void *), void *cb_arg);
void event_base_set(struct event_base *base, struct event *ev);
int evthread_use_pthreads(void);
int evthread_make_base_notifiable(struct event_base *base);
int evutil_make_socket_nonblocking(evutil_socket_t fd);
int event_active(struct event *ev, int res, short ncalls);

#endif
