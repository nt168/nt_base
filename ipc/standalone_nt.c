#include "standalone_nt.h"
#include <stdarg.h>

void *nt_malloc(void *ptr, size_t size)
{
    (void)ptr;
    void *out = malloc(size);
    if (NULL == out)
    {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    return out;
}

void *nt_calloc(void *ptr, size_t count, size_t size)
{
    (void)ptr;
    void *out = calloc(count, size);
    if (NULL == out)
    {
        perror("calloc");
        exit(EXIT_FAILURE);
    }
    return out;
}

void *nt_realloc(void *ptr, size_t size)
{
    void *out = realloc(ptr, size);
    if (NULL == out)
    {
        perror("realloc");
        exit(EXIT_FAILURE);
    }
    return out;
}

void nt_free(void *ptr)
{
    if (NULL != ptr)
        free(ptr);
}

char *nt_strdup(const char *ptr, const char *src)
{
    (void)ptr;
    size_t len = strlen(src) + 1;
    char *dst = (char *)nt_malloc(NULL, len);
    memcpy(dst, src, len);
    return dst;
}

char *nt_dsprintf(char *str, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(NULL, 0, fmt, args);
    va_end(args);

    if (len < 0)
        return NULL;

    char *buffer = (char *)nt_malloc(NULL, (size_t)len + 1);

    va_start(args, fmt);
    vsnprintf(buffer, (size_t)len + 1, fmt, args);
    va_end(args);

    nt_free(str);
    return buffer;
}

size_t nt_strlcpy(char *dst, const char *src, size_t dstsize)
{
    size_t srclen = strlen(src);
    if (dstsize)
    {
        size_t len = (srclen >= dstsize) ? dstsize - 1 : srclen;
        memcpy(dst, src, len);
        dst[len] = '\0';
    }
    return srclen;
}

size_t nt_strlcat(char *dst, const char *src, size_t dstsize)
{
    size_t dlen = strlen(dst);
    size_t slen = strlen(src);
    if (dlen < dstsize)
    {
        size_t copylen = ((dlen + slen) >= dstsize) ? dstsize - dlen - 1 : slen;
        memcpy(dst + dlen, src, copylen);
        dst[dlen + copylen] = '\0';
    }
    return dlen + slen;
}

char *nt_strdcat(char *dst, const char *src, size_t *alloc)
{
    size_t dstlen = (NULL == dst) ? 0 : strlen(dst);
    size_t srclen = strlen(src);
    size_t need = dstlen + srclen + 1;
    if (NULL == dst || *alloc < need)
    {
        size_t newalloc = need * 2;
        dst = realloc(dst, newalloc);
        if (NULL == dst)
        {
            perror("realloc");
            exit(EXIT_FAILURE);
        }
        *alloc = newalloc;
    }
    memcpy(dst + dstlen, src, srclen + 1);
    return dst;
}

int nt_timespec_sub(nt_timespec_t *result, const nt_timespec_t *left, const nt_timespec_t *right)
{
    result->tv_sec = left->tv_sec - right->tv_sec;
    result->tv_nsec = left->tv_nsec - right->tv_nsec;
    if (result->tv_nsec < 0)
    {
        result->tv_sec--;
        result->tv_nsec += 1000000000L;
    }
    return (result->tv_sec < 0 || (result->tv_sec == 0 && result->tv_nsec < 0)) ? FAIL : SUCCEED;
}

int nt_timespec_compare(const nt_timespec_t *left, const nt_timespec_t *right)
{
    if (left->tv_sec == right->tv_sec)
    {
        if (left->tv_nsec == right->tv_nsec)
            return 0;
        return left->tv_nsec > right->tv_nsec ? 1 : -1;
    }
    return left->tv_sec > right->tv_sec ? 1 : -1;
}

void nt_log(int level, const char *fmt, ...)
{
    (void)level;
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    fputc('\n', stderr);
    va_end(args);
}

const char *nt_result_string(int ret)
{
    return SUCCEED == ret ? "SUCCEED" : "FAIL";
}

const char *nt_strerror(int errnum)
{
    return strerror(errnum);
}

char *nt_strcpy_alloc(char **dest, size_t *alloc, size_t *offset, const char *src)
{
    size_t len = strlen(src);

    if (*alloc < *offset + len + 1)
    {
        *alloc = (*offset + len + 1) * 2;
        *dest = nt_realloc(*dest, *alloc);
    }

    memcpy(*dest + *offset, src, len + 1);
    *offset += len;

    return *dest;
}

int nt_snprintf_alloc(char **dest, size_t *alloc, size_t *offset, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    int needed = vsnprintf(NULL, 0, fmt, args);
    va_end(args);

    if (needed < 0)
        return FAIL;

    size_t required = (size_t)needed + 1;

    if (*alloc < *offset + required)
    {
        *alloc = (*offset + required) * 2;
        *dest = nt_realloc(*dest, *alloc);
    }

    va_start(args, fmt);
    vsnprintf(*dest + *offset, *alloc - *offset, fmt, args);
    va_end(args);

    *offset += (size_t)needed;
    return SUCCEED;
}

/* queue helpers */
static void queue_grow(nt_queue_ptr_t queue)
{
    if (queue->alloc == 0)
    {
        queue->alloc = 8;
        queue->values = calloc(queue->alloc, sizeof(void *));
    }
    else if ((queue->tail + 1) % queue->alloc == queue->head)
    {
        size_t newalloc = queue->alloc * 2;
        void **newvalues = calloc(newalloc, sizeof(void *));
        for (size_t i = 0; i < queue->alloc - 1; i++)
            newvalues[i] = queue->values[(queue->head + i) % queue->alloc];
        free(queue->values);
        queue->values = newvalues;
        queue->head = 0;
        queue->tail = queue->alloc - 1;
        queue->alloc = newalloc;
    }
}

void nt_queue_ptr_create(nt_queue_ptr_t *queue)
{
    *queue = calloc(1, sizeof(**queue));
}

void nt_queue_ptr_destroy(nt_queue_ptr_t *queue)
{
    if (NULL == queue || NULL == *queue)
        return;
    free((*queue)->values);
    free(*queue);
    *queue = NULL;
}

void nt_queue_ptr_push(nt_queue_ptr_t *queue, void *value)
{
    if (NULL == *queue)
        nt_queue_ptr_create(queue);
    queue_grow(*queue);
    (*queue)->values[(*queue)->tail] = value;
    (*queue)->tail = ((*queue)->tail + 1) % (*queue)->alloc;
}

void *nt_queue_ptr_pop(nt_queue_ptr_t *queue)
{
    if (NULL == *queue || (*queue)->head == (*queue)->tail)
        return NULL;
    void *value = (*queue)->values[(*queue)->head];
    (*queue)->head = ((*queue)->head + 1) % (*queue)->alloc;
    return value;
}

void *nt_queue_ptr_shift(nt_queue_ptr_t *queue)
{
    return nt_queue_ptr_pop(queue);
}

int nt_queue_ptr_empty(nt_queue_ptr_t *queue)
{
    return (NULL == *queue || (*queue)->head == (*queue)->tail) ? SUCCEED : FAIL;
}

size_t nt_queue_ptr_values_num(nt_queue_ptr_t *queue)
{
    if (NULL == *queue)
        return 0;
    if ((*queue)->tail >= (*queue)->head)
        return (*queue)->tail - (*queue)->head;
    return (*queue)->alloc - ((*queue)->head - (*queue)->tail);
}

void nt_queue_ptr_remove_value(nt_queue_ptr_t *queue, void *value)
{
    if (NULL == *queue)
        return;
    size_t count = nt_queue_ptr_values_num(queue);
    nt_queue_ptr_t tmp;
    nt_queue_ptr_create(&tmp);
    for (size_t i = 0; i < count; i++)
    {
        void *item = nt_queue_ptr_pop(queue);
        if (item != value)
            nt_queue_ptr_push(&tmp, item);
    }
    free((*queue)->values);
    **queue = *tmp;
    free(tmp);
}

/* vector helpers */
void nt_vector_ipc_client_ptr_create(nt_vector_ipc_client_ptr_t *vector)
{
    vector->values = NULL;
    vector->values_num = 0;
    vector->alloc = 0;
}

void nt_vector_ipc_client_ptr_append(nt_vector_ipc_client_ptr_t *vector, void *value)
{
    if (vector->values_num == vector->alloc)
    {
        size_t newalloc = (0 == vector->alloc) ? 4 : vector->alloc * 2;
        vector->values = realloc(vector->values, newalloc * sizeof(void *));
        if (NULL == vector->values)
        {
            perror("realloc");
            exit(EXIT_FAILURE);
        }
        vector->alloc = newalloc;
    }
    vector->values[vector->values_num++] = value;
}

void nt_vector_ipc_client_ptr_remove_noorder(nt_vector_ipc_client_ptr_t *vector, size_t index)
{
    if (index < vector->values_num)
    {
        vector->values[index] = vector->values[vector->values_num - 1];
        vector->values_num--;
    }
}

int nt_vector_ipc_client_ptr_search(nt_vector_ipc_client_ptr_t *vector, void *value, int (*compare_func)(const void *, const void *))
{
    if (NULL == compare_func)
        compare_func = nt_ptr_compare;
    for (size_t i = 0; i < vector->values_num; i++)
    {
        if (0 == compare_func(vector->values[i], value))
            return (int)i;
    }
    return FAIL;
}

void nt_vector_ipc_client_ptr_destroy(nt_vector_ipc_client_ptr_t *vector)
{
    free(vector->values);
    vector->values = NULL;
    vector->values_num = vector->alloc = 0;
}

/* libevent style minimal implementation */
struct event_base
{
    struct event   **events;
    size_t          events_num;
    size_t          alloc;
    int             break_loop;
};

static void     event_base_resize(struct event_base *base)
{
    if (base->events_num < base->alloc)
        return;

    base->alloc = 0 == base->alloc ? 8 : base->alloc * 2;
    base->events = nt_realloc(base->events, base->alloc * sizeof(struct event *));
}

struct event *event_new(struct event_base *ev, evutil_socket_t fd, short what,
                void(*cb_func)(int, short, void *), void *cb_arg)
{
    struct event    *event = (struct event *)nt_malloc(NULL, sizeof(struct event));

    memset(event, 0, sizeof(struct event));
    event->fd = fd;
    event->what = what;
    event->cb_func = cb_func;
    event->cb_arg = cb_arg;
    event->base = ev;

    return event;
}

void event_set(struct event *ev, evutil_socket_t fd, short what, void (*cb_func)(int, short, void *), void *cb_arg)
{
    ev->fd = fd;
    ev->what = what;
    ev->cb_func = cb_func;
    ev->cb_arg = cb_arg;
}

void event_base_set(struct event_base *base, struct event *ev)
{
    ev->base = base;
}

static void     event_base_add(struct event_base *base, struct event *ev)
{
    for (size_t i = 0; i < base->events_num; i++)
    {
        if (base->events[i] == ev)
            return;
    }

    event_base_resize(base);
    base->events[base->events_num++] = ev;
}

int event_add(struct event *ev, const struct timeval *tv)
{
    if (NULL == ev->base)
        return FAIL;

    if (NULL != tv)
    {
        struct timeval now;

        gettimeofday(&now, NULL);
        timeradd(&now, tv, &ev->timeout);
        ev->what |= EV_TIMEOUT;
        ev->pending = 1;
    }

    event_base_add(ev->base, ev);
    return SUCCEED;
}

static void     event_base_remove(struct event_base *base, struct event *ev)
{
    for (size_t i = 0; i < base->events_num; i++)
    {
        if (base->events[i] == ev)
        {
            base->events[i] = base->events[base->events_num - 1];
            base->events_num--;
            return;
        }
    }
}

int event_del(struct event *ev)
{
    if (NULL == ev->base)
        return FAIL;

    event_base_remove(ev->base, ev);
    ev->pending = 0;
    return SUCCEED;
}

void event_free(struct event *ev)
{
    if (NULL != ev->base)
        event_del(ev);
    nt_free(ev);
}

struct event_base *event_base_new(void)
{
    return nt_calloc(NULL, 1, sizeof(struct event_base));
}

void event_base_free(struct event_base *base)
{
    nt_free(base->events);
    nt_free(base);
}

static void     event_dispatch_ready(struct event *ev, short what)
{
    if (NULL != ev->cb_func)
        ev->cb_func(ev->fd, what, ev->cb_arg);
}

static void     event_process_timeouts(struct event_base *base)
{
    struct timeval now;

    gettimeofday(&now, NULL);

    for (size_t i = 0; i < base->events_num; i++)
    {
        struct event *ev = base->events[i];

        if (0 == ev->pending)
            continue;

        if (timercmp(&now, &ev->timeout, >=))
        {
            event_dispatch_ready(ev, EV_TIMEOUT);

            if (0 == (ev->what & EV_PERSIST))
            {
                event_del(ev);
                i--;
            }
            else
            {
                ev->pending = 0;
            }
        }
    }
}

int event_base_loop(struct event_base *base, int flags)
{
    int once = (0 != (flags & EVLOOP_ONCE));
    int nonblock = (0 != (flags & EVLOOP_NONBLOCK));

    base->break_loop = 0;

    do
    {
        fd_set  readfds, writefds;
        int     maxfd = -1;
        struct timeval timeout, *pto = NULL;

        FD_ZERO(&readfds);
        FD_ZERO(&writefds);

        if (0 == nonblock)
        {
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;
            pto = &timeout;
        }
        else
        {
            timeout.tv_sec = timeout.tv_usec = 0;
            pto = &timeout;
        }

        for (size_t i = 0; i < base->events_num; i++)
        {
            struct event *ev = base->events[i];

            if ((ev->what & EV_READ) && ev->fd >= 0)
            {
                FD_SET(ev->fd, &readfds);
                if (ev->fd > maxfd)
                    maxfd = ev->fd;
            }

            if ((ev->what & EV_WRITE) && ev->fd >= 0)
            {
                FD_SET(ev->fd, &writefds);
                if (ev->fd > maxfd)
                    maxfd = ev->fd;
            }
        }

        int ret = select(maxfd + 1, &readfds, &writefds, NULL, pto);

        if (ret < 0)
        {
            if (EINTR == errno)
                continue;
            return ret;
        }

        for (size_t i = 0; i < base->events_num; i++)
        {
            struct event *ev = base->events[i];
            short ready = 0;

            if ((ev->what & EV_READ) && FD_ISSET(ev->fd, &readfds))
                ready |= EV_READ;
            if ((ev->what & EV_WRITE) && FD_ISSET(ev->fd, &writefds))
                ready |= EV_WRITE;

            if (0 != ready)
            {
                event_dispatch_ready(ev, ready);

                if (0 == (ev->what & EV_PERSIST))
                {
                    event_del(ev);
                    i--;
                }
            }
        }

        event_process_timeouts(base);

        if (once)
            break;
    }
    while (0 == base->break_loop);

    return 0;
}

void event_set_log_callback(void (*cb)(int, const char *))
{
    (void)cb;
}

int evthread_use_pthreads(void)
{
    return 0;
}

int evthread_make_base_notifiable(struct event_base *base)
{
    (void)base; return 0;
}

int evutil_make_socket_nonblocking(evutil_socket_t fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int event_active(struct event *ev, int res, short ncalls)
{
    (void)ncalls;
    event_dispatch_ready(ev, (short)res);
    return 0;
}
