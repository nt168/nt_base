#ifndef EXAMPLE_NTIPCSERVICE_H
#define EXAMPLE_NTIPCSERVICE_H

#include "standalone_nt.h"

#define NT_IPC_PATH_MAX        sizeof(((struct sockaddr_un *)0)->sun_path)
#define NT_IPC_SOCKET_BUFFER_SIZE      4096
#define NT_IPC_RECV_IMMEDIATE  0
#define NT_IPC_RECV_WAIT       1
#define NT_IPC_RECV_TIMEOUT    2
#define NT_IPC_WAIT_FOREVER    -1

typedef struct
{
        nt_uint32_t    code;
        nt_uint32_t    size;
        unsigned char   *data;
} nt_ipc_message_t;

typedef struct
{
        int             fd;
        unsigned char   rx_buffer[NT_IPC_SOCKET_BUFFER_SIZE];
        nt_uint32_t    rx_buffer_bytes;
        nt_uint32_t    rx_buffer_offset;
} nt_ipc_socket_t;

typedef struct nt_ipc_client nt_ipc_client_t;

typedef struct
{
        int                             fd;
        struct event_base               *ev;
        struct event                    *ev_listener;
        struct event                    *ev_timer;
        struct event                    *ev_alert;
        char                            *path;
        nt_vector_ipc_client_ptr_t     clients;
        nt_queue_ptr_t                 clients_recv;
} nt_ipc_service_t;

typedef struct
{
        nt_ipc_client_t        *client;
        struct event_base       *ev;
        struct event            *ev_timer;
        unsigned char           state;
} nt_ipc_async_socket_t;

int     nt_ipc_service_init_env(const char *path, char **error);
void    nt_ipc_service_free_env(void);
int     nt_ipc_service_start(nt_ipc_service_t *service, const char *service_name, char **error);
int     nt_ipc_service_recv(nt_ipc_service_t *service, const nt_timespec_t *timeout, nt_ipc_client_t **client,
                nt_ipc_message_t **message);
void    nt_ipc_service_alert(nt_ipc_service_t *service);
void    nt_ipc_service_close(nt_ipc_service_t *service);

int     nt_ipc_client_send(nt_ipc_client_t *client, nt_uint32_t code, const unsigned char *data, nt_uint32_t size);
void    nt_ipc_client_close(nt_ipc_client_t *client);
int     nt_ipc_client_get_fd(nt_ipc_client_t *client);

void                    nt_ipc_client_addref(nt_ipc_client_t *client);
void                    nt_ipc_client_release(nt_ipc_client_t *client);
int                     nt_ipc_client_connected(nt_ipc_client_t *client);
nt_uint64_t            nt_ipc_client_id(const nt_ipc_client_t *client);
nt_ipc_client_t        *nt_ipc_client_by_id(const nt_ipc_service_t *service, nt_uint64_t id);
void    nt_ipc_client_set_userdata(nt_ipc_client_t *client, void *userdata);
void    *nt_ipc_client_get_userdata(nt_ipc_client_t *client);

int     nt_ipc_socket_open(nt_ipc_socket_t *csocket, const char *service_name, int timeout, char **error);
void    nt_ipc_socket_close(nt_ipc_socket_t *csocket);
int     nt_ipc_socket_write(nt_ipc_socket_t *csocket, nt_uint32_t code, const unsigned char *data,
                nt_uint32_t size);
int     nt_ipc_socket_read(nt_ipc_socket_t *csocket, nt_ipc_message_t *message);
int     nt_ipc_socket_connected(const nt_ipc_socket_t *csocket);

int     nt_ipc_async_socket_open(nt_ipc_async_socket_t *asocket, const char *service_name, int timeout, char **error);
void    nt_ipc_async_socket_close(nt_ipc_async_socket_t *asocket);
int     nt_ipc_async_socket_send(nt_ipc_async_socket_t *asocket, nt_uint32_t code, const unsigned char *data,
                nt_uint32_t size);
int     nt_ipc_async_socket_recv(nt_ipc_async_socket_t *asocket, int timeout, nt_ipc_message_t **message);
int     nt_ipc_async_socket_flush(nt_ipc_async_socket_t *asocket, int timeout);
int     nt_ipc_async_socket_check_unsent(nt_ipc_async_socket_t *asocket);
int     nt_ipc_async_socket_connected(nt_ipc_async_socket_t *asocket);
int     nt_ipc_async_exchange(const char *service_name, nt_uint32_t code, int timeout, const unsigned char *data,
                nt_uint32_t size, unsigned char **out, char **error);

void    nt_ipc_message_free(nt_ipc_message_t *message);
void    nt_ipc_message_clean(nt_ipc_message_t *message);
void    nt_ipc_message_init(nt_ipc_message_t *message);
void    nt_ipc_message_format(const nt_ipc_message_t *message, char **data);
void    nt_init_library_ipcservice(unsigned char program_type);

#endif
