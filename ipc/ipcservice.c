/*
** Copyright (C) 2001-2025 Nt SIA
**
** This program is free software: you can redistribute it and/or modify it under the terms of
** the GNU Affero General Public License as published by the Free Software Foundation, version 3.
**
** This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
** without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
** See the GNU Affero General Public License for more details.
**
** You should have received a copy of the GNU Affero General Public License along with this program.
** If not, see <https://www.gnu.org/licenses/>.
**/

#ifdef IPCSERVICE_STANDALONE
#include "standalone_nt.h"
#else
#include "ntcommon.h"
#endif

#ifdef HAVE_IPCSERVICE

#ifdef HAVE_LIBEVENT
#	include <event2/event.h>
#	include <event2/thread.h>
#	include <event2/util.h>
#endif

#include "ntipcservice.h"
#include "ntalgo.h"
#include "ntstr.h"
#include "nttime.h"

#define NT_IPC_DATA_DUMP_SIZE		128

static char	ipc_path[NT_IPC_PATH_MAX] = {0};
static size_t	ipc_path_root_len = 0;

#define NT_IPC_CLIENT_STATE_NONE	0
#define NT_IPC_CLIENT_STATE_QUEUED	1

#define NT_IPC_ASYNC_SOCKET_STATE_NONE		0
#define NT_IPC_ASYNC_SOCKET_STATE_TIMEOUT	1
#define NT_IPC_ASYNC_SOCKET_STATE_ERROR	2

/* IPC client, providing nonblocking connections through socket */
struct nt_ipc_client
{
	nt_ipc_socket_t	csocket;
	nt_ipc_service_t	*service;

	nt_uint32_t		rx_header[2];
	unsigned char		*rx_data;
	nt_uint32_t		rx_bytes;
	nt_queue_ptr_t		rx_queue;
	struct event		*rx_event;

	nt_uint32_t		tx_header[2];
	unsigned char		*tx_data;
	nt_uint32_t		tx_bytes;
	nt_queue_ptr_t		tx_queue;
	struct event		*tx_event;

	nt_uint64_t		id;
	unsigned char		state;

	void			*userdata;

	nt_uint32_t		refcount;
};

NT_PTR_VECTOR_IMPL(ipc_client_ptr, nt_ipc_client_t *)

/*
 * Private API
 */

#define NT_IPC_HEADER_SIZE	(int)(sizeof(nt_uint32_t) * 2)

#define NT_IPC_MESSAGE_CODE	0
#define NT_IPC_MESSAGE_SIZE	1

#if !defined(LIBEVENT_VERSION_NUMBER) || LIBEVENT_VERSION_NUMBER < 0x2000000
typedef int evutil_socket_t;

static struct event	*event_new(struct event_base *ev, evutil_socket_t fd, short what,
		void(*cb_func)(int, short, void *), void *cb_arg)
{
	struct event	*event;

	event = nt_malloc(NULL, sizeof(struct event));
	event_set(event, fd, what, cb_func, cb_arg);
	event_base_set(ev, event);

	return event;
}

static void	event_free(struct event *event)
{
	event_del(event);
	nt_free(event);
}

#endif

static void	ipc_client_read_event_cb(evutil_socket_t fd, short what, void *arg);
static void	ipc_client_write_event_cb(evutil_socket_t fd, short what, void *arg);

static const char	*ipc_get_path(void)
{
	ipc_path[ipc_path_root_len] = '\0';

	return ipc_path;
}

#define NT_IPC_SOCKET_PREFIX	"/nt_"
#define NT_IPC_SOCKET_SUFFIX	".sock"

#define NT_IPC_CLASS_PREFIX_NONE	""
#define NT_IPC_CLASS_PREFIX_SERVER	"server_"
#define NT_IPC_CLASS_PREFIX_PROXY	"proxy_"
#define NT_IPC_CLASS_PREFIX_AGENT	"agent_"

static const char	*ipc_path_prefix = NT_IPC_CLASS_PREFIX_NONE;
static size_t		ipc_path_prefix_len = NT_CONST_STRLEN(NT_IPC_CLASS_PREFIX_NONE);

/******************************************************************************
 *                                                                            *
 * Purpose: makes socket path from the service name                           *
 *                                                                            *
 * Parameters: service_name - [IN] the service name                           *
 *             error        - [OUT] the error message                         *
 *                                                                            *
 * Return value: The created path or NULL if the path exceeds unix domain     *
 *               socket path maximum length                                   *
 *                                                                            *
 ******************************************************************************/
static const char	*ipc_make_path(const char *service_name, char **error)
{
	size_t				path_len, offset;
	static NT_THREAD_LOCAL char	ipc_path_full[NT_IPC_PATH_MAX];

	path_len = strlen(service_name);

	if (NT_IPC_PATH_MAX < ipc_path_root_len + path_len + 1 + NT_CONST_STRLEN(NT_IPC_SOCKET_PREFIX) +
			NT_CONST_STRLEN(NT_IPC_SOCKET_SUFFIX) + ipc_path_prefix_len)
	{
		*error = nt_dsprintf(*error,
				"Socket path \"%s%s%s%s%s\" exceeds maximum length of unix domain socket path.",
				ipc_path, NT_IPC_SOCKET_PREFIX, ipc_path_prefix, service_name, NT_IPC_SOCKET_SUFFIX);
		return NULL;
	}

	memcpy(ipc_path_full, ipc_path, ipc_path_root_len);
	offset = ipc_path_root_len;
	memcpy(ipc_path_full + offset, NT_IPC_SOCKET_PREFIX, NT_CONST_STRLEN(NT_IPC_SOCKET_PREFIX));
	offset += NT_CONST_STRLEN(NT_IPC_SOCKET_PREFIX);
	memcpy(ipc_path_full + offset, ipc_path_prefix, ipc_path_prefix_len);
	offset += ipc_path_prefix_len;
	memcpy(ipc_path_full + offset, service_name, path_len);
	offset += path_len;
	memcpy(ipc_path_full + offset, NT_IPC_SOCKET_SUFFIX, NT_CONST_STRLEN(NT_IPC_SOCKET_SUFFIX) + 1);

	return ipc_path_full;
}

/******************************************************************************
 *                                                                            *
 * Purpose: writes data to a socket                                           *
 *                                                                            *
 * Parameters: fd        - [IN] the socket file descriptor                    *
 *             data      - [IN] the data                                      *
 *             size      - [IN] the data size                                 *
 *             size_sent - [IN] the actual size written to socket             *
 *                                                                            *
 * Return value: SUCCEED - no socket errors were detected. Either the data or *
 *                         a part of it was written to socket or a write to   *
 *                         non-blocking socket would block                    *
 *               FAIL    - otherwise                                          *
 *                                                                            *
 ******************************************************************************/
static int	ipc_write_data(int fd, const unsigned char *data, nt_uint32_t size, nt_uint32_t *size_sent)
{
	nt_uint32_t	offset = 0;
	int		ret = SUCCEED;
	ssize_t		n;

	while (offset != size)
	{
		n = write(fd, data + offset, size - offset);

		if (-1 == n)
		{
			if (EINTR == errno)
				continue;

			if (EWOULDBLOCK == errno || EAGAIN == errno)
				break;

			nt_log(LOG_LEVEL_WARNING, "cannot write to IPC socket: %s", strerror(errno));
			ret = FAIL;
			break;
		}

		offset += n;
	}

	*size_sent = offset;

	return ret;
}

/******************************************************************************
 *                                                                            *
 * Purpose: reads data from a socket                                          *
 *                                                                            *
 * Parameters: fd        - [IN] the socket file descriptor                    *
 *             data      - [IN] the data                                      *
 *             size      - [IN] the data size                                 *
 *             size_sent - [IN] the actual size read from socket              *
 *                                                                            *
 * Return value: SUCCEED - the data was successfully read                     *
 *               FAIL    - otherwise                                          *
 *                                                                            *
 * Comments: When reading data from non-blocking sockets SUCCEED will be      *
 *           returned also if there were no more data to read.                *
 *                                                                            *
 ******************************************************************************/
static int	ipc_read_data(int fd, unsigned char *buffer, nt_uint32_t size, nt_uint32_t *read_size)
{
	int	n;

	*read_size = 0;

	while (-1 == (n = read(fd, buffer + *read_size, size - *read_size)))
	{
		if (EINTR == errno)
			continue;

		if (EWOULDBLOCK == errno || EAGAIN == errno)
			return SUCCEED;

		return FAIL;
	}

	if (0 == n)
		return FAIL;

	*read_size += n;

	return SUCCEED;
}

/******************************************************************************
 *                                                                            *
 * Purpose: reads data from a socket until the requested data has been read   *
 *                                                                            *
 * Parameters: fd        - [IN] the socket file descriptor                    *
 *             buffer    - [IN] the data                                      *
 *             size      - [IN] the data size                                 *
 *             read_size - [IN] the actual size read from socket              *
 *                                                                            *
 * Return value: SUCCEED - the data was successfully read                     *
 *               FAIL    - otherwise                                          *
 *                                                                            *
 * Comments: When reading data from non-blocking sockets this function will   *
 *           return SUCCEED if there are no data to read, even if not all of  *
 *           the requested data has been read.                                *
 *                                                                            *
 ******************************************************************************/
static int	ipc_read_data_full(int fd, unsigned char *buffer, nt_uint32_t size, nt_uint32_t *read_size)
{
	int		ret = FAIL;
	nt_uint32_t	offset = 0, chunk_size;

	*read_size = 0;

	while (offset < size)
	{
		if (FAIL == ipc_read_data(fd, buffer + offset, size - offset, &chunk_size))
			goto out;

		if (0 == chunk_size)
			break;

		offset += chunk_size;
	}

	ret = SUCCEED;
out:
	*read_size = offset;

	return ret;
}

/******************************************************************************
 *                                                                            *
 * Purpose: writes IPC message to socket                                      *
 *                                                                            *
 * Parameters: csocket - [IN] the IPC socket                                  *
 *             code    - [IN] the message code                                *
 *             data    - [IN] the data                                        *
 *             size    - [IN] the data size                                   *
 *             tx_size - [IN] the actual size written to socket               *
 *                                                                            *
 * Return value: SUCCEED - no socket errors were detected. Either the data or *
 *                         a part of it was written to socket or a write to   *
 *                         non-blocking socket would block                    *
 *               FAIL    - otherwise                                          *
 *                                                                            *
 * Comments: When using non-blocking sockets the tx_size parameter must be    *
 *           checked in addition to return value to tell if the message was   *
 *           sent successfully.                                               *
 *                                                                            *
 ******************************************************************************/
static int	ipc_socket_write_message(nt_ipc_socket_t *csocket, nt_uint32_t code, const unsigned char *data,
		nt_uint32_t size, nt_uint32_t *tx_size)
{
	int		ret;
	nt_uint32_t	size_data, buffer[NT_IPC_SOCKET_BUFFER_SIZE / sizeof(nt_uint32_t)];

	buffer[0] = code;
	buffer[1] = size;

	if (NT_IPC_SOCKET_BUFFER_SIZE - NT_IPC_HEADER_SIZE >= size)
	{
		if (0 != size)
			memcpy(buffer + 2, data, size);

		return ipc_write_data(csocket->fd, (unsigned char *)buffer, size + NT_IPC_HEADER_SIZE, tx_size);
	}

	if (FAIL == ipc_write_data(csocket->fd, (unsigned char *)buffer, NT_IPC_HEADER_SIZE, tx_size))
		return FAIL;

	/* in the case of non-blocking sockets only a part of the header might be sent */
	if (NT_IPC_HEADER_SIZE != *tx_size)
		return SUCCEED;

	ret = ipc_write_data(csocket->fd, data, size, &size_data);
	*tx_size += size_data;

	return ret;
}

/******************************************************************************
 *                                                                            *
 * Purpose: reads message header and data from buffer                         *
 *                                                                            *
 * Parameters: header      - [IN/OUT] the message header                      *
 *             data        - [OUT] the message data                           *
 *             rx_bytes    - [IN] the number of bytes stored in message       *
 *                                (including header)                          *
 *             buffer      - [IN] the buffer to parse                         *
 *             size        - [IN] the number of bytes to parse                *
 *             read_size   - [OUT] the number of bytes read                   *
 *                                                                            *
 * Return value: SUCCEED - message was successfully parsed                    *
 *               FAIL - not enough data                                       *
 *                                                                            *
 ******************************************************************************/
static int	ipc_read_buffer(nt_uint32_t *header, unsigned char **data, nt_uint32_t rx_bytes,
		const unsigned char *buffer, nt_uint32_t size, nt_uint32_t *read_size)
{
	nt_uint32_t	copy_size, data_size, data_offset;

	*read_size = 0;

	if (NT_IPC_HEADER_SIZE > rx_bytes)
	{
		copy_size = MIN(NT_IPC_HEADER_SIZE - rx_bytes, size);
		memcpy((char *)header + rx_bytes, buffer, copy_size);
		*read_size += copy_size;

		if (NT_IPC_HEADER_SIZE > rx_bytes + copy_size)
			return FAIL;

		data_size = header[NT_IPC_MESSAGE_SIZE];

		if (0 == data_size)
		{
			*data = NULL;
			return SUCCEED;
		}

		*data = (unsigned char *)nt_malloc(NULL, data_size);
		data_offset = 0;
	}
	else
	{
		data_size = header[NT_IPC_MESSAGE_SIZE];
		data_offset = rx_bytes - NT_IPC_HEADER_SIZE;
	}

	copy_size = MIN(data_size - data_offset, size - *read_size);
	memcpy(*data + data_offset, buffer + *read_size, copy_size);
	*read_size += copy_size;

	return (rx_bytes + *read_size == data_size + NT_IPC_HEADER_SIZE ? SUCCEED : FAIL);
}

/******************************************************************************
 *                                                                            *
 * Purpose: checks if IPC message has been completed                          *
 *                                                                            *
 * Parameters: header   - [IN] the message header                             *
 *             rx_bytes - [IN] the number of bytes set in message             *
 *                             (including header)                             *
 *                                                                            *
 * Return value:  SUCCEED - message has been completed                        *
 *                FAIL - otherwise                                            *
 *                                                                            *
 ******************************************************************************/
static int	ipc_message_is_completed(const nt_uint32_t *header, nt_uint32_t rx_bytes)
{
	if (NT_IPC_HEADER_SIZE > rx_bytes)
		return FAIL;

	if (header[NT_IPC_MESSAGE_SIZE] + NT_IPC_HEADER_SIZE != rx_bytes)
		return FAIL;

	return SUCCEED;
}

/******************************************************************************
 *                                                                            *
 * Purpose: reads IPC message from buffered client socket                     *
 *                                                                            *
 * Parameters: csocket  - [IN] the source socket                              *
 *             header   - [OUT] the header of the message                     *
 *             data     - [OUT] the data of the message                       *
 *             rx_bytes - [IN/OUT] the total message size read (including     *
 *                                 header                                     *
 *                                                                            *
 * Return value:  SUCCEED - data was read successfully, check rx_bytes to     *
 *                          determine if the message was completed.           *
 *                FAIL - failed to read message (socket error or connection   *
 *                       was closed).                                         *
 *                                                                            *
 ******************************************************************************/
static int	ipc_socket_read_message(nt_ipc_socket_t *csocket, nt_uint32_t *header, unsigned char **data,
		nt_uint32_t *rx_bytes)
{
	nt_uint32_t	data_size, offset, read_size = 0;
	int		ret = FAIL;

	/* try to read message from socket buffer */
	if (csocket->rx_buffer_bytes > csocket->rx_buffer_offset)
	{
		ret = ipc_read_buffer(header, data, *rx_bytes, csocket->rx_buffer + csocket->rx_buffer_offset,
				csocket->rx_buffer_bytes - csocket->rx_buffer_offset, &read_size);

		csocket->rx_buffer_offset += read_size;
		*rx_bytes += read_size;

		if (SUCCEED == ret)
			goto out;
	}

	/* not enough data in socket buffer, try to read more until message is completed or no data to read */
	while (SUCCEED != ret)
	{
		csocket->rx_buffer_offset = 0;
		csocket->rx_buffer_bytes = 0;

		if (NT_IPC_HEADER_SIZE < *rx_bytes)
		{
			offset = *rx_bytes - NT_IPC_HEADER_SIZE;
			data_size = header[NT_IPC_MESSAGE_SIZE] - offset;

			/* long messages will be read directly into message buffer */
			if (NT_IPC_SOCKET_BUFFER_SIZE * 0.75 < data_size)
			{
				ret = ipc_read_data_full(csocket->fd, *data + offset, data_size, &read_size);
				*rx_bytes += read_size;
				goto out;
			}
		}

		if (FAIL == ipc_read_data(csocket->fd, csocket->rx_buffer, NT_IPC_SOCKET_BUFFER_SIZE, &read_size))
			goto out;

		/* it's possible that nothing will be read on non-blocking sockets, return success */
		if (0 == read_size)
		{
			ret = SUCCEED;
			goto out;
		}

		csocket->rx_buffer_bytes = read_size;

		ret = ipc_read_buffer(header, data, *rx_bytes, csocket->rx_buffer, csocket->rx_buffer_bytes,
				&read_size);

		csocket->rx_buffer_offset += read_size;
		*rx_bytes += read_size;
	}
out:
	return ret;
}

/******************************************************************************
 *                                                                            *
 * Purpose: frees client's libevent event                                     *
 *                                                                            *
 * Parameters: client - [IN] the client                                       *
 *                                                                            *
 ******************************************************************************/
static void	ipc_client_free_events(nt_ipc_client_t *client)
{
	if (NULL != client->rx_event)
	{
		event_free(client->rx_event);
		client->rx_event = NULL;
	}

	if (NULL != client->tx_event)
	{
		event_free(client->tx_event);
		client->tx_event = NULL;
	}
}

/******************************************************************************
 *                                                                            *
 * Purpose: frees IPC service client                                          *
 *                                                                            *
 * Parameters: client - [IN] the client to free                               *
 *                                                                            *
 ******************************************************************************/
static void	ipc_client_free(nt_ipc_client_t *client)
{
	nt_ipc_message_t	*message;

	nt_log(LOG_LEVEL_TRACE, "In %s() clientid:" NT_FS_UI64, __func__, client->id);

	ipc_client_free_events(client);
	nt_ipc_socket_close(&client->csocket);

	while (NULL != (message = (nt_ipc_message_t *)nt_queue_ptr_pop(&client->rx_queue)))
		nt_ipc_message_free(message);

	nt_queue_ptr_destroy(&client->rx_queue);
	nt_free(client->rx_data);

	while (NULL != (message = (nt_ipc_message_t *)nt_queue_ptr_pop(&client->tx_queue)))
		nt_ipc_message_free(message);

	nt_queue_ptr_destroy(&client->tx_queue);
	nt_free(client->tx_data);

	ipc_client_free_events(client);

	nt_free(client);

	nt_log(LOG_LEVEL_TRACE, "End of %s()", __func__);
}

/******************************************************************************
 *                                                                            *
 * Purpose: adds message to received messages queue                           *
 *                                                                            *
 * Parameters: client - [IN] the client to read                               *
 *                                                                            *
 ******************************************************************************/
static void	ipc_client_push_rx_message(nt_ipc_client_t *client)
{
	nt_ipc_message_t	*message;

	message = (nt_ipc_message_t *)nt_malloc(NULL, sizeof(nt_ipc_message_t));
	message->code = client->rx_header[NT_IPC_MESSAGE_CODE];
	message->size = client->rx_header[NT_IPC_MESSAGE_SIZE];
	message->data = client->rx_data;
	nt_queue_ptr_push(&client->rx_queue, message);

	client->rx_data = NULL;
	client->rx_bytes = 0;
}

/******************************************************************************
 *                                                                            *
 * Purpose: prepares to send the next message in send queue                   *
 *                                                                            *
 * Parameters: client - [IN] the client                                       *
 *                                                                            *
 ******************************************************************************/
static void	ipc_client_pop_tx_message(nt_ipc_client_t *client)
{
	nt_ipc_message_t	*message;

	nt_free(client->tx_data);
	client->tx_bytes = 0;

	if (NULL == (message = (nt_ipc_message_t *)nt_queue_ptr_pop(&client->tx_queue)))
		return;

	client->tx_bytes = NT_IPC_HEADER_SIZE + message->size;
	client->tx_header[NT_IPC_MESSAGE_CODE] = message->code;
	client->tx_header[NT_IPC_MESSAGE_SIZE] = message->size;
	client->tx_data = message->data;
	nt_free(message);
}

/******************************************************************************
 *                                                                            *
 * Purpose: reads data from IPC service client                                *
 *                                                                            *
 * Parameters: client - [IN] the client to read                               *
 *                                                                            *
 * Return value:  FAIL - read error/connection was closed                     *
 *                                                                            *
 * Comments: This function reads data from socket, parses it and adds         *
 *           parsed messages to received messages queue.                      *
 *                                                                            *
 ******************************************************************************/
static int	ipc_client_read(nt_ipc_client_t *client)
{
	int	rc;

	do
	{
		if (FAIL == ipc_socket_read_message(&client->csocket, client->rx_header, &client->rx_data,
				&client->rx_bytes))
		{
			nt_free(client->rx_data);
			client->rx_bytes = 0;
			return FAIL;
		}

		if (SUCCEED == (rc = ipc_message_is_completed(client->rx_header, client->rx_bytes)))
			ipc_client_push_rx_message(client);
	}

	while (SUCCEED == rc);

	return SUCCEED;
}

/******************************************************************************
 *                                                                            *
 * Purpose: writes queued data to IPC service client                          *
 *                                                                            *
 * Parameters: client - [IN] the client                                       *
 *                                                                            *
 * Return value: SUCCEED - the data was sent successfully                     *
 *               FAIL    - otherwise                                          *
 *                                                                            *
 ******************************************************************************/
static int	ipc_client_write(nt_ipc_client_t *client)
{
	nt_uint32_t	data_size, write_size;

	data_size = client->tx_header[NT_IPC_MESSAGE_SIZE];

	if (data_size < client->tx_bytes)
	{
		nt_uint32_t	size, offset;

		size = client->tx_bytes - data_size;
		offset = NT_IPC_HEADER_SIZE - size;

		if (SUCCEED != ipc_write_data(client->csocket.fd, (unsigned char *)client->tx_header + offset, size,
				&write_size))
		{
			return FAIL;
		}

		client->tx_bytes -= write_size;

		if (data_size < client->tx_bytes)
			return SUCCEED;
	}

	while (0 < client->tx_bytes)
	{
		if (SUCCEED != ipc_write_data(client->csocket.fd, client->tx_data + data_size - client->tx_bytes,
				client->tx_bytes, &write_size))
		{
			return FAIL;
		}

		if (0 == write_size)
			return SUCCEED;

		client->tx_bytes -= write_size;
	}

	if (0 == client->tx_bytes)
		ipc_client_pop_tx_message(client);

	return SUCCEED;
}

/******************************************************************************
 *                                                                            *
 * Purpose: gets the next client with messages/closed socket from recv queue  *
 *                                                                            *
 * Parameters: service - [IN] the IPC service                                 *
 *                                                                            *
 * Return value: The client with messages/closed socket                       *
 *                                                                            *
 ******************************************************************************/
static nt_ipc_client_t	*ipc_service_pop_client(nt_ipc_service_t *service)
{
	nt_ipc_client_t	*client;

	if (NULL != (client = (nt_ipc_client_t *)nt_queue_ptr_pop(&service->clients_recv)))
		client->state = NT_IPC_CLIENT_STATE_NONE;

	return client;
}

/******************************************************************************
 *                                                                            *
 * Purpose: pushes client to the recv queue if needed                         *
 *                                                                            *
 * Parameters: service - [IN] the IPC service                                 *
 *             client  - [IN] the IPC client                                  *
 *                                                                            *
 * Comments: The client is pushed to the recv queue if it isn't already there *
 *           and there is messages to return or the client connection was     *
 *           closed.                                                          *
 *                                                                            *
 ******************************************************************************/
static void	ipc_service_push_client(nt_ipc_service_t *service, nt_ipc_client_t *client)
{
	if (NT_IPC_CLIENT_STATE_QUEUED == client->state)
		return;

	if (0 == nt_queue_ptr_values_num(&client->rx_queue) && NULL != client->rx_event)
		return;

	client->state = NT_IPC_CLIENT_STATE_QUEUED;
	nt_queue_ptr_push(&service->clients_recv, client);
}

/******************************************************************************
 *                                                                            *
 * Purpose: adds a new IPC service client                                     *
 *                                                                            *
 * Parameters: service - [IN] the IPC service                                 *
 *             fd      - [IN] the client socket descriptor                    *
 *                                                                            *
 ******************************************************************************/
static void	ipc_service_add_client(nt_ipc_service_t *service, int fd)
{
	static nt_uint64_t	next_clientid = 1;
	nt_ipc_client_t	*client;
	int			flags;

	nt_log(LOG_LEVEL_DEBUG, "In %s()", __func__);

	client = (nt_ipc_client_t *)nt_malloc(NULL, sizeof(nt_ipc_client_t));
	memset(client, 0, sizeof(nt_ipc_client_t));

	if (-1 == (flags = fcntl(fd, F_GETFL, 0)))
	{
		nt_log(LOG_LEVEL_CRIT, "cannot get IPC client socket flags");
		exit(EXIT_FAILURE);
	}

	if (-1 == fcntl(fd, F_SETFL, flags | O_NONBLOCK))
	{
		nt_log(LOG_LEVEL_CRIT, "cannot set non-blocking mode for IPC client socket");
		exit(EXIT_FAILURE);
	}

	client->csocket.fd = fd;
	client->csocket.rx_buffer_bytes = 0;
	client->csocket.rx_buffer_offset = 0;
	client->id = next_clientid++;
	client->state = NT_IPC_CLIENT_STATE_NONE;
	client->refcount = 1;

	nt_queue_ptr_create(&client->rx_queue);
	nt_queue_ptr_create(&client->tx_queue);

	client->service = service;
	client->rx_event = event_new(service->ev, fd, EV_READ | EV_PERSIST, ipc_client_read_event_cb, (void *)client);
	client->tx_event = event_new(service->ev, fd, EV_WRITE | EV_PERSIST, ipc_client_write_event_cb, (void *)client);
	event_add(client->rx_event, NULL);

	nt_vector_ipc_client_ptr_append(&service->clients, client);

	nt_log(LOG_LEVEL_DEBUG, "End of %s() clientid:" NT_FS_UI64, __func__, client->id);
}

/******************************************************************************
 *                                                                            *
 * Purpose: removes IPC service client                                        *
 *                                                                            *
 * Parameters: service - [IN] the IPC service                                 *
 *             client  - [IN] the client to remove                            *
 *                                                                            *
 ******************************************************************************/
static void	ipc_service_remove_client(nt_ipc_service_t *service, nt_ipc_client_t *client)
{
	for (int i = 0; i < service->clients.values_num; i++)
	{
		if (service->clients.values[i] == client)
			nt_vector_ipc_client_ptr_remove_noorder(&service->clients, i);
	}
}

/******************************************************************************
 *                                                                            *
 * Purpose: to find connected client when only it's ID is known               *
 *                                                                            *
 * Parameters: service - [IN] the IPC service                                 *
 *             id      - [IN] ID of client                                    *
 *                                                                            *
 * Return value: address of client or NULL if client has already disconnected *
 *                                                                            *
 ******************************************************************************/
nt_ipc_client_t	*nt_ipc_client_by_id(const nt_ipc_service_t *service, nt_uint64_t id)
{
	nt_ipc_client_t	*client;

	for (int i = 0; i < service->clients.values_num; i++)
	{
		client = service->clients.values[i];

		if (id == client->id)
			return client;
	}

	return NULL;
}

/******************************************************************************
 *                                                                            *
 * Purpose: service client read event libevent callback                       *
 *                                                                            *
 ******************************************************************************/
static void	ipc_client_read_event_cb(evutil_socket_t fd, short what, void *arg)
{
	nt_ipc_client_t	*client = (nt_ipc_client_t *)arg;

	NT_UNUSED(fd);
	NT_UNUSED(what);

	if (SUCCEED != ipc_client_read(client))
	{
		ipc_client_free_events(client);
		ipc_service_remove_client(client->service, client);
	}

	ipc_service_push_client(client->service, client);
}

/******************************************************************************
 *                                                                            *
 * Purpose: service client write event libevent callback                      *
 *                                                                            *
 ******************************************************************************/
static void	ipc_client_write_event_cb(evutil_socket_t fd, short what, void *arg)
{
	nt_ipc_client_t	*client = (nt_ipc_client_t *)arg;

	NT_UNUSED(fd);
	NT_UNUSED(what);

	if (SUCCEED != ipc_client_write(client))
	{
		nt_log(LOG_LEVEL_CRIT, "cannot send data to IPC client");
		nt_ipc_client_close(client);
		return;
	}

	if (0 == client->tx_bytes)
		event_del(client->tx_event);
}

/******************************************************************************
 *                                                                            *
 * Purpose: asynchronous socket write event libevent callback                 *
 *                                                                            *
 ******************************************************************************/
static void	ipc_async_socket_write_event_cb(evutil_socket_t fd, short what, void *arg)
{
	nt_ipc_async_socket_t	*asocket = (nt_ipc_async_socket_t *)arg;

	NT_UNUSED(fd);
	NT_UNUSED(what);

	if (SUCCEED != ipc_client_write(asocket->client))
	{
		nt_log(LOG_LEVEL_CRIT, "cannot send data to IPC client");
		ipc_client_free_events(asocket->client);
		nt_ipc_socket_close(&asocket->client->csocket);
		asocket->state = NT_IPC_ASYNC_SOCKET_STATE_ERROR;
		return;
	}

	if (0 == asocket->client->tx_bytes)
		event_del(asocket->client->tx_event);
}

/******************************************************************************
 *                                                                            *
 * Purpose: asynchronous socket read event libevent callback                  *
 *                                                                            *
 ******************************************************************************/
static void	ipc_async_socket_read_event_cb(evutil_socket_t fd, short what, void *arg)
{
	nt_ipc_async_socket_t	*asocket = (nt_ipc_async_socket_t *)arg;

	NT_UNUSED(fd);
	NT_UNUSED(what);

	if (SUCCEED != ipc_client_read(asocket->client))
	{
		ipc_client_free_events(asocket->client);
		asocket->state = NT_IPC_ASYNC_SOCKET_STATE_ERROR;
	}
}

/******************************************************************************
 *                                                                            *
 * Purpose: timer callback                                                    *
 *                                                                            *
 ******************************************************************************/
static void	ipc_async_socket_timer_cb(evutil_socket_t fd, short what, void *arg)
{
	nt_ipc_async_socket_t	*asocket = (nt_ipc_async_socket_t *)arg;

	NT_UNUSED(fd);
	NT_UNUSED(what);

	asocket->state = NT_IPC_ASYNC_SOCKET_STATE_TIMEOUT;
}

/******************************************************************************
 *                                                                            *
 * Purpose: accepts a new client connection                                   *
 *                                                                            *
 * Parameters: service - [IN] the IPC service                                 *
 *                                                                            *
 ******************************************************************************/
static void	ipc_service_accept(nt_ipc_service_t *service)
{
	int	fd;

	nt_log(LOG_LEVEL_DEBUG, "In %s()", __func__);

	while (-1 == (fd = accept(service->fd, NULL, NULL)))
	{
		if (EINTR != errno)
		{
			/* If there is unaccepted connection libevent will call registered callback function over and */
			/* over again. It is better to exit straight away and cause all other processes to stop. */
			nt_log(LOG_LEVEL_CRIT, "cannot accept incoming IPC connection: %s", nt_strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	ipc_service_add_client(service, fd);

	nt_log(LOG_LEVEL_DEBUG, "End of %s()", __func__);
}

/******************************************************************************
 *                                                                            *
 * Purpose: creates IPC message                                               *
 *                                                                            *
 * Parameters: code    - [IN] the message code                                *
 *             data    - [IN] the data                                        *
 *             size    - [IN] the data size                                   *
 *                                                                            *
 * Return value: The created message.                                         *
 *                                                                            *
 ******************************************************************************/
static nt_ipc_message_t	*ipc_message_create(nt_uint32_t code, const unsigned char *data, nt_uint32_t size)
{
	nt_ipc_message_t	*message;

	message = (nt_ipc_message_t *)nt_malloc(NULL, sizeof(nt_ipc_message_t));

	message->code = code;
	message->size = size;

	if (0 != size)
	{
		message->data = (unsigned char *)nt_malloc(NULL, size);
		memcpy(message->data, data, size);
	}
	else
		message->data = NULL;

	return message;
}

/******************************************************************************
 *                                                                            *
 * Purpose: libevent logging callback                                         *
 *                                                                            *
 ******************************************************************************/
static void ipc_service_event_log_cb(int severity, const char *msg)
{
	int	loglevel;

	switch (severity)
	{
		case _EVENT_LOG_DEBUG:
			loglevel = LOG_LEVEL_TRACE;
			break;
		case _EVENT_LOG_MSG:
			loglevel = LOG_LEVEL_DEBUG;
			break;
		case _EVENT_LOG_WARN:
			loglevel = LOG_LEVEL_WARNING;
			break;
		case _EVENT_LOG_ERR:
			loglevel = LOG_LEVEL_DEBUG;
			break;
		default:
			loglevel = LOG_LEVEL_DEBUG;
			break;
	}

	nt_log(loglevel, "IPC service: %s", msg);
}

/******************************************************************************
 *                                                                            *
 * Purpose: initialize libevent library                                       *
 *                                                                            *
 ******************************************************************************/
static void	ipc_service_init_libevent(void)
{
	event_set_log_callback(ipc_service_event_log_cb);
}

/******************************************************************************
 *                                                                            *
 * Purpose: uninitialize libevent library                                     *
 *                                                                            *
 ******************************************************************************/
static void	ipc_service_free_libevent(void)
{
}

/******************************************************************************
 *                                                                            *
 * Purpose: libevent listener callback                                        *
 *                                                                            *
 ******************************************************************************/
static void	ipc_service_client_connected_cb(evutil_socket_t fd, short what, void *arg)
{
	nt_ipc_service_t	*service = (nt_ipc_service_t *)arg;

	NT_UNUSED(fd);
	NT_UNUSED(what);

	ipc_service_accept(service);
}

/******************************************************************************
 *                                                                            *
 * Purpose: timer callback                                                    *
 *                                                                            *
 ******************************************************************************/
static void	ipc_service_timer_cb(evutil_socket_t fd, short what, void *arg)
{
	NT_UNUSED(fd);
	NT_UNUSED(what);
	NT_UNUSED(arg);
}

/******************************************************************************
 *                                                                            *
 * Purpose: checks if an IPC service is already running                       *
 *                                                                            *
 * Parameters: service_name - [IN]                                            *
 *                                                                            *
 ******************************************************************************/
static int	ipc_check_running_service(const char *service_name)
{
	nt_ipc_socket_t	csocket;
	int			ret;
	char			*error = NULL;

	if (SUCCEED == (ret = nt_ipc_socket_open(&csocket, service_name, 0, &error)))
		nt_ipc_socket_close(&csocket);
	else
		nt_free(error);

	return ret;
}

/*
 * Public client API
 */

/******************************************************************************
 *                                                                            *
 * Purpose: opens socket to an IPC service listening on the specified path    *
 *                                                                            *
 * Parameters: csocket      - [OUT] the IPC socket to the service             *
 *             service_name - [IN] the IPC service name                       *
 *             timeout      - [IN] the connection timeout                     *
 *             error        - [OUT] the error message                         *
 *                                                                            *
 * Return value: SUCCEED - the socket was successfully opened                 *
 *               FAIL    - otherwise                                          *
 *                                                                            *
 ******************************************************************************/
int	nt_ipc_socket_open(nt_ipc_socket_t *csocket, const char *service_name, int timeout, char **error)
{
	struct sockaddr_un	addr;
	time_t			start;
	struct timespec		ts = {0, 100000000};
	const char		*socket_path;
	int			ret = FAIL;

	nt_log(LOG_LEVEL_DEBUG, "In %s()", __func__);

	if (NULL == (socket_path = ipc_make_path(service_name, error)))
		goto out;

	if (-1 == (csocket->fd = socket(AF_UNIX, SOCK_STREAM, 0)))
	{
		*error = nt_dsprintf(*error, "Cannot create client socket: %s.", nt_strerror(errno));
		goto out;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, socket_path, sizeof(addr.sun_path));

	start = time(NULL);

	while (0 != connect(csocket->fd, (struct sockaddr*)&addr, sizeof(addr)))
	{
		if (0 == timeout || time(NULL) - start > timeout)
		{
			*error = nt_dsprintf(*error, "Cannot connect to service \"%s\": %s.", service_name,
					nt_strerror(errno));
			close(csocket->fd);
			goto out;
		}

		nanosleep(&ts, NULL);
	}

	csocket->rx_buffer_bytes = 0;
	csocket->rx_buffer_offset = 0;

	ret = SUCCEED;
out:
	nt_log(LOG_LEVEL_DEBUG, "End of %s():%s", __func__, nt_result_string(ret));
	return ret;
}

/******************************************************************************
 *                                                                            *
 * Purpose: closes socket to an IPC service                                   *
 *                                                                            *
 * Parameters: csocket - [IN/OUT] the IPC socket to close                     *
 *                                                                            *
 ******************************************************************************/
void	nt_ipc_socket_close(nt_ipc_socket_t *csocket)
{
	nt_log(LOG_LEVEL_DEBUG, "In %s()", __func__);

	if (-1 != csocket->fd)
	{
		close(csocket->fd);
		csocket->fd = -1;
	}

	nt_log(LOG_LEVEL_DEBUG, "End of %s()", __func__);
}

/******************************************************************************
 *                                                                            *
 * Purpose: writes a message to IPC service                                   *
 *                                                                            *
 * Parameters: csocket - [IN] an opened IPC socket to the service             *
 *             code    - [IN] the message code                                *
 *             data    - [IN] the data                                        *
 *             size    - [IN] the data size                                   *
 *                                                                            *
 * Return value: SUCCEED - the message was successfully written               *
 *               FAIL    - otherwise                                          *
 *                                                                            *
 ******************************************************************************/
int	nt_ipc_socket_write(nt_ipc_socket_t *csocket, nt_uint32_t code, const unsigned char *data, nt_uint32_t size)
{
	int		ret;
	nt_uint32_t	size_sent;

	nt_log(LOG_LEVEL_DEBUG, "In %s()", __func__);

	if (SUCCEED == ipc_socket_write_message(csocket, code, data, size, &size_sent) &&
			size_sent == size + NT_IPC_HEADER_SIZE)
	{
		ret = SUCCEED;
	}
	else
		ret = FAIL;

	nt_log(LOG_LEVEL_DEBUG, "End of %s():%s", __func__, nt_result_string(ret));

	return ret;
}

/******************************************************************************
 *                                                                            *
 * Purpose: reads a message from IPC service                                  *
 *                                                                            *
 * Parameters: csocket - [IN] an opened IPC socket to the service             *
 *             message - [OUT] the received message                           *
 *                                                                            *
 * Return value: SUCCEED - the message was successfully received              *
 *               FAIL    - otherwise                                          *
 *                                                                            *
 * Comments: If this function succeeds the message must be cleaned/freed by   *
 *           the caller.                                                      *
 *                                                                            *
 ******************************************************************************/
int	nt_ipc_socket_read(nt_ipc_socket_t *csocket, nt_ipc_message_t *message)
{
	int		ret = FAIL;
	nt_uint32_t	rx_bytes = 0, header[2];
	unsigned char	*data = NULL;

	nt_log(LOG_LEVEL_DEBUG, "In %s()", __func__);

	if (SUCCEED != ipc_socket_read_message(csocket, header, &data, &rx_bytes))
		goto out;

	if (SUCCEED != ipc_message_is_completed(header, rx_bytes))
	{
		nt_free(data);
		goto out;
	}

	message->code = header[NT_IPC_MESSAGE_CODE];
	message->size = header[NT_IPC_MESSAGE_SIZE];
	message->data = data;

	if (SUCCEED == NT_CHECK_LOG_LEVEL(LOG_LEVEL_TRACE))
	{
		char	*msg = NULL;

		nt_ipc_message_format(message, &msg);

		nt_log(LOG_LEVEL_DEBUG, "%s() %s", __func__, msg);

		nt_free(msg);
	}

	ret = SUCCEED;
out:
	nt_log(LOG_LEVEL_DEBUG, "End of %s():%s", __func__, nt_result_string(ret));

	return ret;
}

/******************************************************************************
 *                                                                            *
 * Purpose: check if socket is opened                                         *
 *                                                                            *
 * Parameters: csocket      - [OUT] the IPC socket to the service             *
 *                                                                            *
 * Return value: SUCCEED - the socket was successfully opened                 *
 *               FAIL    - otherwise                                          *
 *                                                                            *
 ******************************************************************************/
int	nt_ipc_socket_connected(const nt_ipc_socket_t *csocket)
{
	return 0 < csocket->fd ? SUCCEED : FAIL;
}

/******************************************************************************
 *                                                                            *
 * Purpose: frees the resources allocated to store IPC message data           *
 *                                                                            *
 * Parameters: message - [IN] the message to free                             *
 *                                                                            *
 ******************************************************************************/
void	nt_ipc_message_free(nt_ipc_message_t *message)
{
	if (NULL != message)
	{
		nt_free(message->data);
		nt_free(message);
	}
}

/******************************************************************************
 *                                                                            *
 * Purpose: frees the resources allocated to store IPC message data           *
 *                                                                            *
 * Parameters: message - [IN] the message to clean                            *
 *                                                                            *
 ******************************************************************************/
void	nt_ipc_message_clean(nt_ipc_message_t *message)
{
	nt_free(message->data);
}

/******************************************************************************
 *                                                                            *
 * Purpose: initializes IPC message                                           *
 *                                                                            *
 * Parameters: message - [IN] the message to initialize                       *
 *                                                                            *
 ******************************************************************************/
void	nt_ipc_message_init(nt_ipc_message_t *message)
{
	memset(message, 0, sizeof(nt_ipc_message_t));
}

/******************************************************************************
 *                                                                            *
 * Purpose: formats message to readable format for debug messages             *
 *                                                                            *
 * Parameters: message - [IN] the message                                     *
 *             data    - [OUT] the formatted message                          *
 *                                                                            *
 ******************************************************************************/
void	nt_ipc_message_format(const nt_ipc_message_t *message, char **data)
{
	size_t		data_alloc = NT_IPC_DATA_DUMP_SIZE * 4 + 32, data_offset = 0;
	nt_uint32_t	i, data_num;

	if (NULL == message)
		return;

	data_num = message->size;

	if (NT_IPC_DATA_DUMP_SIZE < data_num)
		data_num = NT_IPC_DATA_DUMP_SIZE;

	*data = (char *)nt_malloc(*data, data_alloc);
	nt_snprintf_alloc(data, &data_alloc, &data_offset, "code:%u size:%u data:", message->code, message->size);

	for (i = 0; i < data_num; i++)
	{
		if (0 != i)
			nt_strcpy_alloc(data, &data_alloc, &data_offset, (0 == (i & 7) ? " | " : " "));

		nt_snprintf_alloc(data, &data_alloc, &data_offset, "%02x", (int)message->data[i]);
	}

	(*data)[data_offset] = '\0';
}

#ifdef HAVE_OPENIPMI
/******************************************************************************
 *                                                                            *
 * Purpose: copies ipc message                                                *
 *                                                                            *
 * Parameters: dst - [IN] the destination message                             *
 *             src - [IN] the source message                                  *
 *                                                                            *
 ******************************************************************************/
void	nt_ipc_message_copy(nt_ipc_message_t *dst, const nt_ipc_message_t *src)
{
	dst->code = src->code;
	dst->size = src->size;
	dst->data = (unsigned char *)nt_malloc(NULL, src->size);
	memcpy(dst->data, src->data, src->size);
}
#endif /* HAVE_OPENIPMI */

static void	ipc_service_user_cb(evutil_socket_t fd, short what, void *arg)
{
	NT_UNUSED(fd);
	NT_UNUSED(what);
	NT_UNUSED(arg);
}

/*
 * Public service API
 */

/******************************************************************************
 *                                                                            *
 * Purpose: initializes IPC service environment                               *
 *                                                                            *
 * Parameters: path    - [IN] the service root path                           *
 *             error   - [OUT] the error message                              *
 *                                                                            *
 * Return value: SUCCEED - the environment was initialized successfully.      *
 *               FAIL    - otherwise                                          *
 *                                                                            *
 ******************************************************************************/
int	nt_ipc_service_init_env(const char *path, char **error)
{
	struct stat	fs;
	int		ret = FAIL;

	nt_log(LOG_LEVEL_DEBUG, "In %s() path:%s", __func__, path);

	if (0 != ipc_path_root_len)
	{
		*error = nt_dsprintf(*error, "The IPC service environment has been already initialized with"
				" root directory at \"%s\".", ipc_get_path());
		goto out;
	}

	if (0 != stat(path, &fs))
	{
		*error = nt_dsprintf(*error, "Failed to stat the specified path \"%s\": %s.", path,
				nt_strerror(errno));
		goto out;
	}

	if (0 == S_ISDIR(fs.st_mode))
	{
		*error = nt_dsprintf(*error, "The specified path \"%s\" is not a directory.", path);
		goto out;
	}

	if (0 != access(path, W_OK | R_OK))
	{
		*error = nt_dsprintf(*error, "Cannot access path \"%s\": %s.", path, nt_strerror(errno));
		goto out;
	}

	ipc_path_root_len = strlen(path);
	if (NT_IPC_PATH_MAX < ipc_path_root_len + 3)
	{
		*error = nt_dsprintf(*error, "The IPC root path \"%s\" is too long.", path);
		goto out;
	}

	memcpy(ipc_path, path, ipc_path_root_len + 1);

	while (1 < ipc_path_root_len && '/' == ipc_path[ipc_path_root_len - 1])
		ipc_path[--ipc_path_root_len] = '\0';

	ipc_service_init_libevent();

	if (0 != evthread_use_pthreads())
	{
		*error = nt_strdup(*error, "Cannot initialize libevent threading support");
		goto out;
	}

	ret = SUCCEED;
out:
	nt_log(LOG_LEVEL_DEBUG, "End of %s():%s", __func__, nt_result_string(ret));

	return ret;
}

/******************************************************************************
 *                                                                            *
 * Purpose: frees IPC service environment                                     *
 *                                                                            *
 ******************************************************************************/
void	nt_ipc_service_free_env(void)
{
	ipc_service_free_libevent();
}

/******************************************************************************
 *                                                                            *
 * Purpose: starts IPC service on the specified path                          *
 *                                                                            *
 * Parameters: service      - [IN/OUT] the IPC service                        *
 *             service_name - [IN] the unix domain socket path                *
 *             error        - [OUT] the error message                         *
 *                                                                            *
 * Return value: SUCCEED - the service was initialized successfully.          *
 *               FAIL    - otherwise                                          *
 *                                                                            *
 ******************************************************************************/
int	nt_ipc_service_start(nt_ipc_service_t *service, const char *service_name, char **error)
{
	struct sockaddr_un	addr;
	const char		*socket_path;
	int			ret = FAIL;
	mode_t			mode;

	nt_log(LOG_LEVEL_DEBUG, "In %s() service:%s", __func__, service_name);

	mode = umask(077);

	if (NULL == (socket_path = ipc_make_path(service_name, error)))
		goto out;

	if (0 == access(socket_path, F_OK))
	{
		if (0 != access(socket_path, W_OK))
		{
			*error = nt_dsprintf(*error, "The file \"%s\" is used by another process.", socket_path);
			goto out;
		}

		if (SUCCEED == ipc_check_running_service(service_name))
		{
			*error = nt_dsprintf(*error, "\"%s\" service is already running.", service_name);
			goto out;
		}

		unlink(socket_path);
	}

	if (-1 == (service->fd = socket(AF_UNIX, SOCK_STREAM, 0)))
	{
		*error = nt_dsprintf(*error, "Cannot create socket: %s.", nt_strerror(errno));
		goto out;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, socket_path, sizeof(addr.sun_path));

	if (0 != bind(service->fd, (struct sockaddr*)&addr, sizeof(addr)))
	{
		*error = nt_dsprintf(*error, "Cannot bind socket to \"%s\": %s.", socket_path, nt_strerror(errno));
		goto out;
	}

	if (0 != listen(service->fd, SOMAXCONN))
	{
		*error = nt_dsprintf(*error, "Cannot listen socket: %s.", nt_strerror(errno));
		goto out;
	}

	service->path = nt_strdup(NULL, socket_path);
	nt_vector_ipc_client_ptr_create(&service->clients);
	nt_queue_ptr_create(&service->clients_recv);

	service->ev = event_base_new();
	service->ev_listener = event_new(service->ev, service->fd, EV_READ | EV_PERSIST,
			ipc_service_client_connected_cb, service);
	event_add(service->ev_listener, NULL);

	service->ev_timer = event_new(service->ev, -1, 0, ipc_service_timer_cb, service);
	service->ev_alert = event_new(service->ev, -1, 0, ipc_service_user_cb, NULL);

	ret = SUCCEED;
out:
	umask(mode);

	nt_log(LOG_LEVEL_DEBUG, "End of %s():%s", __func__, nt_result_string(ret));

	return ret;
}

/******************************************************************************
 *                                                                            *
 * Purpose: closes IPC service and frees the resources allocated by it        *
 *                                                                            *
 * Parameters: service - [IN/OUT] the IPC service                             *
 *                                                                            *
 ******************************************************************************/
void	nt_ipc_service_close(nt_ipc_service_t *service)
{
	nt_ipc_client_t	*client = NULL;

	nt_log(LOG_LEVEL_DEBUG, "In %s() path:%s", __func__, service->path);

	if (0 != close(service->fd))
		nt_log(LOG_LEVEL_DEBUG, "Cannot close path \"%s\": %s", service->path, nt_strerror(errno));

	if (-1 == unlink(service->path))
		nt_log(LOG_LEVEL_WARNING, "cannot remove socket at %s: %s.", service->path, nt_strerror(errno));

	/* remove received clients which are not registered */
	while (NULL != (client = (nt_ipc_client_t *)nt_queue_ptr_pop(&service->clients_recv)))
	{
		if (FAIL == nt_vector_ipc_client_ptr_search(&service->clients, client, NT_DEFAULT_PTR_COMPARE_FUNC))
			ipc_client_free(client);
	}

	for (int i = 0; i < service->clients.values_num; i++)
		ipc_client_free(service->clients.values[i]);

	nt_free(service->path);

	nt_vector_ipc_client_ptr_destroy(&service->clients);
	nt_queue_ptr_destroy(&service->clients_recv);

	event_free(service->ev_alert);
	event_free(service->ev_timer);
	event_free(service->ev_listener);
	event_base_free(service->ev);

	nt_log(LOG_LEVEL_DEBUG, "End of %s()", __func__);
}

/******************************************************************************
 *                                                                            *
 * Purpose: receives ipc message from a connected client                      *
 *                                                                            *
 * Parameters: service - [IN] the IPC service                                 *
 *             timeout - [IN] the timeout. (0,0) is used for nonblocking call *
 *                            and (NT_IPC_WAIT_FOREVER, *) is                *
 *                            used for blocking call without timeout          *
 *             client  - [OUT] the client that sent the message or            *
 *                             NULL if there are no messages and the          *
 *                             specified timeout passed.                      *
 *                             The client must be released by caller with     *
 *                             nt_ipc_client_release() function.             *
 *             message - [OUT] the received message or NULL if the client     *
 *                             connection was closed.                         *
 *                             The message must be freed by caller with       *
 *                             ipc_message_free() function.                   *
 *                                                                            *
 * Return value: NT_IPC_RECV_IMMEDIATE - returned immediately without        *
 *                                        waiting for socket events           *
 *                                        (pending events are processed)      *
 *               NT_IPC_RECV_WAIT      - returned after receiving socket     *
 *                                        event                               *
 *               NT_IPC_RECV_TIMEOUT   - returned after timeout expired      *
 *                                                                            *
 ******************************************************************************/
int	nt_ipc_service_recv(nt_ipc_service_t *service, const nt_timespec_t *timeout, nt_ipc_client_t **client,
		nt_ipc_message_t **message)
{
	int	ret, flags;

	nt_log(LOG_LEVEL_DEBUG, "In %s() timeout:%d.%03d", __func__, timeout->sec, timeout->ns / 1000000);

	if ((0 != timeout->sec || 0 != timeout->ns) && SUCCEED == nt_queue_ptr_empty(&service->clients_recv))
	{
		if (NT_IPC_WAIT_FOREVER != timeout->sec)
		{
			struct timeval	tv = {timeout->sec, timeout->ns / 1000};
			evtimer_add(service->ev_timer, &tv);
		}
		flags = EVLOOP_ONCE;
	}
	else
		flags = EVLOOP_NONBLOCK;

	event_base_loop(service->ev, flags);

	if (NULL != (*client = ipc_service_pop_client(service)))
	{
		if (NULL != (*message = (nt_ipc_message_t *)nt_queue_ptr_pop(&(*client)->rx_queue)))
		{
			if (SUCCEED == NT_CHECK_LOG_LEVEL(LOG_LEVEL_TRACE))
			{
				char	*data = NULL;

				nt_ipc_message_format(*message, &data);
				nt_log(LOG_LEVEL_DEBUG, "%s() %s", __func__, data);

				nt_free(data);
			}

			ipc_service_push_client(service, *client);
			nt_ipc_client_addref(*client);
		}

		ret = (EVLOOP_NONBLOCK == flags ? NT_IPC_RECV_IMMEDIATE : NT_IPC_RECV_WAIT);
	}
	else
	{	ret = NT_IPC_RECV_TIMEOUT;
		*client = NULL;
		*message = NULL;
	}

	evtimer_del(service->ev_timer);

	nt_log(LOG_LEVEL_DEBUG, "End of %s():%d", __func__, ret);

	return ret;
}

/******************************************************************************
 *                                                                            *
 * Purpose: interrupt IPC service recv loop from another thread               *
 *                                                                            *
 ******************************************************************************/
void	nt_ipc_service_alert(nt_ipc_service_t *service)
{
	event_active(service->ev_alert, 0, 0);
}

/******************************************************************************
 *                                                                            *
 * Purpose: Sends IPC message to client                                       *
 *                                                                            *
 * Parameters: client - [IN] the IPC client                                   *
 *             code   - [IN] the message code                                 *
 *             data   - [IN] the data                                         *
 *             size   - [IN] the data size                                    *
 *                                                                            *
 * Comments: If data can't be written directly to socket (buffer full) then   *
 *           the message is queued and sent during nt_ipc_service_recv()     *
 *           messaging loop whenever socket becomes ready.                    *
 *                                                                            *
 ******************************************************************************/
int	nt_ipc_client_send(nt_ipc_client_t *client, nt_uint32_t code, const unsigned char *data, nt_uint32_t size)
{
	nt_uint32_t		tx_size = 0;
	nt_ipc_message_t	*message;
	int			ret = FAIL;

	nt_log(LOG_LEVEL_DEBUG, "In %s() clientid:" NT_FS_UI64, __func__, client->id);

	if (0 != client->tx_bytes)
	{
		message = ipc_message_create(code, data, size);
		nt_queue_ptr_push(&client->tx_queue, message);
		ret = SUCCEED;
		goto out;
	}

	if (FAIL == ipc_socket_write_message(&client->csocket, code, data, size, &tx_size))
		goto out;

	if (tx_size != NT_IPC_HEADER_SIZE + size)
	{
		client->tx_header[NT_IPC_MESSAGE_CODE] = code;
		client->tx_header[NT_IPC_MESSAGE_SIZE] = size;
		client->tx_data = (unsigned char *)nt_malloc(NULL, size);
		memcpy(client->tx_data, data, size);
		client->tx_bytes = NT_IPC_HEADER_SIZE + size - tx_size;
		event_add(client->tx_event, NULL);
	}

	ret = SUCCEED;
out:
	nt_log(LOG_LEVEL_DEBUG, "End of %s():%s", __func__, nt_result_string(ret));

	return ret;
}

/******************************************************************************
 *                                                                            *
 * Purpose: closes client socket and frees resources allocated for client     *
 *                                                                            *
 * Parameters: client - [IN] the IPC client                                   *
 *                                                                            *
 ******************************************************************************/
void	nt_ipc_client_close(nt_ipc_client_t *client)
{
	ipc_client_free_events(client);
	nt_ipc_socket_close(&client->csocket);

	ipc_service_remove_client(client->service, client);
	nt_queue_ptr_remove_value(&client->service->clients_recv, client);
	nt_ipc_client_release(client);
}

int	nt_ipc_client_get_fd(nt_ipc_client_t *client)
{
	return client->csocket.fd;
}

void	nt_ipc_client_addref(nt_ipc_client_t *client)
{
	client->refcount++;
}

void	nt_ipc_client_release(nt_ipc_client_t *client)
{
	if (0 == --client->refcount)
		ipc_client_free(client);
}

int	nt_ipc_client_connected(nt_ipc_client_t *client)
{
	return (NULL == client->rx_event ? FAIL : SUCCEED);
}

nt_uint64_t	nt_ipc_client_id(const nt_ipc_client_t *client)
{
	return client->id;
}

void	nt_ipc_client_set_userdata(nt_ipc_client_t *client, void *userdata)
{
	client->userdata = userdata;
}

void	*nt_ipc_client_get_userdata(nt_ipc_client_t *client)
{
	return client->userdata;
}

/******************************************************************************
 *                                                                            *
 * Purpose: opens asynchronous socket to IPC service client                   *
 *                                                                            *
 * Parameters: client       - [OUT] the IPC service client                    *
 *             service_name - [IN] the IPC service name                       *
 *             timeout      - [IN] the connection timeout                     *
 *             error        - [OUT] the error message                         *
 *                                                                            *
 * Return value: SUCCEED - the socket was successfully opened                 *
 *               FAIL    - otherwise                                          *
 *                                                                            *
 ******************************************************************************/
int	nt_ipc_async_socket_open(nt_ipc_async_socket_t *asocket, const char *service_name, int timeout, char **error)
{
	int	ret = FAIL, flags;

	nt_log(LOG_LEVEL_DEBUG, "In %s()", __func__);

	memset(asocket, 0, sizeof(nt_ipc_async_socket_t));
	asocket->client = (nt_ipc_client_t *)nt_malloc(NULL, sizeof(nt_ipc_client_t));
	memset(asocket->client, 0, sizeof(nt_ipc_client_t));

	if (SUCCEED != nt_ipc_socket_open(&asocket->client->csocket, service_name, timeout, error))
	{
		nt_free(asocket->client);
		goto out;
	}

	if (-1 == (flags = fcntl(asocket->client->csocket.fd, F_GETFL, 0)))
	{
		nt_log(LOG_LEVEL_CRIT, "cannot get IPC client socket flags");
		exit(EXIT_FAILURE);
	}

	if (-1 == fcntl(asocket->client->csocket.fd, F_SETFL, flags | O_NONBLOCK))
	{
		nt_log(LOG_LEVEL_CRIT, "cannot set non-blocking mode for IPC client socket");
		exit(EXIT_FAILURE);
	}

	asocket->ev = event_base_new();
	asocket->ev_timer = event_new(asocket->ev, -1, 0, ipc_async_socket_timer_cb, asocket);
	asocket->client->rx_event = event_new(asocket->ev, asocket->client->csocket.fd, EV_READ | EV_PERSIST,
			ipc_async_socket_read_event_cb, (void *)asocket);
	asocket->client->tx_event = event_new(asocket->ev, asocket->client->csocket.fd, EV_WRITE | EV_PERSIST,
			ipc_async_socket_write_event_cb, (void *)asocket);
	event_add(asocket->client->rx_event, NULL);

	asocket->state = NT_IPC_ASYNC_SOCKET_STATE_NONE;

	ret = SUCCEED;
out:
	nt_log(LOG_LEVEL_DEBUG, "End of %s() clientid:" NT_FS_UI64 " ret:%s", __func__, asocket->client->id,
			nt_result_string(ret));

	return ret;
}

/******************************************************************************
 *                                                                            *
 * Purpose: closes asynchronous IPC socket and frees allocated resources      *
 *                                                                            *
 * Parameters: asocket - [IN] the asynchronous IPC socket                     *
 *                                                                            *
 ******************************************************************************/
void	nt_ipc_async_socket_close(nt_ipc_async_socket_t *asocket)
{
	nt_log(LOG_LEVEL_DEBUG, "In %s()", __func__);

	ipc_client_free(asocket->client);
	asocket->client = NULL;

	event_free(asocket->ev_timer);
	event_base_free(asocket->ev);

	nt_log(LOG_LEVEL_DEBUG, "End of %s()", __func__);
}

/******************************************************************************
 *                                                                            *
 * Purpose: Sends message through asynchronous IPC socket                     *
 *                                                                            *
 * Parameters: asocket - [IN] the asynchronous IPC socket                     *
 *             code    - [IN] the message code                                *
 *             data    - [IN] the data                                        *
 *             size    - [IN] the data size                                   *
 *                                                                            *
 * Comments: If data can't be written directly to socket (buffer full) then   *
 *           the message is queued and sent during nt_ipc_async_socket_recv()*
 *           or nt_ipc_async_socket_flush() functions whenever socket becomes*
 *           ready.                                                           *
 *                                                                            *
 ******************************************************************************/
int	nt_ipc_async_socket_send(nt_ipc_async_socket_t *asocket, nt_uint32_t code, const unsigned char *data,
		nt_uint32_t size)
{
	int	ret = FAIL;

	nt_log(LOG_LEVEL_DEBUG, "In %s()", __func__);

	ret = nt_ipc_client_send(asocket->client, code, data, size);

	nt_log(LOG_LEVEL_DEBUG, "End of %s():%s", __func__, nt_result_string(ret));

	return ret;
}

/******************************************************************************
 *                                                                            *
 * Purpose: receives message through asynchronous IPC socket                  *
 *                                                                            *
 * Parameters: asocket - [IN] the asynchronous IPC socket                     *
 *             timeout - [IN] the timeout in seconds, 0 is used for           *
 *                            nonblocking call and NT_IPC_WAIT_FOREVER is    *
 *                            used for blocking call without timeout          *
 *             message - [OUT] the received message or NULL if the client     *
 *                             connection was closed.                         *
 *                             The message must be freed by caller with       *
 *                             ipc_message_free() function.                   *
 *                                                                            *
 * Return value: SUCCEED - the message was read successfully or timeout       *
 *                         occurred                                           *
 *               FAIL    - otherwise                                          *
 *                                                                            *
 * Comments: After socket has been closed (or connection error has occurred)  *
 *           calls to nt_ipc_client_read() will return success with buffered *
 *           messages, until all buffered messages are retrieved.             *
 *                                                                            *
 ******************************************************************************/
int	nt_ipc_async_socket_recv(nt_ipc_async_socket_t *asocket, int timeout, nt_ipc_message_t **message)
{
	int	ret, flags;

	nt_log(LOG_LEVEL_DEBUG, "In %s() timeout:%d", __func__, timeout);

	if (timeout != 0 && SUCCEED == nt_queue_ptr_empty(&asocket->client->rx_queue))
	{
		if (NT_IPC_WAIT_FOREVER != timeout)
		{
			struct timeval	tv = {timeout, 0};
			evtimer_add(asocket->ev_timer, &tv);
		}
		flags = EVLOOP_ONCE;
	}
	else
		flags = EVLOOP_NONBLOCK;

	/* do only single event base loop if timeout is not set */
	asocket->state = (0 != timeout ? NT_IPC_ASYNC_SOCKET_STATE_NONE : NT_IPC_ASYNC_SOCKET_STATE_TIMEOUT);

	do
	{
		event_base_loop(asocket->ev, flags);
		*message = (nt_ipc_message_t *)nt_queue_ptr_pop(&asocket->client->rx_queue);
	}
	while (NULL == *message && NT_IPC_ASYNC_SOCKET_STATE_NONE == asocket->state);

	if (SUCCEED == NT_CHECK_LOG_LEVEL(LOG_LEVEL_TRACE) && NULL != *message)
	{
		char	*data = NULL;

		nt_ipc_message_format(*message, &data);
		nt_log(LOG_LEVEL_DEBUG, "%s() %s", __func__, data);

		nt_free(data);
	}

	if (NULL != *message || NT_IPC_ASYNC_SOCKET_STATE_ERROR != asocket->state)
		ret = SUCCEED;
	else
		ret = FAIL;

	evtimer_del(asocket->ev_timer);

	nt_log(LOG_LEVEL_DEBUG, "End of %s():%d", __func__, ret);

	return ret;
}

/******************************************************************************
 *                                                                            *
 * Purpose: flushes unsent through asynchronous IPC socket                    *
 *                                                                            *
 * Parameters: asocket - [IN] the asynchronous IPC service socket             *
 *             timeout - [IN] the timeout in seconds, 0 is used for           *
 *                            nonblocking call and NT_IPC_WAIT_FOREVER is    *
 *                            used for blocking call without timeout          *
 *                                                                            *
 * Return value: SUCCEED - the data was flushed successfully or timeout       *
 *                         occurred. Use nt_ipc_client_unsent_data() to      *
 *                         check if all data was sent.                        *
 *               FAIL    - failed to send data (connection was closed or an   *
 *                         error occurred).                                   *
 *                                                                            *
 ******************************************************************************/
int	nt_ipc_async_socket_flush(nt_ipc_async_socket_t *asocket, int timeout)
{
	int	ret = FAIL, flags;

	nt_log(LOG_LEVEL_DEBUG, "In %s() timeout:%d", __func__, timeout);

	if (0 == asocket->client->tx_bytes)
	{
		ret = SUCCEED;
		goto out;
	}

	if (NT_IPC_ASYNC_SOCKET_STATE_ERROR == asocket->state)
		goto out;

	asocket->state = NT_IPC_ASYNC_SOCKET_STATE_NONE;

	if (0 != timeout)
	{
		if (NT_IPC_WAIT_FOREVER != timeout)
		{
			struct timeval	tv = {timeout, 0};
			evtimer_add(asocket->ev_timer, &tv);
		}
		flags = EVLOOP_ONCE;
	}
	else
		flags = EVLOOP_NONBLOCK;

	do
	{
		event_base_loop(asocket->ev, flags);

		if (SUCCEED != nt_ipc_client_connected(asocket->client))
			goto out;
	}
	while (0 != timeout && 0 != asocket->client->tx_bytes && NT_IPC_ASYNC_SOCKET_STATE_NONE == asocket->state);

	if (NT_IPC_ASYNC_SOCKET_STATE_ERROR != asocket->state)
	{
		ret = SUCCEED;
		asocket->state = NT_IPC_CLIENT_STATE_NONE;
	}
out:
	evtimer_del(asocket->ev_timer);

	nt_log(LOG_LEVEL_DEBUG, "End of %s():%d", __func__, ret);

	return ret;
}

/******************************************************************************
 *                                                                            *
 * Purpose: check if there are data to be sent                                *
 *                                                                            *
 * Parameters: asocket - [IN] the asynchronous IPC service socket             *
 *                                                                            *
 * Return value: SUCCEED - there are messages queued to be sent               *
 *               FAIL    - all data has been sent                             *
 *                                                                            *
 ******************************************************************************/
int	nt_ipc_async_socket_check_unsent(nt_ipc_async_socket_t *asocket)
{
	return (0 == asocket->client->tx_bytes ? FAIL : SUCCEED);
}

/******************************************************************************
 *                                                                            *
 * Purpose: check if socket is connected                                      *
 *                                                                            *
 * Parameters: asocket - [IN] the asynchronous IPC service socket             *
 *                                                                            *
 * Return value: SUCCEED - socket is connected                                *
 *               FAIL    - otherwise                                          *
 *                                                                            *
 ******************************************************************************/
int	nt_ipc_async_socket_connected(nt_ipc_async_socket_t *asocket)
{
	if (NULL == asocket->client)
		return FAIL;

	return nt_ipc_client_connected(asocket->client);
}

/******************************************************************************
 *                                                                            *
 * Purpose: connect, send message and receive response in a given timeout     *
 *                                                                            *
 * Parameters: service_name - [IN] the IPC service name                       *
 *             code         - [IN] the message code                           *
 *             timeout      - [IN] time allowed to be spent on receive, note  *
 *                                 that this does not include open, send and  *
 *                                 flush that have their own timeouts         *
 *             data         - [IN] the data                                   *
 *             size         - [IN] the data size                              *
 *             out          - [OUT] the received message or NULL on error     *
 *                                  The message must be freed by nt_free()   *
 *             error        - [OUT] the error message                         *
 *                                                                            *
 * Return value: SUCCEED - successfully sent message and received response    *
 *               FAIL    - error occurred                                     *
 *                                                                            *
 ******************************************************************************/
int	nt_ipc_async_exchange(const char *service_name, nt_uint32_t code, int timeout, const unsigned char *data,
		nt_uint32_t size, unsigned char **out, char **error)
{
	nt_ipc_message_t	*message;
	nt_ipc_async_socket_t	asocket;
	int			ret = FAIL;

	nt_log(LOG_LEVEL_DEBUG, "In %s() service:'%s' code:%u timeout:%d", __func__, service_name, code, timeout);

	if (FAIL == nt_ipc_async_socket_open(&asocket, service_name, timeout, error))
		goto out;

	if (FAIL == nt_ipc_async_socket_send(&asocket, code, data, size))
	{
		*error = nt_strdup(NULL, "Cannot send request");
		goto fail;
	}

	if (FAIL == nt_ipc_async_socket_flush(&asocket, timeout))
	{
		*error = nt_strdup(NULL, "Cannot flush request");
		goto fail;
	}

	if (FAIL == nt_ipc_async_socket_recv(&asocket, timeout, &message))
	{
		*error = nt_strdup(NULL, "Cannot receive response");
		goto fail;
	}

	if (NULL == message)
	{
		*error = nt_strdup(NULL, "Timeout while waiting for response");
		goto fail;
	}

	*out = message->data;
	message->data = NULL;

	nt_ipc_message_free(message);
	ret = SUCCEED;
fail:
	nt_ipc_async_socket_close(&asocket);
out:
	nt_log(LOG_LEVEL_DEBUG, "End of %s():%s", __func__, nt_result_string(ret));
	return ret;
}

void	nt_init_library_ipcservice(unsigned char program_type)
{
	switch (program_type)
	{
		case NT_PROGRAM_TYPE_SERVER:
			ipc_path_prefix = NT_IPC_CLASS_PREFIX_SERVER;
			ipc_path_prefix_len = NT_CONST_STRLEN(NT_IPC_CLASS_PREFIX_SERVER);
			break;
		case NT_PROGRAM_TYPE_PROXY_ACTIVE:
		case NT_PROGRAM_TYPE_PROXY_PASSIVE:
			ipc_path_prefix = NT_IPC_CLASS_PREFIX_PROXY;
			ipc_path_prefix_len = NT_CONST_STRLEN(NT_IPC_CLASS_PREFIX_PROXY);
			break;
		case NT_PROGRAM_TYPE_AGENTD:
			ipc_path_prefix = NT_IPC_CLASS_PREFIX_AGENT;
			ipc_path_prefix_len = NT_CONST_STRLEN(NT_IPC_CLASS_PREFIX_AGENT);
			break;
		default:
			ipc_path_prefix = NT_IPC_CLASS_PREFIX_NONE;
			ipc_path_prefix_len = NT_CONST_STRLEN(NT_IPC_CLASS_PREFIX_NONE);
			break;
	}
}

#endif
