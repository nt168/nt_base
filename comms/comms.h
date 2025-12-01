/*
** Copyright (C) 2001-2025 Zabbix SIA
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

#ifndef COMMS_H
#define COMMS_H

//#include "config.h"

/* socket polling timeout in milliseconds */
#define NT_SOCKET_POLL_TIMEOUT	1000

#ifdef _WINDOWS
#	define NT_TCP_WRITE(s, b, bl)		((ssize_t)send((s), (b), (int)(bl), 0))
#	define NT_TCP_READ(s, b, bl)		((ssize_t)recv((s), (b), (int)(bl), 0))
#	define NT_TCP_RECV(s, b, bl, f)		((ssize_t)recv((s), (b), (int)(bl), f))
#	define nt_socket_close(s)		if (NT_SOCKET_ERROR != (s)) closesocket(s)
#	define nt_bind(s, a, l)		(bind((s), (a), (int)(l)))
#	define nt_sendto(fd, b, n, f, a, l)	(sendto((fd), (b), (int)(n), (f), (a), (l)))
#	define NT_PROTO_AGAIN			WSAEINTR
#	define NT_SOCKET_ERROR			INVALID_SOCKET
#else
#	define NT_TCP_WRITE(s, b, bl)		((ssize_t)write((s), (b), (bl)))
#	define NT_TCP_READ(s, b, bl)		((ssize_t)read((s), (b), (bl)))
#	define NT_TCP_RECV(s, b, bl, f)	((ssize_t)recv((s), (b), (bl), f))
#	define nt_socket_close(s)		if (NT_SOCKET_ERROR != (s)) close(s)
#	define nt_bind(s, a, l)		(bind((s), (a), (l)))
#	define nt_sendto(fd, b, n, f, a, l)	(sendto((fd), (b), (n), (f), (a), (l)))
#	define NT_PROTO_AGAIN			EINTR
#	define NT_SOCKET_ERROR			-1
#	define nt_socket_poll(x, y, z)		poll(x, y, z)
#endif

char 	*socket_poll_error(short revents);

#endif /* NT_COMMS_H */
