#ifndef NT_COMMS_H
#define NT_COMMS_H

//#include "nt_algo.h"
#include "nt_common.h"
#include "nt_comms.h"
#include "nt_time.h"

/* 先引入系统 socket 相关头文件（Linux/Unix 路径） */
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>        /* struct addrinfo, getaddrinfo, getnameinfo, NI_* */
#include <netinet/in.h>   /* struct sockaddr_in, sockaddr_in6, IPPROTO_TCP 等 */
#include <arpa/inet.h>    /* inet_pton, inet_ntop, inet_ntoa */
#include <poll.h>         /* struct pollfd, POLLIN, POLLOUT, POLLERR... */

struct addrinfo;




#define NT_IPV4_MAX_CIDR_PREFIX	32	/* max number of bits in IPv4 CIDR prefix */
#define NT_IPV6_MAX_CIDR_PREFIX	128	/* max number of bits in IPv6 CIDR prefix */

#ifdef _WINDOWS
#	define nt_socket_last_error()		WSAGetLastError()

#	define NT_PROTO_ERROR			SOCKET_ERROR
#	define NT_SOCKET_TO_INT(s)		((int)(s))
#else
#	define nt_socket_last_error()		errno

#	define NT_PROTO_ERROR		-1
#	define NT_SOCKET_TO_INT(s)	(s)
#endif

#ifdef _WINDOWS
#	if !defined(POLLIN)
#		define POLLIN	0x001
#	endif
#	if !defined(POLLPRI)
#		define POLLPRI	0x002
#	endif
#	if !defined(POLLOUT)
#		define POLLOUT	0x004
#	endif
#	if !defined(POLLERR)
#		define POLLERR	0x008
#	endif
#	if !defined(POLLHUP)
#		define POLLHUP	0x010
#	endif
#	if !defined(POLLNVAL)
#		define POLLNVAL	0x020
#	endif
#	if !defined(POLLRDNORM)
#		define POLLRDNORM	0x040
#	endif
#	if !defined(POLLWRNORM)
#		define POLLWRNORM	0x100
#	endif

typedef struct
{
	SOCKET	fd;
	short	events;
	short	revents;
}
nt_pollfd_t;

int	nt_socket_poll(nt_pollfd_t* fds, unsigned long fds_num, int timeout);

#else
#	define nt_socket_poll(x, y, z)		poll(x, y, z)

typedef struct pollfd nt_pollfd_t;

#endif

void	nt_tcp_init_hints(struct addrinfo *hints, int socktype, int flags);

int	nt_socket_had_nonblocking_error(void);

#ifdef _WINDOWS
typedef SOCKET	NT_SOCKET;
#else
typedef int	NT_SOCKET;
#endif

#if defined(HAVE_IPV6)
#	define NT_SOCKADDR struct sockaddr_storage
#else
#	define NT_SOCKADDR struct sockaddr_in
#endif

typedef enum
{
	NT_BUF_TYPE_STAT = 0,
	NT_BUF_TYPE_DYN
}
nt_buf_type_t;

#define NT_SOCKET_COUNT	256
#define NT_STAT_BUF_LEN	2048

typedef struct
{
	unsigned int	connect_mode;	/* not used in server */
	unsigned int	accept_modes;	/* not used in server */
	unsigned int	frontend_accept_modes;

	char		*connect;
	char		*accept;	/* not used in nt_sender, nt_get */
	char		*ca_file;
	char		*crl_file;
	char		*server_cert_issuer;
	char		*server_cert_subject;
	char		*cert_file;
	char		*key_file;
	char		*psk_identity;
	char		*psk_file;
	char		*cipher_cert13;	/* not used in nt_get, config file parameter 'TLSCipherCert13' */
	char		*cipher_cert;	/* not used in nt_get, config file parameter 'TLSCipherCert' */
	char		*cipher_psk13;	/* not used in nt_get, config file parameter 'TLSCipherPSK13' */
	char		*cipher_psk;	/* not used in nt_get, config file parameter 'TLSCipherPSK' */
	char		*cipher_all13;	/* not used in nt_sender, nt_get, config file parameter */
					/*'TLSCipherAll13' */
	char		*cipher_all;	/* not used in nt_sender, nt_get, config file parameter */
					/*'TLSCipherAll' */
	char		*cipher_cmd13;	/* not used in agent, server, proxy, config file parameter '--tls-cipher13' */
	char		*cipher_cmd;	/* not used in agent, server, proxy, config file parameter 'tls-cipher' */
	char		*frontend_cert_issuer;
	char		*frontend_cert_subject;
	char		*frontend_accept;
	char		*tls_listen;
} nt_config_tls_t;

nt_config_tls_t	*nt_config_tls_new(void);
void	nt_config_tls_free(nt_config_tls_t *config_tls);

typedef struct
{
	nt_config_tls_t	*config_tls;
	const char		*hostname;
	const char		*server;
	const int		proxymode;
	const int		config_timeout;
	const int		config_trapper_timeout;
	const char		*config_source_ip;
	const char		*config_ssl_ca_location;
	const char		*config_ssl_cert_location;
	const char		*config_ssl_key_location;
}
nt_config_comms_args_t;

#if defined(HAVE_GNUTLS) || defined(HAVE_OPENSSL)

#if defined(HAVE_GNUTLS)
#	include <gnutls/gnutls.h>
#	include <gnutls/x509.h>
#elif defined(HAVE_OPENSSL)
#	include <openssl/ssl.h>
#	include <openssl/err.h>
#	include <openssl/rand.h>
#endif

typedef struct
{
#if defined(HAVE_GNUTLS)
	gnutls_session_t		ctx;
	gnutls_psk_client_credentials_t	psk_client_creds;
	gnutls_psk_server_credentials_t	psk_server_creds;
	unsigned char	psk_buf[HOST_TLS_PSK_LEN / 2];
	unsigned char	close_notify_received;
#elif defined(HAVE_OPENSSL)
	SSL				*ctx;
#if defined(HAVE_OPENSSL_WITH_PSK)
	char	psk_buf[HOST_TLS_PSK_LEN / 2];
	int	psk_len;
	size_t	identity_len;
#endif
#endif
} nt_tls_context_t;
#endif

typedef struct
{
	NT_SOCKET			socket;
	NT_SOCKET			socket_orig;
	size_t				read_bytes;
	char				*buffer;
	char				*next_line;
#if defined(HAVE_GNUTLS) || defined(HAVE_OPENSSL)
	nt_tls_context_t		*tls_ctx;
#endif
	unsigned int			connection_type;	/* type of connection actually established: */
								/* NT_TCP_SEC_UNENCRYPTED, NT_TCP_SEC_TLS_PSK or */
								/* NT_TCP_SEC_TLS_CERT */
	nt_buf_type_t			buf_type;
	unsigned char			accepted;
	int				num_socks;
	NT_SOCKET			sockets[NT_SOCKET_COUNT];
	char				buf_stat[NT_STAT_BUF_LEN];
	NT_SOCKADDR			peer_info;		/* getpeername() result */
	/* Peer host DNS name or IP address for diagnostics (after TCP connection is established). */
	/* TLS connection may be shut down at any time and it will not be possible to get peer IP address anymore. */
	char				peer[NT_MAX_DNSNAME_LEN + 1];
	int				protocol;
	int				timeout;
	nt_timespec_t			deadline;

	/* limits tcp received packet size, overrides flags limits */
	nt_uint64_t			max_len_limit;
}
nt_socket_t;

typedef struct
{
	size_t		buf_dyn_bytes;
	size_t		buf_stat_bytes;
	size_t		offset;
	nt_uint64_t	expected_len;
	nt_uint64_t	reserved;
	nt_uint64_t	max_len;
	unsigned char	expect;
	int		protocol_version;
	size_t		allocated;
}
nt_tcp_recv_context_t;

#define NT_MAX_HEADER_LEN 21
typedef struct
{
	unsigned char	header_buf[NT_MAX_HEADER_LEN];
	size_t		header_len;
	char		*compressed_data;
	const char	*data;
	size_t		send_len;
	ssize_t		written;
	ssize_t		written_header;
}
nt_tcp_send_context_t;

#undef NT_MAX_HEADER_LEN

const char	*nt_socket_strerror(void);

#if !defined(_WINDOWS) && !defined(__MINGW32__)
void	nt_gethost_by_ip(const char *ip, char *host, size_t hostlen);
void	nt_getip_by_host(const char *host, char *ip, size_t iplen);
int	nt_inet_ntop(struct sockaddr *ai_addr, char *ip, socklen_t len);
#endif
int	nt_inet_pton(int af, const char *src, void *dst);

int	nt_tcp_connect(nt_socket_t *s, const char *source_ip, const char *ip, unsigned short port, int timeout,
		unsigned int tls_connect, const char *tls_arg1, const char *tls_arg2);

void	nt_socket_clean(nt_socket_t *s);
char	*nt_socket_detach_buffer(nt_socket_t *s);
int	nt_socket_connect(nt_socket_t *s, int type, const char *source_ip, const char *ip, unsigned short port,
		int timeout);
int	nt_socket_pollout(nt_socket_t *s, int timeout, char **error);

int	nt_socket_tls_connect(nt_socket_t *s, unsigned int tls_connect, const char *tls_arg1, const char *tls_arg2,
		const char *server_name, short *event, char **error);

#define NT_TCP_PROTOCOL		0x01
#define NT_TCP_COMPRESS		0x02
#define NT_TCP_LARGE			0x04

#define NT_TCP_SEC_UNENCRYPTED		1		/* do not use encryption with this socket */
#define NT_TCP_SEC_TLS_PSK		2		/* use TLS with pre-shared key (PSK) with this socket */
#define NT_TCP_SEC_TLS_CERT		4		/* use TLS with certificate with this socket */
#define NT_TCP_SEC_UNENCRYPTED_TXT	"unencrypted"
#define NT_TCP_SEC_TLS_PSK_TXT		"psk"
#define NT_TCP_SEC_TLS_CERT_TXT	"cert"

const char	*nt_tcp_connection_type_name(unsigned int type);

#define nt_tcp_send(s, d)				nt_tcp_send_ext((s), (d), strlen(d), 0, NT_TCP_PROTOCOL, 0)
#define nt_tcp_send_to(s, d, timeout)			nt_tcp_send_ext((s), (d), strlen(d), 0,	\
									NT_TCP_PROTOCOL, timeout)
#define nt_tcp_send_bytes_to(s, d, len, timeout)	nt_tcp_send_ext((s), (d), len, 0, NT_TCP_PROTOCOL, timeout)
#define nt_tcp_send_raw(s, d)				nt_tcp_send_ext((s), (d), strlen(d), 0, 0, 0)

int	nt_tcp_send_ext(nt_socket_t *s, const char *data, size_t len, size_t reserved, unsigned char flags,
		int timeout);
int	nt_tcp_send_context_init(const char *data, size_t len, size_t reserved, unsigned char flags,
		nt_tcp_send_context_t *context);
void	nt_tcp_send_context_clear(nt_tcp_send_context_t *state);
int	nt_tcp_send_context(nt_socket_t *s, nt_tcp_send_context_t *context, short *event);

void	nt_tcp_close(nt_socket_t *s);

#ifdef HAVE_IPV6
int	get_address_family(const char *addr, int *family, char *error, int max_error_len);
#endif

int	nt_tcp_listen(nt_socket_t *s, const char *listen_ip, unsigned short listen_port, int timeout,
		int config_tcp_max_backlog_size);
void	nt_tcp_unlisten(nt_socket_t *s);

int	nt_tcp_accept(nt_socket_t *s, unsigned int tls_accept, int poll_timeout, char *tls_listen,
		const char *unencrypted_allowed_ip);
void	nt_tcp_unaccept(nt_socket_t *s);

#define NT_TCP_READ_UNTIL_CLOSE 0x01

#define	nt_tcp_recv(s)				SUCCEED_OR_FAIL(nt_tcp_recv_ext(s, 0, 0))
#define	nt_tcp_recv_large(s)			SUCCEED_OR_FAIL(nt_tcp_recv_ext(s, 0, NT_TCP_LARGE))
#define	nt_tcp_recv_to(s, timeout)		SUCCEED_OR_FAIL(nt_tcp_recv_ext(s, timeout, 0))
#define	nt_tcp_recv_raw(s)			SUCCEED_OR_FAIL(nt_tcp_recv_raw_ext(s, 0))

ssize_t	nt_tcp_read(nt_socket_t *s, char *buf, size_t len, short *events);
ssize_t	nt_tcp_write(nt_socket_t *s, const char *buf, size_t len, short *event);
ssize_t		nt_tcp_recv_ext(nt_socket_t *s, int timeout, unsigned char flags);
ssize_t		nt_tcp_recv_raw_ext(nt_socket_t *s, int timeout);
const char	*nt_tcp_recv_line(nt_socket_t *s);
int		nt_tcp_read_close_notify(nt_socket_t *s, int timeout, short *events);

void	nt_tcp_recv_context_init(nt_socket_t *s, nt_tcp_recv_context_t *tcp_recv_context, unsigned char flags);
ssize_t	nt_tcp_recv_context(nt_socket_t *s, nt_tcp_recv_context_t *context, unsigned char flags, short *events);
ssize_t	nt_tcp_recv_context_raw(nt_socket_t *s, nt_tcp_recv_context_t *context, short *events, int once);
const char	*nt_tcp_recv_context_line(nt_socket_t *s, nt_tcp_recv_context_t *context, short *events);

void	nt_socket_set_deadline(nt_socket_t *s, int timeout);
int	nt_socket_check_deadline(nt_socket_t *s);

int	nt_ip_cmp(unsigned int prefix_size, const struct addrinfo *current_ai, const NT_SOCKADDR *name,
		int ipv6v4_mode);
int	nt_validate_peer_list(const char *peer_list, char **error);
int	nt_tcp_check_allowed_peers_info(const NT_SOCKADDR *peer_info, const char *peer_list);
int	nt_tcp_check_allowed_peers(const nt_socket_t *s, const char *peer_list);
int	validate_cidr(const char *ip, const char *cidr, void *value);

int	nt_udp_connect(nt_socket_t *s, const char *source_ip, const char *ip, unsigned short port, int timeout);
int	nt_udp_send(nt_socket_t *s, const char *data, size_t data_len, int timeout);
int	nt_udp_recv(nt_socket_t *s, int timeout);
void	nt_udp_close(nt_socket_t *s);

#define NT_DEFAULT_FTP_PORT		21
#define NT_DEFAULT_SSH_PORT		22
#define NT_DEFAULT_TELNET_PORT		23
#define NT_DEFAULT_SMTP_PORT		25
#define NT_DEFAULT_DNS_PORT		53
#define NT_DEFAULT_HTTP_PORT		80
#define NT_DEFAULT_POP_PORT		110
#define NT_DEFAULT_NNTP_PORT		119
#define NT_DEFAULT_NTP_PORT		123
#define NT_DEFAULT_IMAP_PORT		143
#define NT_DEFAULT_LDAP_PORT		389
#define NT_DEFAULT_HTTPS_PORT		443
#define NT_DEFAULT_AGENT_PORT		10050
#define NT_DEFAULT_SERVER_PORT		10051
#define NT_DEFAULT_GATEWAY_PORT	10052

#define NT_DEFAULT_AGENT_PORT_STR	"10050"
#define NT_DEFAULT_SERVER_PORT_STR	"10051"

#ifdef HAVE_IPV6
#	define nt_getnameinfo(sa, host, hostlen, serv, servlen, flags)		\
			getnameinfo(sa, AF_INET == (sa)->sa_family ?		\
					sizeof(struct sockaddr_in) :		\
					sizeof(struct sockaddr_in6),		\
					host, hostlen, serv, servlen, flags)
#endif

#ifdef _WINDOWS
int	nt_socket_start(char **error);
#endif

int	nt_telnet_test_login(nt_socket_t *s);
//int	nt_telnet_login(nt_socket_t *s, const char *username, const char *password, AGENT_RESULT *result);
//int	nt_telnet_execute(nt_socket_t *s, const char *command, AGENT_RESULT *result, const char *encoding);

/* TLS BLOCK */
#if defined(HAVE_GNUTLS) || defined(HAVE_OPENSSL)

#if defined(HAVE_OPENSSL) && OPENSSL_VERSION_NUMBER < 0x1010000fL
#	if !defined(LIBRESSL_VERSION_NUMBER)
#		define OPENSSL_INIT_LOAD_SSL_STRINGS			0
#		define OPENSSL_INIT_LOAD_CRYPTO_STRINGS		0
#		define OPENSSL_VERSION					SSLEAY_VERSION
#	endif
#	define OpenSSL_version					SSLeay_version
#	define TLS_method					TLSv1_2_method
#	define TLS_client_method				TLSv1_2_client_method
#	define SSL_CTX_get_ciphers(ciphers)			((ciphers)->cipher_list)
#	if !defined(LIBRESSL_VERSION_NUMBER)
#		define SSL_CTX_set_min_proto_version(ctx, TLSv)	1
#	endif
#endif

#if defined(_WINDOWS)

/* Typical thread is long-running, if necessary, it initializes TLS for itself. Zabbix sender is an exception. If */
/* data is sent from a file or in real time then sender's 'main' thread starts the 'send_value' thread for each   */
/* 250 values to be sent. To avoid TLS initialization on every start of 'send_value' thread we initialize TLS in  */
/* 'main' thread and use this structure for passing minimum TLS variables into 'send_value' thread. */

struct nt_thread_sendval_tls_args
{
#if defined(HAVE_GNUTLS)
	gnutls_certificate_credentials_t	my_cert_creds;
	gnutls_psk_client_credentials_t		my_psk_client_creds;
	gnutls_priority_t			ciphersuites_cert;
	gnutls_priority_t			ciphersuites_psk;
#elif defined(HAVE_OPENSSL)
	SSL_CTX			*ctx_cert;
#ifdef HAVE_OPENSSL_WITH_PSK
	SSL_CTX			*ctx_psk;
	const char		*psk_identity_for_cb;
	size_t			psk_identity_len_for_cb;
	char			*psk_for_cb;
	size_t			psk_len_for_cb;
#endif
#endif
};

typedef struct nt_thread_sendval_tls_args NT_THREAD_SENDVAL_TLS_ARGS;

void	nt_tls_pass_vars(NT_THREAD_SENDVAL_TLS_ARGS *args);
void	nt_tls_take_vars(NT_THREAD_SENDVAL_TLS_ARGS *args);

#endif	/* #if defined(_WINDOWS) */

typedef enum
{
	NT_TLS_INIT_NONE,	/* not initialized */
	NT_TLS_INIT_PROCESS,	/* initialized by each process */
	NT_TLS_INIT_THREADS	/* initialized by parent process */
}
nt_tls_status_t;

void	nt_tls_validate_config(nt_config_tls_t *config_tls, int config_active_forks,
		int config_passive_forks, nt_get_program_type_f nt_get_program_type_cb);
void	nt_tls_library_deinit(nt_tls_status_t status);
void	nt_tls_init_parent(nt_get_program_type_f nt_get_program_type_cb_arg);

typedef size_t	(*nt_find_psk_in_cache_f)(const unsigned char *, unsigned char *, unsigned int *);

void	nt_tls_init_child(const nt_config_tls_t *config_tls, nt_get_program_type_f nt_get_program_type_cb_arg,
		nt_find_psk_in_cache_f nt_find_psk_in_cache_cb_arg);

void	nt_tls_free(void);
void	nt_tls_free_on_signal(void);
void	nt_tls_version(void);

#endif	/* #if defined(HAVE_GNUTLS) || defined(HAVE_OPENSSL) */
typedef struct
{
	unsigned int	connection_type;
	const char	*psk_identity;
	size_t		psk_identity_len;
	char		issuer[HOST_TLS_ISSUER_LEN_MAX];
	char		subject[HOST_TLS_SUBJECT_LEN_MAX];
}
nt_tls_conn_attr_t;

int		nt_tls_used(const nt_socket_t *s);
int		nt_tls_get_attr_cert(const nt_socket_t *s, nt_tls_conn_attr_t *attr);
int		nt_tls_get_attr_psk(const nt_socket_t *s, nt_tls_conn_attr_t *attr);
int		nt_tls_get_attr(const nt_socket_t *sock, nt_tls_conn_attr_t *attr, char **error);
int		nt_tls_validate_attr(const nt_tls_conn_attr_t *attr, const char *tls_issuer, const char *tls_subject,
				const char *tls_psk_identity, const char **msg);
int		nt_check_server_issuer_subject(const nt_socket_t *sock, const char *allowed_issuer,
				const char *allowed_subject, char **error);
unsigned int	nt_tls_get_psk_usage(void);

/* TLS BLOCK END */

#define NT_REDIRECT_ADDRESS_LEN	255
#define NT_REDIRECT_ADDRESS_LEN_MAX	(NT_REDIRECT_ADDRESS_LEN + 1)

#define NT_REDIRECT_FAIL		-1
#define NT_REDIRECT_NONE		0
#define NT_REDIRECT_RESET		1
#define NT_REDIRECT_RETRY		2

typedef struct
{
	char		address[NT_REDIRECT_ADDRESS_LEN_MAX];
	nt_uint64_t	revision;
	unsigned char	reset;
}
nt_comms_redirect_t;

#endif /* NT_COMMS_H */
