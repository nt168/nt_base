#ifndef NT_IP_H
#define NT_IP_H

#include "../nt_types.h"

int	nt_is_ip4(const char *ip);
int	nt_is_ip6(const char *ip);
int	nt_is_supported_ip(const char *ip);
int	nt_is_ip(const char *ip);

int	nt_ip_in_list(const char *list, const char *ip);

int	nt_parse_serveractive_element(const char *str, char **host, unsigned short *port,
		unsigned short port_default);

char	*nt_join_hostport(char *hostport, size_t hostport_sz, const char *host, unsigned short port);

#define NT_IPRANGE_V4	0
#define NT_IPRANGE_V6	1

#define NT_IPRANGE_GROUPS_V4	4
#define NT_IPRANGE_GROUPS_V6	8

#define NT_PORTRANGE_INIT_PORT	-1

typedef struct
{
	int	from;
	int	to;
}
nt_range_t;

typedef struct
{
	/* contains groups of ranges for either NT_IPRANGE_V4 or NT_IPRANGE_V6 */
	/* ex. 127-127.0-0.0-0.2-254 (from-to.from-to.from-to.from-to)           */
	/*                                  0       1       2       3            */
	nt_range_t	range[NT_IPRANGE_GROUPS_V6];

	/* range type - NT_IPRANGE_V4 or NT_IPRANGE_V6 */
	unsigned char	type;

	/* 1 if the range was defined with network mask, 0 otherwise */
	unsigned char   mask;
}
nt_iprange_t;

int	nt_iprange_parse(nt_iprange_t *iprange, const char *address);
void	nt_iprange_first(const nt_iprange_t *iprange, int *address);
int	nt_iprange_next(const nt_iprange_t *iprange, int *address);
int	nt_iprange_uniq_next(const nt_iprange_t *ipranges, const int num, char *ip, const size_t len);
int	nt_iprange_uniq_iter(const nt_iprange_t *ipranges, const int num, int *idx, int *ipaddress);
void	nt_iprange_ip2str(const unsigned char type, const int *ipaddress, char *ip, const size_t len);
int	nt_portrange_uniq_next(const nt_range_t *ranges, const int num, int *port);
int	nt_portrange_uniq_iter(const nt_range_t *ranges, const int num, int *idx, int *port);

int	nt_iprange_validate(const nt_iprange_t *iprange, const int *address);
nt_uint64_t	nt_iprange_volume(const nt_iprange_t *iprange);

#endif /* NT_IP_H */
