#include "nt_ip.h"
#include "nt_num.h"
#include "nt_str.h"
#include "nt_log.h"

/******************************************************************************
 *                                                                            *
 * Purpose: checks if string is IPv4 address                                  *
 *                                                                            *
 * Parameters: ip - [IN]                                                      *
 *                                                                            *
 * Return value: SUCCEED - input is IPv4 address                              *
 *               FAIL    - otherwise                                          *
 *                                                                            *
 ******************************************************************************/
int	nt_is_ip4(const char *ip)
{
	const char	*p = ip;
	int		digits = 0, dots = 0, res = FAIL, octet = 0;

	nt_log(LOG_LEVEL_DEBUG, "In %s() ip:'%s'", __func__, ip);

	while ('\0' != *p)
	{
		if (0 != isdigit(*p))
		{
			octet = octet * 10 + (*p - '0');
			digits++;
		}
		else if ('.' == *p)
		{
			if (0 == digits || 3 < digits || 255 < octet)
				break;

			digits = 0;
			octet = 0;
			dots++;
		}
		else
		{
			digits = 0;
			break;
		}

		p++;
	}
	if (3 == dots && 1 <= digits && 3 >= digits && 255 >= octet)
		res = SUCCEED;

	nt_log(LOG_LEVEL_DEBUG, "End of %s():%s", __func__, nt_result_string(res));

	return res;
}

/******************************************************************************
 *                                                                            *
 * Purpose: checks if string is IPv6 address                                  *
 *                                                                            *
 * Parameters: ip - [IN]                                                      *
 *                                                                            *
 * Return value: SUCCEED - input is IPv6 address                              *
 *               FAIL    - otherwise                                          *
 *                                                                            *
 ******************************************************************************/
int	nt_is_ip6(const char *ip)
{
	const char	*p = ip, *last_colon;
	int		xdigits = 0, only_xdigits = 0, colons = 0, dbl_colons = 0, res;

	nt_log(LOG_LEVEL_DEBUG, "In %s() ip:'%s'", __func__, ip);

	while ('\0' != *p)
	{
		if (0 != isxdigit(*p))
		{
			xdigits++;
			only_xdigits = 1;
		}
		else if (':' == *p)
		{
			if (0 == xdigits && 0 < colons)
			{
				/* consecutive sections of zeros are replaced with a double colon */
				only_xdigits = 1;
				dbl_colons++;
			}

			if (4 < xdigits || 1 < dbl_colons)
				break;

			xdigits = 0;
			colons++;
		}
		else
		{
			only_xdigits = 0;
			break;
		}

		p++;
	}

	if (2 > colons || 7 < colons || 1 < dbl_colons || 4 < xdigits)
		res = FAIL;
	else if (1 == only_xdigits)
		res = SUCCEED;
	else if (7 > colons && (last_colon = strrchr(ip, ':')) < p)
		res = nt_is_ip4(last_colon + 1);	/* past last column is ipv4 mapped address */
	else
		res = FAIL;

	nt_log(LOG_LEVEL_DEBUG, "End of %s():%s", __func__, nt_result_string(res));

	return res;
}

/******************************************************************************
 *                                                                            *
 * Parameters: ip - [IN]                                                      *
 *                                                                            *
 * Return value: SUCCEED - input is IP address                                *
 *               FAIL    - otherwise                                          *
 *                                                                            *
 ******************************************************************************/
int	nt_is_supported_ip(const char *ip)
{
	if (SUCCEED == nt_is_ip4(ip))
		return SUCCEED;
#ifdef HAVE_IPV6
	if (SUCCEED == nt_is_ip6(ip))
		return SUCCEED;
#endif
	return FAIL;
}

/******************************************************************************
 *                                                                            *
 * Parameters: ip - [IN]                                                      *
 *                                                                            *
 * Return value: SUCCEED - input is IP address                                *
 *               FAIL    - otherwise                                          *
 *                                                                            *
 ******************************************************************************/
int	nt_is_ip(const char *ip)
{
	return SUCCEED == nt_is_ip4(ip) ? SUCCEED : nt_is_ip6(ip);
}

/******************************************************************************
 *                                                                            *
 * Purpose: checks if IP matches range of IP addresses                        *
 *                                                                            *
 * Parameters: list - [IN] comma-separated list of IP ranges                  *
 *                         192.168.0.1-64,192.168.0.128,10.10.0.0/24,12fc::21 *
 *             ip   - [IN]                                                    *
 *                                                                            *
 * Return value: FAIL - out of range, SUCCEED - within range                  *
 *                                                                            *
 ******************************************************************************/
int	nt_ip_in_list(const char *list, const char *ip)
{
	int		ipaddress[8];
	nt_iprange_t	iprange;
	char		*address = NULL;
	size_t		address_alloc = 0, address_offset;
	const char	*ptr;
	int		ret = FAIL;

	nt_log(LOG_LEVEL_DEBUG, "In %s() list:'%s' ip:'%s'", __func__, list, ip);

	if (SUCCEED != nt_iprange_parse(&iprange, ip))
		goto out;
#ifndef HAVE_IPV6
	if (NT_IPRANGE_V6 == iprange.type)
		goto out;
#endif
	nt_iprange_first(&iprange, ipaddress);

	for (ptr = list; '\0' != *ptr; list = ptr + 1)
	{
		if (NULL == (ptr = strchr(list, ',')))
			ptr = list + strlen(list);

		address_offset = 0;
		nt_strncpy_alloc(&address, &address_alloc, &address_offset, list, (size_t)(ptr - list));

		if (SUCCEED != nt_iprange_parse(&iprange, address))
			continue;
#ifndef HAVE_IPV6
		if (NT_IPRANGE_V6 == iprange.type)
			continue;
#endif
		if (SUCCEED == nt_iprange_validate(&iprange, ipaddress))
		{
			ret = SUCCEED;
			break;
		}
	}

	nt_free(address);
out:
	nt_log(LOG_LEVEL_DEBUG, "End of %s():%s", __func__, nt_result_string(ret));

	return ret;
}

/******************************************************************************
 *                                                                            *
 * Purpose: parses ServerActive element like "IP<:port>" or "[IPv6]<:port>"   *
 *                                                                            *
 ******************************************************************************/
int	nt_parse_serveractive_element(const char *str, char **host, unsigned short *port, unsigned short port_default)
{
#ifdef HAVE_IPV6
	char	*r1 = NULL;
#endif
	char	*r2 = NULL;
	int	res = FAIL;

	*port = port_default;

#ifdef HAVE_IPV6
	if ('[' == *str)
	{
		str++;

		if (NULL == (r1 = strchr(str, ']')))
			goto fail;

		if (':' != r1[1] && '\0' != r1[1])
			goto fail;

		if (':' == r1[1] && SUCCEED != nt_is_ushort(r1 + 2, port))
			goto fail;

		*r1 = '\0';

		if (SUCCEED != nt_is_ip6(str))
			goto fail;

		*host = nt_strdup(*host, str);
	}
	else if (SUCCEED == nt_is_ip6(str))
	{
		*host = nt_strdup(*host, str);
	}
	else
	{
#endif
		if (NULL != (r2 = strchr(str, ':')))
		{
			if (SUCCEED != nt_is_ushort(r2 + 1, port))
				goto fail;

			*r2 = '\0';
		}

		*host = nt_strdup(NULL, str);
#ifdef HAVE_IPV6
	}
#endif

	res = SUCCEED;
fail:
#ifdef HAVE_IPV6
	if (NULL != r1)
		*r1 = ']';
#endif
	if (NULL != r2)
		*r2 = ':';

	return res;
}

/******************************************************************************
 *                                                                            *
 * Purpose: combines host and port into a network address "host:port"         *
 *                                                                            *
 * Parameters: hostport       - [IN/OUT] string formatting buffer pointer     *
 *             hostport_sz    - [IN] size of buffer                           *
 *             host           - [IN]                                          *
 *             port           - [IN]                                          *
 *                                                                            *
 * Return value: pointer to hostport buffer                                   *
 *                                                                            *
 ******************************************************************************/
char	*nt_join_hostport(char *hostport, size_t hostport_sz, const char *host, unsigned short port)
{
	const char	*format = "%s:%hu";

	if (NULL != strchr(host, ':'))
		format = "[%s]:%hu";

	nt_snprintf(hostport, hostport_sz, format, host, port);

	return hostport;
}
