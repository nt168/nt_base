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

#include "nt_crypto.h"

#include "nt_time.h"
#include "nt_hash.h"

/******************************************************************************
 *                                                                            *
 * Purpose: converts ASCII hex digit string to binary representation (byte    *
 *          string)                                                           *
 *                                                                            *
 * Parameters:                                                                *
 *     p_hex   - [IN] null-terminated input string                            *
 *     buf     - [OUT] output buffer                                          *
 *     buf_len - [IN] output buffer size                                      *
 *                                                                            *
 * Return value:                                                              *
 *     Number of bytes written into 'buf' on successful conversion.           *
 *     -1 - an error occurred.                                                *
 *                                                                            *
 * Comments:                                                                  *
 *     In case of error incomplete useless data may be written into 'buf'.    *
 *                                                                            *
 ******************************************************************************/
int	nt_hex2bin(const unsigned char *p_hex, unsigned char *buf, int buf_len)
{
	unsigned char	*q = buf;
	int		len = 0;

	while ('\0' != *p_hex)
	{
		if (0 != isxdigit(*p_hex) && 0 != isxdigit(*(p_hex + 1)) && buf_len > len)
		{
			unsigned char	hi = *p_hex & 0x0f;
			unsigned char	lo;

			if ('9' < *p_hex++)
				hi = (unsigned char)(hi + 9u);

			lo = *p_hex & 0x0f;

			if ('9' < *p_hex++)
				lo = (unsigned char)(lo + 9u);

			*q++ = (unsigned char)(hi << 4 | lo);
			len++;
		}
		else
			return -1;
	}

	return len;
}

/******************************************************************************
 *                                                                            *
 * Purpose: converts binary data to hex string                                *
 *                                                                            *
 * Parameters: bin     - [IN] data to convert                                 *
 *             bin_len - [IN] number of bytes to convert                      *
 *             out     - [OUT] output buffer                                  *
 *             out_len - [IN] size of output buffer (should be at least       *
 *                             2 * bin_len + 1)                               *
 *                                                                            *
 * Return value: The number of bytes written (excluding terminating zero).    *
 *                                                                            *
 ******************************************************************************/
int    nt_bin2hex(const unsigned char *bin, size_t bin_len, char *out, size_t out_len)
{
	const char	*hex = "0123456789abcdef";
	size_t		i;

	if (bin_len * 2 + 1 > out_len)
		bin_len = (out_len - 1) / 2;

	for (i = 0; i < bin_len; i++)
	{
		*out++ = hex[bin[i] >> 4];
		*out++ = hex[bin[i] & 15];
	}

	*out = '\0';

	return bin_len * 2;
}

/******************************************************************************
 *                                                                            *
 * Purpose: creates semi-unique token based on seed and current timestamp     *
 *                                                                            *
 * Parameters:  seed - [IN]                                                   *
 *                                                                            *
 * Return value: Hexadecimal token string, must be freed by caller.           *
 *                                                                            *
 * Comments: if you change token creation algorithm do not forget to adjust   *
 *           NT_SESSION_TOKEN_SIZE macro                                     *
 *                                                                            *
 ******************************************************************************/
char	*nt_create_token(nt_uint64_t seed)
{
	const char	*hex = "0123456789abcdef";
	nt_timespec_t	ts;
	md5_state_t	state;
	md5_byte_t	hash[NT_MD5_DIGEST_SIZE];
	int		i;
	char		*token, *ptr;

	ptr = token = (char *)nt_malloc(NULL, NT_SESSION_TOKEN_SIZE + 1);

	nt_timespec(&ts);

	nt_md5_init(&state);
	nt_md5_append(&state, (const md5_byte_t *)&seed, (int)sizeof(seed));
	nt_md5_append(&state, (const md5_byte_t *)&ts, (int)sizeof(ts));
	nt_md5_finish(&state, hash);

	for (i = 0; i < NT_MD5_DIGEST_SIZE; i++)
	{
		*ptr++ = hex[hash[i] >> 4];
		*ptr++ = hex[hash[i] & 15];
	}

	*ptr = '\0';

	return token;
}

/******************************************************************************
 *                                                                            *
 * Purpose: calculates UUID version 4 as string of 32 symbols                 *
 *                                                                            *
 * Parameters: seed - [IN] string for seed calculation                        *
 *                                                                            *
 * Return value: uuid string                                                  *
 *                                                                            *
 ******************************************************************************/
char	*nt_gen_uuid4(const char *seed)
{
	size_t		i;
	const char	*hex = "0123456789abcdef";
	char		*ptr, *uuid;
	md5_state_t	state;
	md5_byte_t	hash[NT_MD5_DIGEST_SIZE];

#define NT_UUID_VERSION	4
#define NT_UUID_VARIANT	2

	ptr = uuid = (char *)nt_malloc(NULL, 2 * NT_MD5_DIGEST_SIZE + 1);

	nt_md5_init(&state);
	nt_md5_append(&state, (const md5_byte_t *)seed, (int)strlen(seed));
	nt_md5_finish(&state, hash);

	hash[6] = (md5_byte_t)((hash[6] & 0xf) | (NT_UUID_VERSION << 4));
	hash[8] = (md5_byte_t)((hash[8] & 0x3f) | (NT_UUID_VARIANT << 6));

	for (i = 0; i < NT_MD5_DIGEST_SIZE; i++)
	{
		*ptr++ = hex[(hash[i] >> 4) & 0xf];
		*ptr++ = hex[hash[i] & 0xf];
	}

	*ptr = '\0';

	return uuid;
}
