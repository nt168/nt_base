#include "nt_hash.h"

/******************************************************************************
 *                                                                            *
 * Purpose: gets textual representation of md5 sum                            *
 *                                                                            *
 * Parameters:                                                                *
 *          md5 - [IN]  buffer with md5 sum                                   *
 *          str - [OUT] Preallocated string with a text representation of MD5 *
 *                      sum. String size must be at least                     *
 *                      NT_MD5_PRINT_BUF_LEN bytes.                          *
 *                                                                            *
 ******************************************************************************/
void	nt_md5buf2str(const md5_byte_t *md5, char *str)
{
	const char	*hex = "0123456789abcdef";
	char		*p = str;
	int		i;

	for (i = 0; i < NT_MD5_DIGEST_SIZE; i++)
	{
		*p++ = hex[md5[i] >> 4];
		*p++ = hex[md5[i] & 15];
	}

	*p = '\0';
}
