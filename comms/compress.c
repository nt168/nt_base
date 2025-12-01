#include "nt_compress.h"

#include "nt_common.h"

#ifdef HAVE_ZLIB
#include "zlib.h"

#define NT_COMPRESS_STRERROR_LEN	512

static int	nt_zlib_errno = 0;

/******************************************************************************
 *                                                                            *
 * Purpose: returns last conversion error message                             *
 *                                                                            *
 ******************************************************************************/
const char	*nt_compress_strerror(void)
{
	static char	message[NT_COMPRESS_STRERROR_LEN];

	switch (nt_zlib_errno)
	{
		case Z_ERRNO:
			nt_strlcpy(message, nt_strerror(errno), sizeof(message));
			break;
		case Z_MEM_ERROR:
			nt_strlcpy(message, "not enough memory", sizeof(message));
			break;
		case Z_BUF_ERROR:
			nt_strlcpy(message, "not enough space in output buffer", sizeof(message));
			break;
		case Z_DATA_ERROR:
			nt_strlcpy(message, "corrupted input data", sizeof(message));
			break;
		default:
			nt_snprintf(message, sizeof(message), "unknown error (%d)", nt_zlib_errno);
			break;
	}

	return message;
}

/******************************************************************************
 *                                                                            *
 * Purpose: compress data                                                     *
 *                                                                            *
 * Parameters: in       - [IN] the data to compress                           *
 *             size_in  - [IN] the input data size                            *
 *             out      - [OUT] the compressed data                           *
 *             size_out - [OUT] the compressed data size                      *
 *                                                                            *
 * Return value: SUCCEED - the data was compressed successfully               *
 *               FAIL    - otherwise                                          *
 *                                                                            *
 * Comments: In the case of success the output buffer must be freed by the    *
 *           caller.                                                          *
 *                                                                            *
 ******************************************************************************/
int	nt_compress(const char *in, size_t size_in, char **out, size_t *size_out)
{
	Bytef	*buf;
	uLongf	buf_size;

	buf_size = compressBound(size_in);
	buf = (Bytef *)nt_malloc(NULL, buf_size);

	if (Z_OK != (nt_zlib_errno = compress(buf, &buf_size, (const Bytef *)in, size_in)))
	{
		nt_free(buf);
		return FAIL;
	}

	*out = (char *)buf;
	*size_out = buf_size;

	return SUCCEED;
}

/******************************************************************************
 *                                                                            *
 * Purpose: uncompress data                                                   *
 *                                                                            *
 * Parameters: in       - [IN] the data to uncompress                         *
 *             size_in  - [IN] the input data size                            *
 *             out      - [OUT] the uncompressed data                         *
 *             size_out - [IN/OUT] the buffer and uncompressed data size      *
 *                                                                            *
 * Return value: SUCCEED - the data was uncompressed successfully             *
 *               FAIL    - otherwise                                          *
 *                                                                            *
 ******************************************************************************/
int	nt_uncompress(const char *in, size_t size_in, char *out, size_t *size_out)
{
	uLongf	size_o = *size_out;

	if (Z_OK != (nt_zlib_errno = uncompress((Bytef *)out, &size_o, (const Bytef *)in, size_in)))
		return FAIL;

	*size_out = size_o;

	return SUCCEED;
}

#else

int	nt_compress(const char *in, size_t size_in, char **out, size_t *size_out)
{
	NT_UNUSED(in);
	NT_UNUSED(size_in);
	NT_UNUSED(out);
	NT_UNUSED(size_out);
	return FAIL;
}

int	nt_uncompress(const char *in, size_t size_in, char *out, size_t *size_out)
{
	NT_UNUSED(in);
	NT_UNUSED(size_in);
	NT_UNUSED(out);
	NT_UNUSED(size_out);
	return FAIL;
}

const char	*nt_compress_strerror(void)
{
	return "";
}

#endif
