#ifndef NT_COMPRESS_H
#define NT_COMPRESS_H

#include "nt_types.h"

int	nt_compress(const char *in, size_t size_in, char **out, size_t *size_out);
int	nt_uncompress(const char *in, size_t size_in, char *out, size_t *size_out);
const char	*nt_compress_strerror(void);

#endif
