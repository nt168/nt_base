#ifndef EXAMPLE_NTSTR_H
#define EXAMPLE_NTSTR_H

#include "standalone_nt.h"

const char *nt_strerror(int errnum);
char *nt_strcpy_alloc(char **dest, size_t *alloc, size_t *offset, const char *src);
int nt_snprintf_alloc(char **dest, size_t *alloc, size_t *offset, const char *fmt, ...);

#endif
