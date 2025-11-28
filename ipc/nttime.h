#ifndef EXAMPLE_NTTIME_H
#define EXAMPLE_NTTIME_H

#include "standalone_nt.h"

int nt_timespec_sub(nt_timespec_t *result, const nt_timespec_t *left, const nt_timespec_t *right);
int nt_timespec_compare(const nt_timespec_t *left, const nt_timespec_t *right);

#endif
