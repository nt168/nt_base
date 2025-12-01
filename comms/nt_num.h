#ifndef NT_NUM_H
#define NT_NUM_H

#include "nt_common.h"
#include "nt_log.h"

#define nt_is_ushort(str, value) \
	nt_is_uint_n_range(str, NT_SIZE_T_MAX, value, sizeof(unsigned short), 0x0, 0xFFFF)

#define nt_is_uint32(str, value) \
	nt_is_uint_n_range(str, NT_SIZE_T_MAX, value, 4, 0x0, 0xFFFFFFFF)

#define nt_is_uint64(str, value) \
	nt_is_uint_n_range(str, NT_SIZE_T_MAX, value, 8, 0x0, __UINT64_C(0xFFFFFFFFFFFFFFFF))

#define nt_is_uint64_n(str, n, value) \
	nt_is_uint_n_range(str, n, value, 8, 0x0, __UINT64_C(0xFFFFFFFFFFFFFFFF))

#define nt_is_uint31(str, value) \
	nt_is_uint_n_range(str, NT_SIZE_T_MAX, value, 4, 0x0, 0x7FFFFFFF)

#define NT_MAX_UINT31_1	0x7FFFFFFE
#define nt_is_uint31_1(str, value) \
	nt_is_uint_n_range(str, NT_SIZE_T_MAX, value, 4, 0x0, NT_MAX_UINT31_1)

#define nt_is_uint_range(str, value, min, max) \
	nt_is_uint_n_range(str, NT_SIZE_T_MAX, value, sizeof(unsigned int), min, max)
int	nt_is_uint_n_range(const char *str, size_t n, void *value, size_t size, nt_uint64_t min, nt_uint64_t max);

int	nt_is_int(const char *str, int *value);

int	nt_is_hex_n_range(const char *str, size_t n, void *value, size_t size, nt_uint64_t min, nt_uint64_t max);
int	nt_is_hex_string(const char *str);

double	nt_get_float_epsilon(void);
double	nt_get_double_epsilon(void);
void	nt_update_epsilon_to_float_precision(void);
void	nt_update_epsilon_to_python_compatible_precision(void);
int	nt_double_compare(double a, double b);
int	nt_validate_value_dbl(double value);

int	nt_int_in_list(char *list, int value);

#define NT_UNIT_SYMBOLS	"KMGTsmhdw"

#define NT_FLAG_DOUBLE_PLAIN	0x00
#define NT_FLAG_DOUBLE_SUFFIX	0x01
int	nt_is_double(const char *str, double *value);

#if defined(_WINDOWS) || defined(__MINGW32__)
int	nt_wis_uint(const wchar_t *wide_string);
#endif

const char	*nt_print_double(char *buffer, size_t size, double val);
int		nt_number_parse(const char *number, int *len);

#define NT_STR2UINT64(uint, string) nt_is_uint64(string, &uint)

int	nt_str2uint64(const char *str, const char *suffixes, nt_uint64_t *value);

void	nt_trim_integer(char *str);
void	nt_trim_float(char *str);
#endif /* NT_NUM_H */
