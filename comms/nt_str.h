#ifndef NT_STR_H
#define NT_STR_H

#include "nt_common.h"

char	*nt_string_replace(const char *str, const char *sub_str1, const char *sub_str2);

int	nt_is_ascii_string(const char *str);

int	nt_rtrim(char *str, const char *charlist);
void	nt_ltrim(char *str, const char *charlist);
void	nt_lrtrim(char *str, const char *charlist);
void	nt_remove_chars(char *str, const char *charlist);
char	*nt_str_printable_dyn(const char *text);
#define NT_WHITESPACE			" \t\r\n"
void	nt_del_zeros(char *s);

size_t	nt_get_escape_string_len(const char *src, const char *charlist);
char	*nt_dyn_escape_string(const char *src, const char *charlist);
int	nt_escape_string(char *dst, size_t len, const char *src, const char *charlist);

int	nt_str_in_list(const char *list, const char *value, char delimiter);
int	nt_str_n_in_list(const char *list, const char *value, size_t len, char delimiter);

char	*nt_str_linefeed(const char *src, size_t maxline, const char *delim);
void	nt_strarr_init(char ***arr);
void	nt_strarr_add(char ***arr, const char *entry);
void	nt_strarr_free(char ***arr);

void	nt_strcpy_alloc(char **str, size_t *alloc_len, size_t *offset, const char *src);
void	nt_chrcpy_alloc(char **str, size_t *alloc_len, size_t *offset, char c);
void	nt_str_memcpy_alloc(char **str, size_t *alloc_len, size_t *offset, const char *src, size_t n);

#define NT_STRQUOTE_DEFAULT		1
#define NT_STRQUOTE_SKIP_BACKSLASH	0
void	nt_strquote_alloc_opt(char **str, size_t *str_alloc, size_t *str_offset, const char *value_str, int option);

void	nt_strsplit_first(const char *src, char delimiter, char **left, char **right);
void	nt_strsplit_last(const char *src, char delimiter, char **left, char **right);

/* secure string copy */
#define nt_strscpy(x, y)	nt_strlcpy(x, y, sizeof(x))
#define nt_strscat(x, y)	nt_strlcat(x, y, sizeof(x))
void	nt_strlcat(char *dst, const char *src, size_t siz);
size_t	nt_strlcpy_utf8(char *dst, const char *src, size_t size);

char	*nt_strdcat(char *dest, const char *src);
char	*nt_strdcatf(char *dest, const char *f, ...) __nt_attr_format_printf(2, 3);

const char	*nt_truncate_itemkey(const char *key, const size_t char_max, char *buf, const size_t buf_len);
const char	*nt_truncate_value(const char *val, const size_t char_max, char *buf, const size_t buf_len);

#define NT_NULL2STR(str)	(NULL != str ? str : "(null)")
#define NT_NULL2EMPTY_STR(str)	(NULL != (str) ? (str) : "")

char	*nt_strcasestr(const char *haystack, const char *needle);
int	nt_strncasecmp(const char *s1, const char *s2, size_t n);

#if defined(_WINDOWS) || defined(__MINGW32__)
char	*nt_unicode_to_utf8(const wchar_t *wide_string);
char	*nt_unicode_to_utf8_static(const wchar_t *wide_string, char *utf8_string, int utf8_size);
#endif

void	nt_strlower(char *str);
void	nt_strupper(char *str);

#if defined(_WINDOWS) || defined(__MINGW32__) || defined(HAVE_ICONV)
char	*nt_convert_to_utf8(char *in, size_t in_size, const char *encoding, char **error);
#endif	/* HAVE_ICONV */

#define NT_MAX_BYTES_IN_UTF8_CHAR	4
const char	*nt_get_bom_econding(char *in, size_t in_size);
size_t	nt_utf8_char_len(const char *text);
size_t	nt_strlen_utf8(const char *text);
char	*nt_strshift_utf8(char *text, size_t num);
size_t	nt_strlen_utf8_nchars(const char *text, size_t utf8_maxlen);
size_t	nt_charcount_utf8_nbytes(const char *text, size_t maxlen);

int	nt_is_ascii_printable(const char *text);
int	nt_is_utf8(const char *text);
void	nt_replace_invalid_utf8(char *text);
void	nt_replace_invalid_utf8_and_nonprintable(char *text);

void	nt_dos2unix(char *str);

int	nt_replace_mem_dyn(char **data, size_t *data_alloc, size_t *data_len, size_t offset, size_t sz_to,
		const char *from, size_t sz_from);

void	nt_trim_str_list(char *list, char delimiter);

int	nt_strcmp_null(const char *s1, const char *s2);

char	*nt_dyn_escape_shell_single_quote(const char *arg);

int	nt_strcmp_natural(const char *s1, const char *s2);
int	nt_str_extract(const char *text, size_t len, char **value);
char	*nt_substr(const char *src, size_t left, size_t right);
char	*nt_substr_unquote(const char *src, size_t left, size_t right);

/* UTF-8 trimming */
void	nt_ltrim_utf8(char *str, const char *charlist);
void	nt_rtrim_utf8(char *str, const char *charlist);

void	nt_strncpy_alloc(char **str, size_t *alloc_len, size_t *offset, const char *src, size_t n);
void	nt_replace_string(char **data, size_t l, size_t *r, const char *value);
#endif /* NT_STR_H */
