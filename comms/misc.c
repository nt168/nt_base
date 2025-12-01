#include <fcntl.h>
#include <stdlib.h>
#include "../nt_log.h"
#include "../version.h"
#if defined(_WINDOWS) || defined(__MINGW32__)
#	include <stddef.h>
#endif

#include "nt_common.h"
#include "nt_types.h"

#if defined(_WINDOWS) || defined(__MINGW32__)
#	include "ntstr.h"
#endif

static NT_THREAD_LOCAL volatile sig_atomic_t	nt_timed_out;	/* 0 - no timeout occurred, 1 - SIGALRM took place */

#if defined(_WINDOWS) || defined(__MINGW32__)

int	__nt_stat(const char *path, nt_stat_t *buf)
{
	int	ret, fd;
	wchar_t	*wpath;

	wpath = nt_utf8_to_unicode(path);

	if (-1 == (ret = _wstat64(wpath, buf)))
		goto out;

	if (0 != S_ISDIR(buf->st_mode) || 0 != buf->st_size)
		goto out;

	/* In the case of symlinks _wstat64 returns zero file size.   */
	/* Try to work around it by opening the file and using fstat. */

	ret = -1;

	if (-1 != (fd = _wopen(wpath, O_RDONLY)))
	{
		ret = _fstat64(fd, buf);
		_close(fd);
	}
out:
	nt_free(wpath);

	return ret;
}
#endif

/******************************************************************************
 *                                                                            *
 * Purpose: return program name without path                                  *
 *                                                                            *
 * Return value: program name without path                                    *
 *                                                                            *
 ******************************************************************************/
const char	*get_program_name(const char *path)
{
	const char	*filename = NULL;

	for (filename = path; path && *path; path++)
	{
		if ('\\' == *path || '/' == *path)
			filename = path + 1;
	}

	return filename;
}

/******************************************************************************
 *                                                                            *
 * Purpose: checks result of calloc()                                         *
 *                                                                            *
 * Return value: returns a pointer to newly allocated memory or terminates    *
 *               program if out of memory                                     *
 *                                                                            *
 ******************************************************************************/
// void	*nt_calloc2(const char *filename, int line, void *old, size_t nmemb, size_t size, void *new_ptr)
// {
// 	/* old pointer must be NULL */
// 	if (NULL != old)
// 	{
// 		nt_log(LOG_LEVEL_CRIT,
// 				"[file:%s,line:%d] nt_calloc: allocating already allocated memory. "
// 				"Please report this to Nt developers.",
// 				filename, line);
// 	}

// 	if (0 == nmemb || 0 == size)
// 	{
// 		nt_log(LOG_LEVEL_DEBUG,
// 				"[file:%s,line:%d] nt_calloc: "
// 				"allocating " NT_FS_SIZE_T " memory objects of size " NT_FS_SIZE_T ". "
// 				"Please report this to Nt developers.",
// 				filename, line, (nt_fs_size_t)nmemb, (nt_fs_size_t)size);
// 	}

// 	if (NULL != new_ptr)
// 		return new_ptr;

// 	nt_log(LOG_LEVEL_CRIT,
// 			"[file:%s,line:%d] nt_calloc: out of memory. Requested " NT_FS_SIZE_T " bytes.",
// 			filename, line, (nt_fs_size_t)size);

// 	exit(EXIT_FAILURE);
// }

/******************************************************************************
 *                                                                            *
 * Purpose: checks result of malloc()                                         *
 *                                                                            *
 * Return value: returns a pointer to newly allocated memory or terminates    *
 *               program if out of memory                                     *
 *                                                                            *
 ******************************************************************************/
// void	*nt_malloc2(const char *filename, int line, void *old, size_t size, void *new_ptr)
// {
// 	/* old pointer must be NULL */
// 	if (NULL != old)
// 	{
// 		nt_log(LOG_LEVEL_CRIT,
// 				"[file:%s,line:%d] nt_malloc: allocating already allocated memory. "
// 				"Please report this to Nt developers.",
// 				filename, line);
// 	}

// 	if (0 == size)
// 	{
// 		nt_log(LOG_LEVEL_DEBUG,
// 				"[file:%s,line:%d] nt_malloc: allocating 0 bytes. "
// 				"Please report this to Nt developers.",
// 				filename, line);
// 	}

// 	if (NULL != new_ptr)
// 		return new_ptr;

// 	nt_log(LOG_LEVEL_CRIT,
// 			"[file:%s,line:%d] nt_malloc: out of memory. "
// 			"Requested " NT_FS_SIZE_T " byte(s).",
// 			filename, line, (nt_fs_size_t)size);

// 	exit(EXIT_FAILURE);
// }

/******************************************************************************
 *                                                                            *
 * Purpose: checks result of realloc()                                        *
 *                                                                            *
 * Return value: returns a pointer to reallocated memory or terminates        *
 *               program if out of memory                                     *
 *                                                                            *
 ******************************************************************************/
// void	*nt_realloc2(const char *filename, int line, size_t size, void *new_ptr)
// {
// 	if (0 == size)
// 	{
// 		nt_log(LOG_LEVEL_DEBUG,
// 				"[file:%s,line:%d] nt_realloc: reallocating to 0 bytes. "
// 				"Please report this to Nt developers.",
// 				filename, line);
// 	}

// 	if (NULL != new_ptr)
// 		return new_ptr;

// 	nt_log(LOG_LEVEL_CRIT,
// 			"[file:%s,line:%d] nt_realloc: out of memory. Requested " NT_FS_SIZE_T " bytes.",
// 			filename, line, (nt_fs_size_t)size);

// 	exit(EXIT_FAILURE);
// }

// char	*nt_strdup2(const char *filename, int line, char *old, const char *str)
// {
// 	char	*ptr = NULL;

// 	nt_free(old);

// 	ptr = strdup(str);
// 	if (NULL != ptr)
// 		return ptr;

// 	nt_log(LOG_LEVEL_CRIT,
// 			"[file:%s,line:%d] nt_strdup: out of memory. Requested " NT_FS_SIZE_T " bytes.",
// 			filename, line, (nt_fs_size_t)(strlen(str) + 1));

// 	exit(EXIT_FAILURE);
// }

/****************************************************************************************
 *                                                                                      *
 * Purpose: For overwriting sensitive data in memory.                                   *
 *          Similar to memset() but should not be optimized out by a compiler.          *
 *                                                                                      *
 * Derived from:                                                                        *
 *   http://www.dwheeler.com/secure-programs/Secure-Programs-HOWTO/protect-secrets.html *
 * See also:                                                                            *
 *   http://www.open-std.org/jtc1/sc22/wg14/www/docs/n1381.pdf on secure_memset()       *
 *                                                                                      *
 ****************************************************************************************/
// void	*nt_guaranteed_memset(void *v, int c, size_t n)
// {
// 	volatile signed char	*p = (volatile signed char *)v;

// 	while (0 != n--)
// 		*p++ = (signed char)c;

// 	return v;
// }

static const char	copyright_message[] =
	"Copyright (C) 2025 Nt SIA\n"
	"License AGPLv3: GNU Affero General Public License version 3 <https://www.gnu.org/licenses/>.\n"
	"This is free software: you are free to change and redistribute it according to\n"
	"the license. There is NO WARRANTY, to the extent permitted by law.";

/******************************************************************************
 *                                                                            *
 * Purpose: print version and compilation time of application on stdout       *
 *          by application request with parameter '-V'                        *
 *                                                                            *
 ******************************************************************************/
void	nt_print_version(const char *title_message)
{
	printf("%s (Nt) %s\n", title_message, NT_VERSION);
	printf("Revision %s %s, compilation time: %s %s\n\n", NT_REVISION, NT_REVDATE, __DATE__, __TIME__);
	puts(copyright_message);
}

/******************************************************************************
 *                                                                            *
 * Purpose: check if string is a valid internet hostname                      *
 *                                                                            *
 * Parameters: hostname - [IN] hostname string to be checked                  *
 *                                                                            *
 * Return value: SUCCEED - could be a valid hostname,                         *
 *               FAIL - definitely not a valid hostname                       *
 * Comments:                                                                  *
 *     Validation is not strict. Restrictions not checked:                    *
 *         - individual label (component) length 1-63,                        *
 *         - hyphens ('-') allowed only as interior characters in labels,     *
 *         - underscores ('_') allowed in domain name, but not in hostname.   *
 *                                                                            *
 ******************************************************************************/
int	nt_validate_hostname(const char *hostname)
{
	int		component;	/* periods ('.') are only allowed when they serve to delimit components */
	int		len = NT_MAX_DNSNAME_LEN;
	const char	*p;

	/* the first character must be an alphanumeric character */
	if (0 == isalnum(*hostname))
		return FAIL;

	/* check only up to the first 'len' characters, the 1st character is already successfully checked */
	for (p = hostname + 1, component = 1; '\0' != *p; p++)
	{
		if (0 == --len)				/* hostname too long */
			return FAIL;

		/* check for allowed characters */
		if (0 != isalnum(*p) || '-' == *p || '_' == *p)
			component = 1;
		else if ('.' == *p && 1 == component)
			component = 0;
		else
			return FAIL;
	}

	return SUCCEED;
}

/******************************************************************************
 *                                                                            *
 * Purpose: get nearest index position of sorted elements in array            *
 *                                                                            *
 * Parameters: p   - pointer to array of elements                             *
 *             sz  - element size                                             *
 *             num - number of elements                                       *
 *             id  - index to look for                                        *
 *                                                                            *
 * Return value: index at which it would be possible to insert the element so *
 *               that the array is still sorted                               *
 *                                                                            *
 ******************************************************************************/
int	get_nearestindex(const void *p, size_t sz, int num, nt_uint64_t id)
{
	int		first_index, last_index, index;
	nt_uint64_t	element_id;

	if (0 == num)
		return 0;

	first_index = 0;
	last_index = num - 1;

	while (1)
	{
		index = first_index + (last_index - first_index) / 2;

		if (id == (element_id = *(const nt_uint64_t *)((const char *)p + index * sz)))
			return index;

		if (last_index == first_index)
		{
			if (element_id < id)
				index++;
			return index;
		}

		if (element_id < id)
			first_index = index + 1;
		else
			last_index = index;
	}
}

/******************************************************************************
 *                                                                            *
 * Purpose: add uint64 value to dynamic array                                 *
 *                                                                            *
 ******************************************************************************/
int	uint64_array_add(nt_uint64_t **values, int *alloc, int *num, nt_uint64_t value, int alloc_step)
{
	int	index;

	index = get_nearestindex(*values, sizeof(nt_uint64_t), *num, value);
	if (index < (*num) && (*values)[index] == value)
		return index;

	if (*alloc == *num)
	{
		if (0 == alloc_step)
		{
			nt_error("Unable to reallocate buffer");
			nt_this_should_never_happen_backtrace();
			assert(0);
		}

		*alloc += alloc_step;
		*values = (nt_uint64_t *)nt_realloc(*values, *alloc * sizeof(nt_uint64_t));
	}

	memmove(&(*values)[index + 1], &(*values)[index], sizeof(nt_uint64_t) * (*num - index));

	(*values)[index] = value;
	(*num)++;

	return index;
}

/******************************************************************************
 *                                                                            *
 * Purpose: remove uint64 values from array                                   *
 *                                                                            *
 ******************************************************************************/
void	uint64_array_remove(nt_uint64_t *values, int *num, const nt_uint64_t *rm_values, int rm_num)
{
	int	rindex, index;

	for (rindex = 0; rindex < rm_num; rindex++)
	{
		index = get_nearestindex(values, sizeof(nt_uint64_t), *num, rm_values[rindex]);
		if (index == *num || values[index] != rm_values[rindex])
			continue;

		memmove(&values[index], &values[index + 1], sizeof(nt_uint64_t) * ((*num) - index - 1));
		(*num)--;
	}
}

// void	nt_alarm_flag_set(void)
// {
// 	nt_timed_out = 1;
// }

void	nt_alarm_flag_clear(void)
{
	nt_timed_out = 0;
}

#if !defined(_WINDOWS) && !defined(__MINGW32__)
unsigned int	nt_alarm_on(unsigned int seconds)
{
	nt_alarm_flag_clear();

	return alarm(seconds);
}

unsigned int	nt_alarm_off(void)
{
	unsigned int	ret;

	ret = alarm(0);
	nt_alarm_flag_clear();
	return ret;
}
#endif

int	nt_alarm_timed_out(void)
{
	return (0 == nt_timed_out ? FAIL : SUCCEED);
}

nt_uint64_t	suffix2factor(char c)
{
	switch (c)
	{
		case 'K':
			return NT_KIBIBYTE;
		case 'M':
			return NT_MEBIBYTE;
		case 'G':
			return NT_GIBIBYTE;
		case 'T':
			return NT_TEBIBYTE;
		case 's':
			return 1;
		case 'm':
			return SEC_PER_MIN;
		case 'h':
			return SEC_PER_HOUR;
		case 'd':
			return SEC_PER_DAY;
		case 'w':
			return SEC_PER_WEEK;
		default:
			return 1;
	}
}
