#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <string.h>
#include <assert.h>
#include <semaphore.h>
#include <time.h>
#include <pwd.h>

#include <pthread.h>
#include <sys/types.h>

#include <sys/wait.h>
#include <sys/stat.h>

#include "nt_types.h"

#define SEM_SERVER_RUN "/sem_server_run"
#define SEM_QTWINDOW_RUN "/sem_qtwindow_run"

#define	SUCCEED		0
#define	FAIL		-1

#define LEVEL_WARNING	3
#define LEVEL_DEBUG		4

#define PHRASE 100
#define MAX_STRING_LEN		2048
#define MAX_BUFFER_LEN		65536
#define PHY_MEBIBYTE		1048576
#define PHY_MAX_UINT64		(~__UINT64_C(0))

#define SEC_PER_MIN		60
#define SEC_PER_HOUR		3600
#define SEC_PER_DAY		86400
#define SEC_PER_WEEK		(7 * SEC_PER_DAY)
#define SEC_PER_MONTH		(30 * SEC_PER_DAY)
#define SEC_PER_YEAR		(365 * SEC_PER_DAY)

#	define phy_int64_t	 int64_t
#	define phy_uint64_t	uint64_t
# define phy_uint     unsigned int
#	define un_int64_t	  int64_t

#define PHY_TASK_FLAG_MULTIPLE_AGENTS 0x01
#define PHY_TASK_FLAG_FOREGROUND      0x02

#ifndef MAX
#	define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifndef MIN
#	define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

typedef struct stat	phy_stat_t;
#	define phy_error __phy_phy_error
void	phy_error(const char *fmt, ...);

#define ARRSIZE(a)	(sizeof(a) / sizeof(*a))
#define PHY_UNUSED(var) (void)(var)

typedef enum
{
	PHY_TASK_START = 0,
	PHY_TASK_PRINT_SUPPORTED,
	PHY_TASK_TEST_METRIC,
	PHY_TASK_SHOW_USAGE,
	PHY_TASK_SHOW_VERSION,
	PHY_TASK_SHOW_HELP,
	PHY_TASK_RUNTIME_CONTROL
}
phy_task_t;

typedef struct
{
	phy_task_t	task;
	int		flags;
	int		data;
}PHY_TASK_EX;

typedef struct
{
	char	tz_sign;	/* '+' or '-' */
	int	tz_hour;
	int	tz_min;
}
phy_timezone_t;

#define phy_fclose(file)	\
				\
do				\
{				\
	if (file)		\
	{			\
		fclose(file);	\
		file = NULL;	\
	}			\
}				\
while (0)

#define phy_free(ptr)		\
				\
do				\
{				\
	if (ptr)		\
	{			\
		free(ptr);	\
		ptr = NULL;	\
	}			\
}				\
while (0)

#define THIS_SHOULD_NEVER_HAPPEN	phy_error("ERROR [file:%s,line:%d] "				\
							"Something impossible has just happened.",	\
							__FILE__, __LINE__)

#if defined(__GNUC__) || defined(__clang__)
#	define __phy_attr_format_printf(idx1, idx2) __attribute__((__format__(__printf__, (idx1), (idx2))))
#else
#	define __phy_attr_format_printf(idx1, idx2)
#endif

size_t	__phy_phy_snprintf(char *str, size_t count, const char *fmt, ...);
size_t	phy_snprintf(char *str, size_t count, const char *fmt, ...);
#	define phy_snprintf __phy_phy_snprintf

#define strscpy(x, y)	phy_strlcpy(x, y, sizeof(x))
#define strscat(x, y)	phy_strlcat(x, y, sizeof(x))

#	define phy_dsprintf __phy_phy_dsprintf
#	define phy_strdcatf __phy_phy_strdcatf
char	*phy_dsprintf(char *dest, const char *f, ...);
size_t	phy_strlcpy(char *dst, const char *src, size_t siz);
void	phy_strlcat(char *dst, const char *src, size_t siz);
void	phy_get_time(struct tm *tm, long *milliseconds, phy_timezone_t *tz);
long	phy_get_timezone_offset(time_t t, struct tm *tm);
long int	phy_get_thread_id();

#define phy_calloc(old, nmemb, size)	phy_calloc2(__FILE__, __LINE__, old, nmemb, size)
#define phy_malloc(old, size)		phy_malloc2(__FILE__, __LINE__, old, size)
#define phy_realloc(src, size)		phy_realloc2(__FILE__, __LINE__, src, size)
#define phy_strdup(old, str)		phy_strdup2(__FILE__, __LINE__, old, str)

#define PHY_STRDUP(var, str)	(var = phy_strdup(var, str))

void    *phy_calloc2(const char *filename, int line, void *old, size_t nmemb, size_t size);
void    *phy_malloc2(const char *filename, int line, void *old, size_t size);
void    *phy_realloc2(const char *filename, int line, void *old, size_t size);
char    *phy_strdup2(const char *filename, int line, char *old, const char *str);

char	*phy_strdcatf(char *dest, const char *f, ...);
char	*phy_dvsprintf(char *dest, const char *f, va_list args);
size_t	phy_vsnprintf(char *str, size_t count, const char *fmt, va_list args);
void	*phy_guaranteed_memset(void *v, int c, size_t n);
void	phy_on_exit(void);
void	phy_alarm_flag_set(void);
#endif
